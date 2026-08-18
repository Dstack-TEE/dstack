#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
report_error() {
  local rc=$?
  echo "FAILED_LINE=$1 COMMAND=$2 rc=$rc" >&2
  for file in "$ROOT"/*.err "$ROOT"/simulator.log; do
    test -f "$file" || continue
    echo "===== $file =====" >&2
    tail -100 "$file" >&2
  done
  exit "$rc"
}
trap 'report_error "$LINENO" "$BASH_COMMAND"' ERR
ROOT=/run/dstack-test-eventlog
SIM=$ROOT/dstack-tee-simulator
UTIL=$ROOT/dstack-util
MOUNT=$ROOT/report
SEED=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
SIM_PID=
cleanup() {
  set +e
  test -n "$SIM_PID" && kill "$SIM_PID" 2>/dev/null
  fusermount3 -uz "$MOUNT" 2>/dev/null
  rm -rf "$ROOT" /run/log/dstack
}
trap cleanup EXIT
mkdir -p "$MOUNT" "$ROOT/runtime" "$ROOT/dmi"
systemctl stop app-compose.service dstack-guest-agent.service dstack-guest-agent.socket dstack-prepare.service 2>/dev/null || true
pkill -x dstack-guest-agent 2>/dev/null || true
rm -rf /run/log/dstack
mkdir -p /run/log/dstack
jq -cn --arg seed "$SEED" --arg mr '{"version":3,"app_id":"eventlog-primary","compose_hash":"","key_provider":"none"}' '{platform:"dstack-tdx",mock_attestation_seed:$seed,mr_config:$mr,vm_config:"{}"}' >"$ROOT/config.json"
"$SIM" --config "$ROOT/config.json" --mountpoint "$MOUNT" --runtime-dir "$ROOT/runtime" --dmi-root "$ROOT/dmi" >"$ROOT/simulator.log" 2>&1 &
SIM_PID=$!
for _ in $(seq 1 200); do mountpoint -q "$MOUNT" && break; kill -0 "$SIM_PID" 2>/dev/null || { cat "$ROOT/simulator.log" >&2; exit 1; }; sleep .05; done
mountpoint -q "$MOUNT"
export DCAP_TDX_QUOTE_CONFIGFS_PATH="$MOUNT/com.intel.dcap"
export DCAP_TDX_RTMR_SYSFS_PATH="$MOUNT/com.intel.dcap/measurements"
export DSTACK_CCEL_FILE="$MOUNT/com.intel.dcap/ccel"
printf 2 >/run/log/dstack/runtime_event_version
chmod 0600 /run/log/dstack/runtime_event_version
"$UTIL" eventlog >"$ROOT/eventlog-before.json"
jq -e 'type=="array" and length>0' "$ROOT/eventlog-before.json" >/dev/null
"$UTIL" show >"$ROOT/show.json"
jq -e 'type=="object"' "$ROOT/show.json" >/dev/null
"$UTIL" replay-imr >"$ROOT/replay-before.txt"
BEFORE=$(od -An -vtx1 "$MOUNT/com.intel.dcap/measurements/rtmr3:sha384" | tr -d " \n")
BASELINE_LOG=$(sha384sum /run/log/dstack/runtime_events.log 2>/dev/null | cut -d" " -f1 || true)
if "$UTIL" extend --event malformed --payload xyz >"$ROOT/invalid.out" 2>"$ROOT/invalid.err"; then INVALID_RC=0; else INVALID_RC=$?; fi
test "$INVALID_RC" -ne 0
test "$(od -An -vtx1 "$MOUNT/com.intel.dcap/measurements/rtmr3:sha384" | tr -d " \n")" = "$BEFORE"
test "$(sha384sum /run/log/dstack/runtime_events.log 2>/dev/null | cut -d" " -f1 || true)" = "$BASELINE_LOG"
"$UTIL" extend --event alpha --payload 010203
# shellcheck disable=SC2016
seq 1 8 | xargs -P4 -I{} sh -c 'payload=$(printf "0a0b0c%02x" "$1"); exec "$2" extend --event "concurrent-$1" --payload "$payload"' _ {} "$UTIL"
stat -c %a /run/log/dstack/runtime_events.log | grep -qx 600
"$UTIL" eventlog >"$ROOT/eventlog-after.json"
"$UTIL" replay-imr >"$ROOT/replay-after.txt"
ACTUAL=$(od -An -vtx1 "$MOUNT/com.intel.dcap/measurements/rtmr3:sha384" | tr -d " \n")
REPLAY=$(sed -n 's/^IMR 3 (CCEL) → //p' "$ROOT/replay-after.txt")
if test "$ACTUAL" != "$REPLAY"; then echo "RTMR_MISMATCH actual=$ACTUAL replay=$REPLAY" >&2; cat "$ROOT/replay-after.txt" >&2; exit 1; fi
python3 - "$ROOT/eventlog-after.json" /run/log/dstack/runtime_events.log <<'PY'
import base64, hashlib, json, pathlib, sys
rows=json.loads(pathlib.Path(sys.argv[1]).read_text())
runtime=[r for r in rows if r.get("event_type")==0x08000001]
assert [r["event"] for r in runtime[-9:]][0] == "alpha"
assert set(r["event"] for r in runtime[-8:]) == {f"concurrent-{i}" for i in range(1,9)}
lines=[json.loads(x) for x in pathlib.Path(sys.argv[2]).read_text().splitlines()]
case_lines=[row for row in lines if row["event"]=="alpha" or row["event"].startswith("concurrent-")]
assert len(case_lines)==9
for row in lines:
    canonical=json.dumps({"name":row["event"],"payload":base64.b64decode(row["payload"]).hex(),"type":0x08000001},sort_keys=True,separators=(",",":"))
    digest=hashlib.sha384(canonical.encode()).hexdigest()
    match=next(r for r in runtime if r["event"]==row["event"])
    assert match["digest"]==digest
PY
# A failed device extension must not commit an event-log record.
LINES_BEFORE=$(wc -l </run/log/dstack/runtime_events.log)
if DCAP_TDX_RTMR_SYSFS_PATH="$ROOT/missing-measurements" "$UTIL" extend --event device-fault --payload 00 >"$ROOT/fault.out" 2>"$ROOT/fault.err"; then FAULT_RC=0; else FAULT_RC=$?; fi
test "$FAULT_RC" -ne 0
test "$(wc -l </run/log/dstack/runtime_events.log)" -eq "$LINES_BEFORE"
"$UTIL" extend --event retry --payload 00
"$UTIL" eventlog >"$ROOT/eventlog-retry.json"
test "$(jq '[.[]|select(.event=="retry")]|length' "$ROOT/eventlog-retry.json")" -eq 1
test "$(jq '[.[]|select(.event=="device-fault")]|length' "$ROOT/eventlog-retry.json")" -eq 0
python3 - <<PY
import json
print(json.dumps({"invalid_rc":$INVALID_RC,"fault_rc":$FAULT_RC,"concurrent":8,"replay_matches_live":True,"permissions":"600","retry_exactly_once":True},sort_keys=True))
PY
