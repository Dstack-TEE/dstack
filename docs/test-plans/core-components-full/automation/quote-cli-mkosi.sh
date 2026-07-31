#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=/run/dstack-test-quote
SIM=$ROOT/dstack-tee-simulator
UTIL=$ROOT/dstack-util
MOUNT=$ROOT/report
SEED=303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
SIM_PID=
report_error() { local rc=$?; echo "FAILED_LINE=$1 COMMAND=$2 rc=$rc" >&2; for f in "$ROOT"/*.err "$ROOT"/simulator.log; do test -f "$f" && { echo "===== $f =====" >&2; tail -100 "$f" >&2; }; done; exit "$rc"; }
trap 'report_error "$LINENO" "$BASH_COMMAND"' ERR
cleanup() { set +e; test -n "$SIM_PID" && kill "$SIM_PID" 2>/dev/null; fusermount3 -uz "$MOUNT" 2>/dev/null; rm -rf "$ROOT"; }
trap cleanup EXIT
mkdir -p "$MOUNT" "$ROOT/runtime" "$ROOT/dmi" "$ROOT/config-a" "$ROOT/config-b"
systemctl stop app-compose.service dstack-guest-agent.service dstack-guest-agent.socket dstack-prepare.service 2>/dev/null || true
pkill -x dstack-guest-agent 2>/dev/null || true
rm -rf /run/log/dstack; mkdir -p /run/log/dstack; printf 2 >/run/log/dstack/runtime_event_version
write_config() { jq -cn --arg seed "$1" --arg mr '{"version":3,"app_id":"quote-primary","compose_hash":"","key_provider":"none"}' '{platform:"dstack-tdx",mock_attestation_seed:$seed,mr_config:$mr,vm_config:"{}"}' >"$ROOT/config.json"; }
start_sim() {
  mkdir -p "$MOUNT" "$ROOT/runtime" "$ROOT/dmi"
  "$SIM" --config "$ROOT/config.json" --mountpoint "$MOUNT" --runtime-dir "$ROOT/runtime" --dmi-root "$ROOT/dmi" >"$ROOT/simulator.log" 2>&1 & SIM_PID=$!
  for _ in $(seq 1 200); do mountpoint -q "$MOUNT" && return; kill -0 "$SIM_PID" 2>/dev/null || { cat "$ROOT/simulator.log" >&2; return 1; }; sleep .05; done; return 1
}
stop_sim() { set +e; fusermount3 -uz "$MOUNT" 2>/dev/null; kill "$SIM_PID" 2>/dev/null; wait "$SIM_PID" 2>/dev/null; set -e; SIM_PID=; }
write_config "$SEED"; start_sim
export DCAP_TDX_QUOTE_CONFIGFS_PATH="$MOUNT/com.intel.dcap" DCAP_TDX_RTMR_SYSFS_PATH="$MOUNT/com.intel.dcap/measurements" DSTACK_CCEL_FILE="$MOUNT/com.intel.dcap/ccel"
printf '{"vm_config":"{\\"identity\\":\\"a\\"}"}\n' >"$ROOT/config-a/.sys-config.json"
printf '{"vm_config":"{\\"identity\\":\\"b\\"}"}\n' >"$ROOT/config-b/.sys-config.json"
python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(64)))' | "$UTIL" quote >"$ROOT/raw.quote"
python3 - "$ROOT/raw.quote" <<'PY'
import pathlib,sys
q=pathlib.Path(sys.argv[1]).read_bytes(); assert len(q)>=632; assert q[568:632]==bytes(range(64))
PY
if python3 -c 'import sys;sys.stdout.buffer.write(b"x"*63)' | "$UTIL" quote >"$ROOT/raw63" 2>"$ROOT/raw63.err"; then RAW63_RC=0; else RAW63_RC=$?; fi
if python3 -c 'import sys;sys.stdout.buffer.write(b"x"*65)' | "$UTIL" quote >"$ROOT/raw65" 2>"$ROOT/raw65.err"; then RAW65_RC=0; else RAW65_RC=$?; fi
test "$RAW63_RC" -ne 0; test "$RAW65_RC" -ne 0; test ! -s "$ROOT/raw63"; test ! -s "$ROOT/raw65"
ZERO64=$(printf '00%.0s' $(seq 1 64)); OVER65=$(printf '11%.0s' $(seq 1 65))
"$UTIL" quote-report --report-data '' --sys-config "$ROOT/config-a/.sys-config.json" -o "$ROOT/empty.json"
"$UTIL" quote-report --report-data 42 --sys-config "$ROOT/config-a/.sys-config.json" -o "$ROOT/one.json"
"$UTIL" quote-report --report-data "$ZERO64" --sys-config "$ROOT/config-a/.sys-config.json" -o "$ROOT/a.json"
"$UTIL" quote-report --debug --report-data "$ZERO64" --sys-config "$ROOT/config-a/.sys-config.json" -o "$ROOT/debug.json" 2>"$ROOT/debug.err"
"$UTIL" quote-report --report-data "$ZERO64" --sys-config "$ROOT/config-b/.sys-config.json" -o "$ROOT/b.json"
if "$UTIL" quote-report --report-data "$OVER65" --sys-config "$ROOT/config-a/.sys-config.json" -o "$ROOT/over.json" 2>"$ROOT/over.err"; then OVER_RC=0; else OVER_RC=$?; fi
test "$OVER_RC" -ne 0; test ! -e "$ROOT/over.json"
for f in empty one a debug b; do jq -e '.attestation|type=="string" and test("^[0-9a-f]+$")' "$ROOT/$f.json" >/dev/null; done
test "$(jq -r .attestation "$ROOT/a.json")" != "$(jq -r .attestation "$ROOT/b.json")"
for f in a debug b; do
  python3 -c 'import json,pathlib,sys; pathlib.Path(sys.argv[2]).write_bytes(bytes.fromhex(json.load(open(sys.argv[1]))["attestation"]))' "$ROOT/$f.json" "$ROOT/$f.bin"
  "$UTIL" attest-json --input "$ROOT/$f.bin" --output "$ROOT/$f.decoded.json"
done
python3 - "$ROOT/a.decoded.json" "$ROOT/debug.decoded.json" "$ROOT/b.decoded.json" <<'PYDECODE'
import json,sys
a,d,b=(json.load(open(x)) for x in sys.argv[1:])
def find(obj,key):
    if isinstance(obj,dict):
        if key in obj: return obj[key]
        for value in obj.values():
            found=find(value,key)
            if found is not None: return found
    if isinstance(obj,list):
        for value in obj:
            found=find(value,key)
            if found is not None: return found
    return None
assert find(a,"report_data")==find(d,"report_data")
assert find(a,"config")==find(d,"config")
qa,qd=find(a,"quote"),find(d,"quote")
assert isinstance(qa,str) and isinstance(qd,str)
assert bytes.fromhex(qa)[:632]==bytes.fromhex(qd)[:632]
assert json.loads(find(a,"config"))["identity"]=="a"
assert json.loads(find(d,"config"))["identity"]=="a"
assert json.loads(find(b,"config"))["identity"]=="b"
PYDECODE
grep -q 'policy is unchanged' "$ROOT/debug.err"
if "$UTIL" quote-report --report-data 00 --sys-config "$ROOT/config-a/.sys-config.json" -o "$ROOT/missing/out.json" 2>"$ROOT/output.err"; then OUTPUT_RC=0; else OUTPUT_RC=$?; fi
test "$OUTPUT_RC" -ne 0; test ! -e "$ROOT/missing/out.json"
stop_sim
if python3 -c 'import sys;sys.stdout.buffer.write(b"z"*64)' | "$UTIL" quote >"$ROOT/device-fault.quote" 2>"$ROOT/device.err"; then DEVICE_RC=0; else DEVICE_RC=$?; fi
test "$DEVICE_RC" -ne 0; test ! -s "$ROOT/device-fault.quote"
start_sim
python3 -c 'import sys;sys.stdout.buffer.write(b"z"*64)' | "$UTIL" quote >"$ROOT/retry.quote"
python3 - "$ROOT/retry.quote" <<'PY'
import pathlib,sys
q=pathlib.Path(sys.argv[1]).read_bytes(); assert q[568:632]==b'z'*64
PY
PRIMARY_HASH=$(sha256sum "$ROOT/retry.quote"|cut -d' ' -f1)
stop_sim
write_config 505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f
start_sim
python3 -c 'import sys;sys.stdout.buffer.write(b"z"*64)' | "$UTIL" quote >"$ROOT/adjacent.quote"
ADJACENT_HASH=$(sha256sum "$ROOT/adjacent.quote"|cut -d' ' -f1)
test "$PRIMARY_HASH" != "$ADJACENT_HASH"
python3 - <<PY
import json
print(json.dumps({"raw63_rc":$RAW63_RC,"raw65_rc":$RAW65_RC,"over_rc":$OVER_RC,"output_rc":$OUTPUT_RC,"device_rc":$DEVICE_RC,"raw_binding":True,"boundaries":[0,1,64,65],"sys_config_distinct":True,"debug_policy_unchanged":True,"retry":True,"adjacent_identity":True},sort_keys=True))
PY
