#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=/run/dstack-test-attest; SIM=$ROOT/dstack-tee-simulator; UTIL=$ROOT/dstack-util; MOUNT=$ROOT/report
SIM_PID=; SEED_A=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f; SEED_B=606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
cleanup(){ set +e; test -n "$SIM_PID" && kill "$SIM_PID" 2>/dev/null; fusermount3 -uz "$MOUNT" 2>/dev/null; rm -rf "$ROOT" /run/log/dstack; }
trap cleanup EXIT
# shellcheck disable=SC2154
trap 'rc=$?; echo "FAILED_LINE=$LINENO rc=$rc" >&2; exit $rc' ERR
systemctl stop app-compose.service dstack-guest-agent.service dstack-guest-agent.socket dstack-prepare.service 2>/dev/null || true
pkill -x dstack-guest-agent 2>/dev/null || true
mkdir -p "$MOUNT" "$ROOT/runtime" "$ROOT/dmi" /run/log/dstack
write_config(){ jq -cn --arg seed "$1" --arg mr "{\"version\":3,\"app_id\":\"$2\",\"compose_hash\":\"\",\"key_provider\":\"none\"}" '{platform:"dstack-tdx",mock_attestation_seed:$seed,mr_config:$mr,vm_config:"{}"}' >"$ROOT/config.json"; }
start_sim(){ mkdir -p "$MOUNT" "$ROOT/runtime" "$ROOT/dmi"; "$SIM" --config "$ROOT/config.json" --mountpoint "$MOUNT" --runtime-dir "$ROOT/runtime" --dmi-root "$ROOT/dmi" >"$ROOT/simulator.log" 2>&1 & SIM_PID=$!; for _ in $(seq 1 200); do mountpoint -q "$MOUNT" && return; kill -0 "$SIM_PID" 2>/dev/null || { cat "$ROOT/simulator.log" >&2; return 1; }; sleep .05; done; return 1; }
stop_sim(){ set +e; fusermount3 -uz "$MOUNT" 2>/dev/null; kill "$SIM_PID" 2>/dev/null; wait "$SIM_PID" 2>/dev/null; set -e; SIM_PID=; }
export DCAP_TDX_QUOTE_CONFIGFS_PATH="$MOUNT/com.intel.dcap" DCAP_TDX_RTMR_SYSFS_PATH="$MOUNT/com.intel.dcap/measurements" DSTACK_CCEL_FILE="$MOUNT/com.intel.dcap/ccel"
write_config "$SEED_A" primary; start_sim
ZERO64=$(printf '00%.0s' $(seq 1 64)); OVER65=$(printf '11%.0s' $(seq 1 65)); APP_A=$(printf '22%.0s' $(seq 1 20)); APP_B=$(printf '23%.0s' $(seq 1 20))
printf 1 >/run/log/dstack/runtime_event_version
"$UTIL" attest --report-data '' --app-id "$APP_A" -o "$ROOT/v0-empty.bin"
"$UTIL" attest --report-data 42 --app-id "$APP_A" -o "$ROOT/v0-one.bin"
"$UTIL" attest --report-data "$ZERO64" --app-id "$APP_A" -o "$ROOT/v0.bin"
"$UTIL" attest --report-data "$ZERO64" --app-id "$APP_B" -o "$ROOT/app-b.bin"
if "$UTIL" attest --report-data "$OVER65" -o "$ROOT/over.bin" 2>"$ROOT/over.err"; then OVER_RC=0; else OVER_RC=$?; fi
if "$UTIL" attest --app-id 22 -o "$ROOT/bad-app.bin" 2>"$ROOT/bad-app.err"; then BAD_APP_RC=0; else BAD_APP_RC=$?; fi
test "$OVER_RC" -ne 0 -a "$BAD_APP_RC" -ne 0; test ! -e "$ROOT/over.bin" -a ! -e "$ROOT/bad-app.bin"
"$UTIL" attest-info -i "$ROOT/v0.bin" >"$ROOT/v0.info"; grep -qx 'version: V0' "$ROOT/v0.info"
"$UTIL" attest-json -i "$ROOT/v0.bin" -o "$ROOT/v0.json"; jq -e '.version=="V0" and .mode=="dstack-tdx"' "$ROOT/v0.json" >/dev/null
printf 2 >/run/log/dstack/runtime_event_version
"$UTIL" extend --event version-two --payload 0102
"$UTIL" attest --report-data "$ZERO64" --app-id "$APP_A" -o "$ROOT/v1.bin"
"$UTIL" attest-info -i "$ROOT/v1.bin" >"$ROOT/v1.info"; grep -qx 'version: V1' "$ROOT/v1.info"
"$UTIL" attest-json -i "$ROOT/v1.bin" -o "$ROOT/v1.json"; jq -e '.version==1' "$ROOT/v1.json" >/dev/null
for f in v0 v1; do "$UTIL" attest-strip -i "$ROOT/$f.bin" -o "$ROOT/$f.strip.bin"; "$UTIL" attest-info -i "$ROOT/$f.strip.bin" >"$ROOT/$f.strip.info"; done
python3 - "$ROOT/v0.bin" "$ROOT" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]).read_bytes(); r=pathlib.Path(sys.argv[2]); r.joinpath('truncated.bin').write_bytes(p[:-1]); r.joinpath('unknown.bin').write_bytes(b'\xffunknown'); r.joinpath('oversized.bin').write_bytes(b'\0'*(10*1024*1024+1))
PY
for kind in truncated unknown oversized; do if "$UTIL" attest-info -i "$ROOT/$kind.bin" >"$ROOT/$kind.out" 2>"$ROOT/$kind.err"; then eval "${kind^^}_RC=0"; else eval "${kind^^}_RC=$?"; fi; done
test "$TRUNCATED_RC" -ne 0 -a "$UNKNOWN_RC" -ne 0 -a "$OVERSIZED_RC" -ne 0
if "$UTIL" attest-json -i "$ROOT/v0.bin" -o "$ROOT/missing/out.json" 2>"$ROOT/output.err"; then OUTPUT_RC=0; else OUTPUT_RC=$?; fi
test "$OUTPUT_RC" -ne 0; test ! -e "$ROOT/missing/out.json"
V0_HASH=$(sha256sum "$ROOT/v0.bin"|cut -d' ' -f1); V1_HASH=$(sha256sum "$ROOT/v1.bin"|cut -d' ' -f1); test "$V0_HASH" != "$V1_HASH"; test "$V0_HASH" != "$(sha256sum "$ROOT/app-b.bin"|cut -d' ' -f1)"
stop_sim
if "$UTIL" attest -o "$ROOT/device.bin" 2>"$ROOT/device.err"; then DEVICE_RC=0; else DEVICE_RC=$?; fi
test "$DEVICE_RC" -ne 0; test ! -e "$ROOT/device.bin"
start_sim; printf 1 >/run/log/dstack/runtime_event_version; "$UTIL" attest --app-id "$APP_A" -o "$ROOT/retry.bin"; stop_sim
write_config "$SEED_B" adjacent; start_sim; printf 1 >/run/log/dstack/runtime_event_version; "$UTIL" attest --app-id "$APP_A" -o "$ROOT/adjacent.bin"; test "$(sha256sum "$ROOT/retry.bin"|cut -d' ' -f1)" != "$(sha256sum "$ROOT/adjacent.bin"|cut -d' ' -f1)"
python3 - <<PY
import json
print(json.dumps({"v0":True,"v1":True,"strip_decodable":True,"binding_distinct":True,"boundaries":[0,1,64,65],"bad_app_rc":$BAD_APP_RC,"truncated_rc":$TRUNCATED_RC,"unknown_rc":$UNKNOWN_RC,"oversized_rc":$OVERSIZED_RC,"output_rc":$OUTPUT_RC,"device_rc":$DEVICE_RC,"retry":True,"adjacent_identity":True},sort_keys=True))
PY
