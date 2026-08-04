#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=/run/dstack-test-ra-key
SIM=$ROOT/dstack-tee-simulator
UTIL=$ROOT/dstack-util
MOUNT=$ROOT/report
SIM_PID=
report_error() { local rc=$?; echo "FAILED_LINE=$1 COMMAND=$2 rc=$rc" >&2; for f in "$ROOT"/*.err "$ROOT"/simulator.log; do test -f "$f" && { echo "===== $f =====" >&2; tail -100 "$f" >&2; }; done; exit "$rc"; }
trap 'report_error "$LINENO" "$BASH_COMMAND"' ERR
cleanup() { set +e; test -n "$SIM_PID" && kill "$SIM_PID" 2>/dev/null; fusermount3 -uz "$MOUNT" 2>/dev/null; rm -rf "$ROOT"; }
trap cleanup EXIT
mkdir -p "$MOUNT" "$ROOT/runtime" "$ROOT/dmi" "$ROOT/out"
systemctl stop app-compose.service dstack-guest-agent.service dstack-guest-agent.socket dstack-prepare.service 2>/dev/null || true
pkill -x dstack-guest-agent 2>/dev/null || true
rm -rf /run/log/dstack; mkdir -p /run/log/dstack; printf 2 >/run/log/dstack/runtime_event_version
jq -cn --arg seed 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f --arg mr '{"version":3,"app_id":"ra-key-primary","compose_hash":"","key_provider":"none"}' '{platform:"dstack-tdx",mock_attestation_seed:$seed,mr_config:$mr,vm_config:"{}"}' >"$ROOT/config.json"
"$SIM" --config "$ROOT/config.json" --mountpoint "$MOUNT" --runtime-dir "$ROOT/runtime" --dmi-root "$ROOT/dmi" >"$ROOT/simulator.log" 2>&1 & SIM_PID=$!
for _ in $(seq 1 200); do mountpoint -q "$MOUNT" && break; kill -0 "$SIM_PID" 2>/dev/null || { cat "$ROOT/simulator.log" >&2; exit 1; }; sleep .05; done
mountpoint -q "$MOUNT"
export DCAP_TDX_QUOTE_CONFIGFS_PATH="$MOUNT/com.intel.dcap" DCAP_TDX_RTMR_SYSFS_PATH="$MOUNT/com.intel.dcap/measurements" DSTACK_CCEL_FILE="$MOUNT/com.intel.dcap/ccel"
for level in 0 1 2; do
  "$UTIL" gen-ca-cert --cert "$ROOT/out/ca$level.pem" --key "$ROOT/out/ca$level.key" --ca-level "$level"
  test "$(stat -c %a "$ROOT/out/ca$level.key")" = 600
  openssl x509 -in "$ROOT/out/ca$level.pem" -noout -text | grep -q 'CA:TRUE'
  openssl x509 -in "$ROOT/out/ca$level.pem" -pubkey -noout >"$ROOT/out/ca$level.cert.pub"
  openssl pkey -in "$ROOT/out/ca$level.key" -pubout >"$ROOT/out/ca$level.key.pub"
  cmp "$ROOT/out/ca$level.cert.pub" "$ROOT/out/ca$level.key.pub"
done
"$UTIL" gen-ra-cert --ca-cert "$ROOT/out/ca1.pem" --ca-key "$ROOT/out/ca1.key" --cert-path "$ROOT/out/ra.pem" --key-path "$ROOT/out/ra.key"
test "$(stat -c %a "$ROOT/out/ra.key")" = 600
openssl verify -CAfile "$ROOT/out/ca1.pem" "$ROOT/out/ra.pem" | grep -q ': OK$'
openssl x509 -in "$ROOT/out/ra.pem" -pubkey -noout >"$ROOT/out/ra.cert.pub"
openssl pkey -in "$ROOT/out/ra.key" -pubout >"$ROOT/out/ra.key.pub"
cmp "$ROOT/out/ra.cert.pub" "$ROOT/out/ra.key.pub"
printf trusted-cert >"$ROOT/out/mismatch.pem"; printf trusted-key >"$ROOT/out/mismatch.key"
if "$UTIL" gen-ra-cert --ca-cert "$ROOT/out/ca1.pem" --ca-key "$ROOT/out/ca2.key" --cert-path "$ROOT/out/mismatch.pem" --key-path "$ROOT/out/mismatch.key" >"$ROOT/mismatch.out" 2>"$ROOT/mismatch.err"; then MISMATCH_RC=0; else MISMATCH_RC=$?; fi
test "$MISMATCH_RC" -ne 0; grep -qx trusted-cert "$ROOT/out/mismatch.pem"; grep -qx trusted-key "$ROOT/out/mismatch.key"
# Both outputs must remain absent when either destination cannot be staged.
"$UTIL" gen-app-keys --ca-level 1 --output "$ROOT/out/app-keys.json"
test "$(stat -c %a "$ROOT/out/app-keys.json")" = 600
jq -e '.ca_cert and .disk_crypt_key and .env_crypt_key and .k256_key and .k256_signature and .key_provider' "$ROOT/out/app-keys.json" >/dev/null
APP1=$(sha256sum "$ROOT/out/app-keys.json"|cut -d' ' -f1)
"$UTIL" gen-app-keys --ca-level 1 --output "$ROOT/out/app-keys-2.json"
APP2=$(sha256sum "$ROOT/out/app-keys-2.json"|cut -d' ' -f1)
test "$APP1" != "$APP2"
if "$UTIL" gen-app-keys --ca-level 1 --output "$ROOT/missing/app.json" >"$ROOT/app-fault.out" 2>"$ROOT/app-fault.err"; then APP_FAULT_RC=0; else APP_FAULT_RC=$?; fi
test "$APP_FAULT_RC" -ne 0; test ! -e "$ROOT/missing/app.json"
"$UTIL" gen-app-keys --ca-level 1 --output "$ROOT/out/app-retry.json"
test "$(jq -r '.ca_cert|length>0' "$ROOT/out/app-retry.json")" = true
# Logs must not contain private PEM bodies or serialized private key fields.
if grep -R -E 'BEGIN (EC |)PRIVATE KEY|disk_crypt_key|env_crypt_key|k256_key' "$ROOT"/*.out "$ROOT"/*.err 2>/dev/null; then exit 1; fi
python3 - <<PY
import json
print(json.dumps({"ca_levels":[0,1,2],"mismatch_rc":$MISMATCH_RC,"app_fault_rc":$APP_FAULT_RC,"chain_valid":True,"key_match":True,"private_modes":"600","random_identity":True,"retry":True,"no_secret_logs":True},sort_keys=True))
PY
