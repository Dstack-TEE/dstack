#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=/run/dstack-test-vtpm; SIM=$ROOT/dstack-tee-simulator; UTIL=$ROOT/dstack-util
SEED1=7171717171717171717171717171717171717171717171717171717171717171
SEED2=7272727272727272727272727272727272727272727272727272727272727272
SIM_PID=
cleanup(){ set +e; test -n "$SIM_PID" && kill "$SIM_PID" 2>/dev/null; test -s "$ROOT/runtime/swtpm.pid" && kill "$(cat "$ROOT/runtime/swtpm.pid")" 2>/dev/null; fusermount3 -uz "$ROOT/tsm" 2>/dev/null; rm -f /dev/tpm0 /dev/tpmrm0; modprobe -r tpm_vtpm_proxy 2>/dev/null; pkill -f 'swtpm.*dstack-' 2>/dev/null; }
trap cleanup EXIT
reset_tpm(){ cleanup; rm -rf "$ROOT/runtime" "$ROOT/tsm" "$ROOT/dmi"; mkdir -p "$ROOT/runtime" "$ROOT/tsm" "$ROOT/dmi" "$ROOT/out"; modprobe tpm_vtpm_proxy; if test ! -e /dev/vtpmx; then IFS=: read -r ma mi </sys/class/misc/vtpmx/dev; mknod /dev/vtpmx c "$ma" "$mi"; fi; chmod 0666 /dev/vtpmx; }
start_tpm(){ reset_tpm; jq -cn --arg seed "$1" '{platform:"dstack-gcp-tdx",mock_attestation_seed:$seed,collateral_base_url:"http://127.0.0.1:18088"}' >$ROOT/config.json; "$SIM" --config $ROOT/config.json --mountpoint $ROOT/tsm --runtime-dir $ROOT/runtime --dmi-root $ROOT/dmi >$ROOT/sim.log 2>&1 & SIM_PID=$!; for _ in $(seq 1 300); do test -e /dev/tpmrm0 && TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_nvreadpublic 0x1c00002 >/dev/null 2>&1 && curl -fsS http://127.0.0.1:18088/tpm/aia/intermediate.der >/dev/null && return; kill -0 "$SIM_PID" 2>/dev/null || { cat $ROOT/sim.log >&2; return 1; }; sleep .05; done; cat $ROOT/sim.log >&2; return 1; }
reject(){ if "$@" >$ROOT/out/reject.log 2>&1; then return 1; fi; }
export TPM2TOOLS_TCTI=device:/dev/tpmrm0
mkdir -p "$ROOT/out"; start_tpm "$SEED1"; ROOT_CA=$ROOT/runtime/mock-roots/tpm-root-ca.pem
"$UTIL" vtpm-attest --root-ca "$ROOT_CA" --nonce nonce-rsa --key-algo rsa --format json >$ROOT/out/vtpm-rsa.json
"$UTIL" vtpm-attest --root-ca "$ROOT_CA" --nonce nonce-ecc --key-algo ecc --format json >$ROOT/out/vtpm-ecc.json
jq -e '.success and .ek_cert_verified and .quote_verified' $ROOT/out/vtpm-rsa.json $ROOT/out/vtpm-ecc.json >/dev/null
DATA=$(printf 42%.0s $(seq 1 32))
for a in auto ecc rsa; do "$UTIL" tpm-quote --key-algo "$a" --hash-algo none --data "$DATA" --output $ROOT/out/$a.json; "$UTIL" tpm-verify --root-ca "$ROOT_CA" --quote $ROOT/out/$a.json >$ROOT/out/verify-$a.log; done
test "$(stat -c %a $ROOT/out/auto.json)" = 600
cp "$ROOT_CA" $ROOT/out/root1.pem
start_tpm "$SEED2"; cp $ROOT/runtime/mock-roots/tpm-root-ca.pem $ROOT/out/root2.pem; if cmp -s "$ROOT/out/root1.pem" "$ROOT/out/root2.pem"; then exit 1; fi; start_tpm "$SEED1"; ROOT_CA=$ROOT/runtime/mock-roots/tpm-root-ca.pem
reject "$UTIL" tpm-verify --root-ca $ROOT/out/root2.pem --quote $ROOT/out/auto.json
jq '.pcr_values[0].value[0] ^= 1' $ROOT/out/auto.json >$ROOT/out/pcr.json; reject "$UTIL" tpm-verify --root-ca "$ROOT_CA" --quote $ROOT/out/pcr.json
jq '.signature = (.signature[0:-2] + "00")' $ROOT/out/auto.json >$ROOT/out/sig.json; reject "$UTIL" tpm-verify --root-ca "$ROOT_CA" --quote $ROOT/out/sig.json
kill "$SIM_PID"; wait "$SIM_PID" 2>/dev/null || true; SIM_PID=
reject "$UTIL" tpm-verify --root-ca "$ROOT_CA" --quote $ROOT/out/auto.json
reject "$UTIL" tpm-quote --key-algo auto --hash-algo none --data "$DATA" --output $ROOT/out/device-fault.json
test ! -e $ROOT/out/device-fault.json
reject "$UTIL" tpm-quote --key-algo auto --hash-algo none --data "$DATA" --output $ROOT/missing/out.json; test ! -e $ROOT/missing/out.json
start_tpm "$SEED1"; "$UTIL" tpm-verify --root-ca $ROOT/runtime/mock-roots/tpm-root-ca.pem --quote $ROOT/out/auto.json >/dev/null
python3 - <<'PY'
import json
print(json.dumps({k:True for k in "vtpm_rsa vtpm_ecc quote_auto quote_ecc quote_rsa verify wrong_root_rejected pcr_rejected signature_rejected network_rejected device_rejected output_atomic retry adjacent_identity permissions".split()},sort_keys=True))
PY
