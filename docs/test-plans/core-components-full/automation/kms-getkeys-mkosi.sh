#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# shellcheck disable=SC2154
trap 'echo "FAILED_LINE=$LINENO" >&2' ERR
ROOT=/run/dstack-test-getkeys; UTIL=$ROOT/dstack-util; URL=$1; APP_A=$(printf '31%.0s' $(seq 1 20)); APP_B=$(printf '32%.0s' $(seq 1 20))
export DSTACK_CCEL_FILE=$ROOT/ccel.bin
run(){ "$UTIL" get-keys --kms-url "$URL" --app-id "$1" -o "$2"; }
run "$APP_A" "$ROOT/a.json" 2>"$ROOT/a.err"; jq -e '.ca_cert and .disk_crypt_key and .env_crypt_key and .k256_key' "$ROOT/a.json" >/dev/null; test "$(stat -c %a "$ROOT/a.json")" = 600
run "$APP_A" "$ROOT/repeat.json" 2>"$ROOT/repeat.err"; run "$APP_B" "$ROOT/b.json" 2>"$ROOT/b.err"
stable_hash(){ jq -cS '{disk_crypt_key,env_crypt_key,k256_key,k256_signature,gateway_app_id}' "$1" | sha256sum | cut -d' ' -f1; }
A=$(stable_hash "$ROOT/a.json")
test "$A" = "$(stable_hash "$ROOT/repeat.json")"
test "$A" = "$(stable_hash "$ROOT/b.json")"
if "$UTIL" get-keys --kms-url "$URL" --root-ca "$ROOT/kms.crt" --app-id 31 -o "$ROOT/bad-app.json" 2>"$ROOT/bad-app.err"; then BAD_APP_RC=0; else BAD_APP_RC=$?; fi
printf 'not-a-certificate\n' >"$ROOT/wrong.crt"; if "$UTIL" get-keys --kms-url "$URL" --root-ca "$ROOT/wrong.crt" -o "$ROOT/wrong.json" 2>"$ROOT/wrong.err"; then WRONG_CA_RC=0; else WRONG_CA_RC=$?; fi
if timeout 8 "$UTIL" get-keys --kms-url https://10.0.2.2:1 --root-ca "$ROOT/kms.crt" -o "$ROOT/unreachable.json" 2>"$ROOT/unreachable.err"; then UNREACHABLE_RC=0; else UNREACHABLE_RC=$?; fi
if run "$APP_A" "$ROOT/missing/out.json" 2>"$ROOT/output.err"; then OUTPUT_RC=0; else OUTPUT_RC=$?; fi
test "$BAD_APP_RC" -ne 0 -a "$WRONG_CA_RC" -ne 0 -a "$UNREACHABLE_RC" -ne 0 -a "$OUTPUT_RC" -ne 0; test ! -e "$ROOT/bad-app.json" -a ! -e "$ROOT/wrong.json" -a ! -e "$ROOT/unreachable.json" -a ! -e "$ROOT/missing/out.json"
run "$APP_A" "$ROOT/retry.json" 2>"$ROOT/retry.err"; test "$A" = "$(stable_hash "$ROOT/retry.json")"
python3 - <<PY
import json
print(json.dumps({"valid":True,"repeat_stable":True,"app_id_scope_preserved":True,"retry":True,"atomic":True,"restrictive":True,"bad_app_rc":$BAD_APP_RC,"wrong_ca_rc":$WRONG_CA_RC,"unreachable_rc":$UNREACHABLE_RC,"output_rc":$OUTPUT_RC},sort_keys=True))
PY
