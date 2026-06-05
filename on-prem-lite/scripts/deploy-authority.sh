#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# VENDOR · deploy the on-prem-lite authority stack (vendor authority +
# dstack-verifier) via docker-compose. Runs on the vendor's infrastructure (needs
# internet for TDX quote collateral). Prints the authority Ed25519 pubkey — that
# value gets pinned (measured) into the launcher compose by vendor-release.sh.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ENV_FILE="${1:-$HERE/config.env}"
[[ -f "$ENV_FILE" ]] || c_die "env file not found: $ENV_FILE (copy config.env.example → config.env)"
A="${AUTHORITY_URL:?set AUTHORITY_URL (e.g. http://localhost:8084)}"

c_step "building + starting authority stack (verifier + authority) on :8084"
docker compose -f "$ROOT/docker-compose.authority.yml" --env-file "$ENV_FILE" up -d --build

c_step "waiting for authority health at $A"
for _ in $(seq 1 40); do
    curl -sf "$A/api/v1/authority-pubkey" >/dev/null 2>&1 && break
    sleep 0.5
done
curl -sf "$A/api/v1/authority-pubkey" >/dev/null 2>&1 \
    || c_die "authority did not become healthy at $A"
c_ok "authority up at $A"

PUBKEY="$(curl -s "$A/api/v1/authority-pubkey" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["pubkey"])')"
[[ -n "$PUBKEY" ]] || c_die "could not read authority pubkey"
c_ok "AUTHORITY_PUBKEY (stable across restarts): $PUBKEY"
echo "$PUBKEY" > "$HERE/.authority-pubkey"

cat <<EOF

Next (vendor):
  ./vendor-release.sh        # mint image key, encrypt workload, register policy,
                             # pin AUTHORITY_PUBKEY + app_id into the launcher compose
EOF
