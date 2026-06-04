#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Deploy the VENDOR-side stack (vendor authority + dstack-verifier) via
# docker-compose. Runs on the vendor's infrastructure (needs internet for PCCS
# and OS-image collateral). Prints the authority Ed25519 pubkey to configure into
# the KMS key-broker (deploy-kms.sh consumes it).

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

cd "$ROOT"

c_step "building + starting authority stack (verifier + authority)"
REQUIRE_ATTESTATION="${REQUIRE_ATTESTATION:-true}" \
EXPECTED_OS_IMAGE_HASH="${EXPECTED_OS_IMAGE_HASH:-}" \
AUTHORITY_ADMIN_TOKEN="${AUTHORITY_ADMIN_TOKEN:-}" \
AUTHORITY_NONCE_SECRET="${AUTHORITY_NONCE_SECRET:-}" \
AUTHORITY_SIGNING_KEY="${AUTHORITY_SIGNING_KEY:-}" \
PCCS_URL="${PCCS_URL:-https://pccs.phala.network}" \
VERIFIER_IMAGE="${VERIFIER_IMAGE:-cr.kvin.wang/dstack-verifier:latest}" \
    docker compose -f docker-compose.authority.yml up -d --build

c_step "waiting for authority + verifier health"
for _ in $(seq 1 40); do
    curl -sf "${AUTHORITY_URL}/api/v1/authority-pubkey" >/dev/null 2>&1 && break
    sleep 0.5
done
curl -sf "${AUTHORITY_URL}/api/v1/authority-pubkey" >/dev/null 2>&1 \
    || c_die "authority did not become healthy at ${AUTHORITY_URL}"
c_ok "authority up at ${AUTHORITY_URL}"

PUBKEY="$(curl -s "${AUTHORITY_URL}/api/v1/authority-pubkey" | python3 -c 'import sys,json;print(json.load(sys.stdin)["pubkey"])')"
c_ok "authority pubkey (stable across restarts): ${PUBKEY}"
echo "$PUBKEY" > "$HERE/.authority-pubkey"

cat <<EOF

Next:
  - copy this pubkey into the KMS key-broker:  AUTHORITY_PUBKEY=${PUBKEY}
  - run:  ./deploy-kms.sh        (uses .authority-pubkey automatically)
  - then: ./provision-kms.sh
EOF
