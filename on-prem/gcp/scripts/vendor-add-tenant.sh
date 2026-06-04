#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# VENDOR · run ONCE per new customer (tenant).
#
# Because the parameterized compose makes every digest/hash customer-INDEPENDENT,
# onboarding a customer is just: create the tenant + register the (already-known)
# app with the release's launcher_compose_hash + workload image digest. The
# os-image / kms-compose policy is global and was registered by vendor-release.sh.
#
#   ./vendor-add-tenant.sh <user_id>
# Prints the tenant's API key (multi-user mode) — hand it to that operator.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

GCP="$(cd "$HERE/.." && pwd)"
A="${AUTHORITY_URL:?set AUTHORITY_URL}"
UID_ARG="${1:?usage: vendor-add-tenant.sh <user_id>}"
AUTH=(-H "Authorization: Bearer ${AUTHORITY_ADMIN_TOKEN:-}")

MANIFEST="$GCP/deploy/.release-manifest.env"
[[ -f "$MANIFEST" ]] || c_die "no release manifest — run ./vendor-release.sh first"
# shellcheck disable=SC1090
source "$MANIFEST"

c_step "create tenant $UID_ARG"
curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
    -d "{\"user_id\":\"$UID_ARG\"}" "$A/api/v1/admin/users" | python3 -m json.tool || true

c_step "register app $APP_ID for $UID_ARG"
curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
    -d "{\"app_id\":\"$APP_ID\",
         \"allowed_launcher_digests\":[\"$LAUNCHER_COMPOSE_HASH\"],
         \"image_digest\":\"$WORKLOAD_IMAGE_DIGEST\"}" \
    "$A/api/v1/admin/users/$UID_ARG/images" | python3 -m json.tool

c_ok "tenant $UID_ARG ready (app $APP_ID, launcher $LAUNCHER_COMPOSE_HASH, image $WORKLOAD_IMAGE_DIGEST)"
echo "Hand this operator: their API key (above), the filled deploy/ templates, and AUTHORITY_PUBKEY=$AUTHORITY_PUBKEY"
