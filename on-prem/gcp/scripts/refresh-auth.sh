#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPERATOR · push a refreshed AuthBundle to an already-provisioned KMS, without
# re-provisioning the root key. This is the day-2 "apply the vendor's update"
# step: after the vendor registers a new workload image_digest (or rotates a
# key / revokes a digest) and bumps the tenant's bundle, the operator relays the
# new signed bundle into their running KMS over IAP — the same courier channel
# as provisioning, but bundle-only (no sealed_root).
#
#   sync-auth flow (kms_ctl.py): usage-receipt ← key-broker → authority /sync-auth
#   (verify caller, bump bundle_seq, re-sign) → key-broker /courier/install
#   (verify Ed25519 sig vs pinned AUTHORITY_PUBKEY + bundle_seq strictly ↑).
#
# The launcher's version-poll loop then sees the new current_image_digest and
# rolling-updates the workload (G11 admits the new digest; G8 rejects rollback).
#
#   ./refresh-auth.sh
#
# config.env: KMS_VM, GCP_PROJECT, GCP_ZONE, USER_ID, AUTHORITY_URL,
#   [AUTHORITY_API_KEY] (multi-user), [KMS_LOCAL_PORT].

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

: "${KMS_VM:?}" "${GCP_PROJECT:?}" "${GCP_ZONE:?}" "${USER_ID:?}" "${AUTHORITY_URL:?}"
PORT="${KMS_LOCAL_PORT:-8001}"

c_step "opening IAP tunnel localhost:${PORT} → ${KMS_VM}:8001"
gcloud compute start-iap-tunnel "$KMS_VM" 8001 \
    --local-host-port="localhost:${PORT}" \
    --project="$GCP_PROJECT" --zone="$GCP_ZONE" >/tmp/iap-refresh.log 2>&1 &
TUNNEL_PID=$!
trap 'kill $TUNNEL_PID 2>/dev/null || true' EXIT

# the KMS must already be provisioned & serving (healthz == "ready"); sync-auth
# only swaps the authorization data, it does NOT bootstrap the root.
c_step "waiting for key-broker (must be already provisioned)"
for _ in $(seq 1 30); do
    [ "$(curl -s --max-time 3 "http://localhost:${PORT}/healthz" 2>/dev/null)" = "ready" ] && break
    sleep 2
done
_hz="$(curl -s --max-time 3 "http://localhost:${PORT}/healthz" 2>/dev/null)"
[ "$_hz" = "ready" ] || c_die "key-broker not 'ready' on :${PORT} (got '${_hz:-unreachable}'); provision first (operator-deploy.sh kms)"
c_ok "key-broker: $_hz"

c_step "sync-auth (push refreshed bundle for user_id=${USER_ID})"
KMS_URL="http://localhost:${PORT}" \
AUTHORITY_URL="${AUTHORITY_URL}" \
USER_ID="${USER_ID}" \
AUTHORITY_API_KEY="${AUTHORITY_API_KEY:-}" \
    python3 "$ROOT/authority/kms_ctl.py" sync-auth

c_ok "bundle refreshed. launchers pick up the new current_image_digest on their next version poll."
