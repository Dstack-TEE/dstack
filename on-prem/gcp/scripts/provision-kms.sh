#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Provision the KMS via the courier attest flow (the CLI is the courier):
#   challenge → courier/init (TDX+vTPM Attest) → provision (verifier checks
#   quote + report_data binding + os_image_hash + signs AuthBundle) →
#   courier/install (key-broker verifies sig + HPKE-opens root + writes keyset)
# then restart KMS so it boots from the authority-provided root.
#
#   ./provision-kms.sh            provision (re-provision needs a fresh state)
#   ./provision-kms.sh --reset    wipe KMS state first (avoids bundle_seq clash)

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

KMS_DIR=/dstack/persistent/kms
PORT="${KMS_LOCAL_PORT:-8001}"

if [[ "${1:-}" == "--reset" ]]; then
    c_step "wiping prior KMS state on ${KMS_VM}"
    kms_ssh "rm -rf ${KMS_DIR}/{certs,_ready,auth_bundle.json,root_key.bin}
    docker compose -f /dstack/docker-compose.yaml up -d --no-deps --force-recreate key-broker 2>&1 | tail -1
    sleep 3"
fi

c_step "opening IAP tunnel localhost:${PORT} → ${KMS_VM}:8001"
gcloud compute start-iap-tunnel "$KMS_VM" 8001 \
    --local-host-port="localhost:${PORT}" \
    --project="$GCP_PROJECT" --zone="$GCP_ZONE" >/tmp/iap-prov.log 2>&1 &
TUNNEL_PID=$!
trap 'kill $TUNNEL_PID 2>/dev/null || true' EXIT
# A freshly-deployed CVM needs a few minutes to boot, pull the images and start
# the key-broker — wait for a non-empty /healthz (up to ~6min) rather than racing.
c_step "waiting for key-broker on the tunnel (CVM may still be booting)"
for _ in $(seq 1 90); do
    [ -n "$(curl -s --max-time 3 "http://localhost:${PORT}/healthz" 2>/dev/null)" ] && break
    sleep 4
done
_hz="$(curl -s --max-time 3 "http://localhost:${PORT}/healthz" 2>/dev/null)"
[ -n "$_hz" ] || c_die "key-broker not reachable on :${PORT} after ~6min (CVM booted? is 'fw allow 8001' applied? did KMS prelaunch pass?)"
c_ok "key-broker: $_hz"

c_step "courier attest (user_id=${USER_ID})"
KMS_URL="http://localhost:${PORT}" \
AUTHORITY_URL="${AUTHORITY_URL}" \
USER_ID="${USER_ID}" \
AUTHORITY_API_KEY="${AUTHORITY_API_KEY:-}" \
    python3 "$ROOT/authority/kms_ctl.py" attest

# No SSH: the key-broker just wrote /kms/_ready, so the KMS container's
# wait-loop execs dstack-kms on its own (see kms-prod compose). Confirm over
# HTTP via the same IAP tunnel — key-broker /healthz flips to "ready".
c_step "waiting for KMS to auto-boot from the provisioned root (HTTP, no ssh)"
for _ in $(seq 1 30); do
    [ "$(curl -s http://localhost:${PORT}/healthz)" = "ready" ] && break
    sleep 2
done
c_ok "key-broker healthz: $(curl -s http://localhost:${PORT}/healthz)"
c_ok "KMS provisioned. It serves TLS on :8000 once the wait-loop exec's dstack-kms."
echo "  verify (optional, needs IAP fw on :8000): tunnel :8000 then curl -sk https://localhost:8000/prpc/KMS.GetMeta"
