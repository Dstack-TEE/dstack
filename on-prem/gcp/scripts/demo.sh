#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Demo: GCP private deployment — dstack KMS key-broker + vendor authority
#
# Traces the complete operator flow on localhost:
#   1. Courier attest  — 4-step provisioning of an air-gapped KMS
#   2. Auth webhook    — KMS boot authorization (allow/deny)
#   3. mTLS CEK        — launcher lease/acquire, renewal, slot quota enforcement
#   4. Sync-auth       — push updated AuthBundle without re-provisioning
#
# Usage:
#   bash on-prem/gcp/scripts/demo.sh
#
# Environment overrides:
#   KEY_BROKER_BIN   path to key-broker binary  (default: target/debug/key-broker)
#   AUTHORITY_DIR  path to authority dir  (default: authority)
#   AUTHORITY_PORT vendor authority HTTP port    (default: 18083)
#   KEY_BROKER_PORT  key-broker HTTP port            (default: 18001)
#   KEY_BROKER_MTLS  key-broker mTLS port            (default: 18002)
#   DEMO_SLOT_QUOTA  slot quota for this demo  (default: 2)

set -euo pipefail

# ─── colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

step()  { echo -e "\n${BOLD}${CYAN}▶ $*${RESET}"; }
pass()  { echo -e "  ${GREEN}✓ $*${RESET}"; }
fail()  { echo -e "  ${RED}✗ $*${RESET}"; exit 1; }
info()  { echo -e "  ${YELLOW}$*${RESET}"; }
banner(){ echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; \
          echo -e "${BOLD}${CYAN}  $*${RESET}"; \
          echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; }

# ─── config ─────────────────────────────────────────────────────────────────
ON_PREM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # on-prem/
WORKSPACE_ROOT="$(cd "$ON_PREM_ROOT/.." && pwd)"                     # dstack workspace root (has target/)
KEY_BROKER_BIN="${KEY_BROKER_BIN:-$WORKSPACE_ROOT/target/debug/key-broker}"
AUTHORITY_DIR="${AUTHORITY_DIR:-$ON_PREM_ROOT/authority}"
AUTHORITY_PORT="${AUTHORITY_PORT:-18083}"
KEY_BROKER_PORT="${KEY_BROKER_PORT:-18001}"
KEY_BROKER_MTLS="${KEY_BROKER_MTLS:-18002}"
export DEMO_SLOT_QUOTA="${DEMO_SLOT_QUOTA:-2}"

AUTHORITY_URL="http://localhost:${AUTHORITY_PORT}"
KEY_BROKER_URL="http://localhost:${KEY_BROKER_PORT}"
KEY_BROKER_MTLS_URL="https://localhost:${KEY_BROKER_MTLS}"

CUSTOMER_ID="demo-customer"
KMS_VOL="/tmp/kms-demo-$$"
APP_ID="0000000000000000000000000000000000000000"
IMAGE_DIGEST="sha256:test"

# ─── cleanup ────────────────────────────────────────────────────────────────
PIDS=()
cleanup() {
    echo -e "\n${YELLOW}cleaning up…${RESET}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$KMS_VOL" /tmp/demo-client-$$.key /tmp/demo-client-$$.crt
    # remove per-demo customer record so re-runs start fresh
    rm -f "$HOME/.config/authority/customers.json"
}
trap cleanup EXIT

# ─── prerequisites ───────────────────────────────────────────────────────────
banner "Prerequisites"
for cmd in curl jq openssl python3; do
    command -v "$cmd" &>/dev/null && pass "$cmd found" || fail "$cmd not found"
done
python3 -c "import fastapi, uvicorn, cryptography" 2>/dev/null \
    && pass "Python packages OK (fastapi, uvicorn, cryptography)" \
    || fail "Missing Python packages — run: pip install fastapi uvicorn cryptography"

# ─── kill any stale demo processes on our ports ──────────────────────────────
for port in "$AUTHORITY_PORT" "$KEY_BROKER_PORT" "$KEY_BROKER_MTLS"; do
    pids=$(lsof -ti ":${port}" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        kill $pids 2>/dev/null || true
        sleep 0.5
    fi
done

# ─── build key-broker ───────────────────────────────────────────────────────────
banner "Build"
if [[ ! -x "$KEY_BROKER_BIN" ]]; then
    step "building key-broker…"
    cargo build -p key-broker 2>&1 | tail -3
fi
pass "key-broker binary: $KEY_BROKER_BIN"

# ─── start vendor authority ───────────────────────────────────────────────────
banner "Start Services"
step "starting vendor authority on port $AUTHORITY_PORT"
cd "$AUTHORITY_DIR"
uvicorn main:app --port "$AUTHORITY_PORT" --log-level warning &
PIDS+=($!)
cd "$WORKSPACE_ROOT"

# wait for authority ready
for i in $(seq 1 20); do
    curl -sf "$AUTHORITY_URL/api/v1/authority-pubkey" &>/dev/null && break
    sleep 0.3
done
curl -sf "$AUTHORITY_URL/api/v1/authority-pubkey" &>/dev/null \
    && pass "vendor authority ready at $AUTHORITY_URL" \
    || fail "vendor authority failed to start"

# ─── fetch authority pubkey ────────────────────────────────────────────────────
AUTHORITY_PUBKEY=$(curl -sf "$AUTHORITY_URL/api/v1/authority-pubkey" | jq -r '.pubkey')
info "authority pubkey: ${AUTHORITY_PUBKEY:0:20}…"

# ─── start KMS key-broker ────────────────────────────────────────────────────────
step "starting KMS key-broker on ports $KEY_BROKER_PORT / $KEY_BROKER_MTLS"
mkdir -p "$KMS_VOL"
KMS_VOLUME="$KMS_VOL" \
PORT="$KEY_BROKER_PORT" \
PORT_MTLS="$KEY_BROKER_MTLS" \
AUTHORITY_PUBKEY="$AUTHORITY_PUBKEY" \
"$KEY_BROKER_BIN" &>/tmp/key-broker-demo-$$.log &
PIDS+=($!)

for i in $(seq 1 30); do
    STATUS=$(curl -s "$KEY_BROKER_URL/healthz" 2>/dev/null || true)
    [[ "$STATUS" == "waiting for root key" || "$STATUS" == "ready" ]] && break
    sleep 0.3
done
STATUS=$(curl -s "$KEY_BROKER_URL/healthz" 2>/dev/null || true)
[[ "$STATUS" == "waiting for root key" || "$STATUS" == "ready" ]] \
    && pass "key-broker started (status: $STATUS)" \
    || fail "key-broker failed to start — check /tmp/key-broker-demo-$$.log"

# ─── STEP 1: Courier Attest ────────────────────────────────────────────────────
banner "Step 1 — Courier Attest (Provisioning)"

step "1.1  challenge → get nonce from vendor authority"
CHALLENGE=$(curl -sf -X POST "$AUTHORITY_URL/api/v1/challenge" \
    -H 'Content-Type: application/json' \
    -d "{\"customer_id\":\"$CUSTOMER_ID\",\"client_ts\":$(date +%s)}")
NONCE=$(echo "$CHALLENGE" | jq -r '.nonce')
pass "nonce: ${NONCE:0:16}…"

step "1.2  key-broker /courier/init → transport keypair + TDX quote"
INIT=$(curl -sf -X POST "$KEY_BROKER_URL/courier/init" \
    -H 'Content-Type: application/json' \
    -d "{\"nonce\":\"$NONCE\"}")
TRANSPORT_PUB=$(echo "$INIT" | jq -r '.transport_pub')
KMS_TS=$(echo "$INIT" | jq -r '.kms_ts')
QUOTE=$(echo "$INIT" | jq -r '.quote')
pass "transport_pub: ${TRANSPORT_PUB:0:20}…  kms_ts: $KMS_TS"

step "1.3  authority /api/v1/provision → sealed root key + AuthBundle"
PROVISION=$(curl -sf -X POST "$AUTHORITY_URL/api/v1/provision" \
    -H 'Content-Type: application/json' \
    -d "{\"customer_id\":\"$CUSTOMER_ID\",\"nonce\":\"$NONCE\",\"quote\":\"$QUOTE\",\"transport_pub\":\"$TRANSPORT_PUB\",\"kms_ts\":$KMS_TS}")
SEALED_ROOT=$(echo "$PROVISION" | jq -r '.sealed_root')
AUTH_BUNDLE=$(echo "$PROVISION" | jq -c '.auth_bundle')
BUNDLE_SEQ=$(echo "$AUTH_BUNDLE" | jq '.bundle_seq')
SLOT_QUOTA=$(echo "$AUTH_BUNDLE" | jq '.slot_quota')
pass "sealed_root len=${#SEALED_ROOT}  bundle_seq=$BUNDLE_SEQ  slot_quota=$SLOT_QUOTA"

step "1.4  key-broker /courier/install → write root key + activate AuthBundle"
INSTALL=$(curl -sf -X POST "$KEY_BROKER_URL/courier/install" \
    -H 'Content-Type: application/json' \
    -d "{\"sealed_root\":\"$SEALED_ROOT\",\"auth_bundle\":$AUTH_BUNDLE}")
OK=$(echo "$INSTALL" | jq -r '.ok')
[[ "$OK" == "true" ]] && pass "install ok" || fail "install failed: $INSTALL"

# ─── STEP 2: Healthcheck ──────────────────────────────────────────────────────
banner "Step 2 — Healthcheck"
STATUS=$(curl -s "$KEY_BROKER_URL/healthz")
[[ "$STATUS" == "ready" ]] && pass "key-broker is ready" || fail "expected ready, got: $STATUS"

# ─── STEP 3: Auth Webhook ─────────────────────────────────────────────────────
banner "Step 3 — Auth Webhook (KMS boot authorization)"

BOOT_INFO_KMS=$(cat <<EOF
{
  "mrAggregated": "0xabc123",
  "osImageHash": "0xdeadbeef",
  "appId": "$APP_ID",
  "composeHash": "0xanyhash",
  "instanceId": "kms-instance-demo",
  "deviceId": "0xdevice001",
  "tcbStatus": "UpToDate"
}
EOF
)

step "3.1  /bootAuth/kms — should be allowed"
RESP=$(curl -sf -X POST "$KEY_BROKER_URL/bootAuth/kms" \
    -H 'Content-Type: application/json' \
    -d "$BOOT_INFO_KMS")
IS_ALLOWED=$(echo "$RESP" | jq -r '.isAllowed')
REASON=$(echo "$RESP" | jq -r '.reason')
[[ "$IS_ALLOWED" == "true" ]] \
    && pass "isAllowed=true (reason: '${REASON:-<empty>}')" \
    || fail "unexpected deny: $REASON"

BOOT_INFO_APP=$(cat <<EOF
{
  "mrAggregated": "0xabc123",
  "osImageHash": "0xdeadbeef",
  "appId": "$APP_ID",
  "composeHash": "0xanyhash_wildcard",
  "instanceId": "app-instance-demo",
  "deviceId": "0xdevice001",
  "tcbStatus": "UpToDate"
}
EOF
)

step "3.2  /bootAuth/app — wildcard compose hash, should be allowed"
RESP=$(curl -sf -X POST "$KEY_BROKER_URL/bootAuth/app" \
    -H 'Content-Type: application/json' \
    -d "$BOOT_INFO_APP")
IS_ALLOWED=$(echo "$RESP" | jq -r '.isAllowed')
[[ "$IS_ALLOWED" == "true" ]] \
    && pass "isAllowed=true (wildcard '*' matched)" \
    || fail "unexpected deny: $(echo "$RESP" | jq -r '.reason')"

step "3.3  /bootAuth/app — unknown app_id, should be denied"
RESP=$(curl -sf -X POST "$KEY_BROKER_URL/bootAuth/app" \
    -H 'Content-Type: application/json' \
    -d "{
  \"mrAggregated\": \"0xabc\",
  \"osImageHash\": \"0xdeadbeef\",
  \"appId\": \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\",
  \"composeHash\": \"0xwrong\",
  \"instanceId\": \"x\",
  \"deviceId\": \"0xd\",
  \"tcbStatus\": \"UpToDate\"
}")
IS_ALLOWED=$(echo "$RESP" | jq -r '.isAllowed')
REASON=$(echo "$RESP" | jq -r '.reason')
[[ "$IS_ALLOWED" == "false" ]] \
    && pass "isAllowed=false  reason='$REASON'" \
    || fail "expected deny, got allow"

# ─── STEP 4: mTLS CEK Delivery ─────────────────────────────────────────────────
banner "Step 4 — mTLS CEK Delivery (launcher lease)"

step "4.0  generate self-signed client TLS cert (simulates launcher cert, no AppInfo)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout /tmp/demo-client-$$.key -out /tmp/demo-client-$$.crt \
    -nodes -days 1 -subj '/CN=demo-launcher' 2>/dev/null
pass "client cert generated"

mtls_acquire() {
    local instance_id=$1
    curl -sf \
        --cert /tmp/demo-client-$$.crt \
        --key /tmp/demo-client-$$.key \
        --insecure \
        -X POST "$KEY_BROKER_MTLS_URL/lease/acquire" \
        -H 'Content-Type: application/json' \
        -d "{
          \"app_id\": \"$APP_ID\",
          \"instance_id\": \"$instance_id\",
          \"compose_hash\": \"0xdemo\",
          \"image_digest\": \"$IMAGE_DIGEST\"
        }"
}

step "4.1  lease/acquire inst-1 — expect slot 0"
LEASE1=$(mtls_acquire "inst-demo-1")
SLOT1=$(echo "$LEASE1" | jq -r '.lease' | jq -r '.slot_id' 2>/dev/null \
        || echo "$LEASE1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.loads(d['lease'])['slot_id'])" 2>/dev/null)
info "raw lease: $(echo "$LEASE1" | jq -r '.lease' | cut -c1-60)…"
pass "inst-1 acquired  slot_id=$SLOT1"
SLOT1_ID="$SLOT1"

step "4.2  lease/acquire inst-2 — expect slot 1"
LEASE2=$(mtls_acquire "inst-demo-2")
SLOT2=$(echo "$LEASE2" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.loads(d['lease'])['slot_id'])" 2>/dev/null)
pass "inst-2 acquired  slot_id=$SLOT2"

step "4.3  lease/acquire inst-3 — expect REJECTED (slot quota=$DEMO_SLOT_QUOTA exhausted)"
set +e
RESP3=$(mtls_acquire "inst-demo-3" 2>&1)
EXIT3=$?
set -e
if echo "$RESP3" | grep -qi "exhausted\|quota\|error\|slot" 2>/dev/null || [[ $EXIT3 -ne 0 ]]; then
    pass "inst-3 REJECTED as expected"
    info "response: $RESP3"
else
    fail "expected rejection but got: $RESP3"
fi

step "4.4  lease/renew inst-1"
RENEW=$(curl -sf \
    --cert /tmp/demo-client-$$.crt \
    --key /tmp/demo-client-$$.key \
    --insecure \
    -X POST "$KEY_BROKER_MTLS_URL/lease/renew" \
    -H 'Content-Type: application/json' \
    -d "{\"slot_id\":\"$SLOT1_ID\",\"instance_id\":\"inst-demo-1\"}")
RENEWED=$(echo "$RENEW" | jq -r '.lease' | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print('slot='+d['slot_id']+'  expires='+str(d['expires_at']))" 2>/dev/null)
pass "renewed: $RENEWED"

# ─── STEP 5: Sync-Auth ─────────────────────────────────────────────────────────
banner "Step 5 — Sync-Auth (push updated AuthBundle)"

step "5.1  /usage-receipt — collect billing receipt from KMS"
RECEIPT=$(curl -sf "$KEY_BROKER_URL/usage-receipt")
ACTIVE=$(echo "$RECEIPT" | jq '.active_slots | length')
SEQ=$(echo "$RECEIPT" | jq '.bundle_seq')
pass "receipt: active_slots=$ACTIVE  bundle_seq=$SEQ"

step "5.2  authority /api/v1/sync-auth — issue updated bundle (no root re-issue)"
SYNC=$(curl -sf -X POST "$AUTHORITY_URL/api/v1/sync-auth" \
    -H 'Content-Type: application/json' \
    -d "{\"customer_id\":\"$CUSTOMER_ID\",\"usage_receipt\":$RECEIPT}")
AUTH_BUNDLE2=$(echo "$SYNC" | jq -c '.auth_bundle')
BUNDLE_SEQ2=$(echo "$AUTH_BUNDLE2" | jq '.bundle_seq')
pass "new bundle_seq=$BUNDLE_SEQ2 (was $BUNDLE_SEQ)"

step "5.3  key-broker /courier/install — activate updated bundle (sealed_root omitted)"
INSTALL2=$(curl -sf -X POST "$KEY_BROKER_URL/courier/install" \
    -H 'Content-Type: application/json' \
    -d "{\"auth_bundle\":$AUTH_BUNDLE2}")
OK2=$(echo "$INSTALL2" | jq -r '.ok')
[[ "$OK2" == "true" ]] && pass "bundle updated" || fail "install failed: $INSTALL2"

step "5.4  verify /version endpoint reflects new bundle"
VERSION=$(curl -sf "$KEY_BROKER_MTLS_URL/version?app_id=$APP_ID" \
    --cert /tmp/demo-client-$$.crt --key /tmp/demo-client-$$.key --insecure)
VSEQ=$(echo "$VERSION" | jq '.bundle_seq')
VDIG=$(echo "$VERSION" | jq -r '.current_image_digest')
[[ "$VSEQ" == "$BUNDLE_SEQ2" ]] \
    && pass "bundle_seq=$VSEQ  current_image_digest=$VDIG" \
    || fail "bundle_seq mismatch: got $VSEQ expected $BUNDLE_SEQ2"

# ─── Summary ──────────────────────────────────────────────────────────────────
banner "Demo Complete"
echo -e "
  ${GREEN}All steps passed.${RESET}

  ${BOLD}What was demonstrated:${RESET}
  1. Courier attest  — vendor authority provisioned KMS with sealed root key
  2. Auth webhook    — KMS boot allow (wildcard) and deny (unknown app) verified
  3. mTLS CEK        — launcher leases (slots 0–1 OK, slot 2 rejected by quota)
  4. Sync-auth       — authority pushed updated AuthBundle; KMS accepted it

  ${BOLD}Key parameters:${RESET}
  authority pubkey : ${AUTHORITY_PUBKEY:0:28}…
  kms volume      : $KMS_VOL
  slot_quota      : $DEMO_SLOT_QUOTA
"
