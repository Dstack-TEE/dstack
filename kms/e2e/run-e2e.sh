#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# KMS End-to-End Test Script
# Tests the full stack: Hardhat node → contract deployment → auth-eth → KMS
# with real TDX attestation via TEE proxy
#
# Usage: ./kms/e2e/run-e2e.sh [--skip-build]

set -e

# ==================== Configuration ====================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AUTH_ETH_DIR="$SCRIPT_DIR/../auth-eth"

# TEE attestation proxy
export DSTACK_AGENT_ADDRESS="${DSTACK_AGENT_ADDRESS:-https://712eab2f507b963e11144ae67218177e93ac2a24-3000.tdxlab.dstack.org:13004}"

# Ports: support concurrent runs via env override or random allocation
get_free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}
HARDHAT_PORT="${HARDHAT_PORT:-$(get_free_port)}"
AUTH_ETH_PORT="${AUTH_ETH_PORT:-$(get_free_port)}"
KMS_PORT="${KMS_PORT:-$(get_free_port)}"

# Hardhat account #0 (pre-funded with 10000 ETH)
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Process tracking
PIDS=()

# ==================== Logging ====================

log_info()    { printf "${BLUE}[INFO]${NC} %s\n" "$1"; }
log_warn()    { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
log_error()   { printf "${RED}[ERROR]${NC} %s\n" "$1"; }
log_success() { printf "${GREEN}[PASS]${NC} %s\n" "$1"; }
log_fail()    { printf "${RED}[FAIL]${NC} %s\n" "$1"; }

log_section() {
    printf "\n"
    log_info "=========================================="
    log_info "$1"
    log_info "=========================================="
}

log_phase() {
    printf "\n"
    log_info "Phase $1: $2"
    log_info "------------------------------------------"
}

# ==================== Test Utilities ====================

run_test() {
    local name="$1"
    local result="$2"

    if [ "$result" = "0" ]; then
        log_success "$name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "$name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Wait for HTTP service to respond
wait_for_service() {
    local url="$1"
    local name="$2"
    local max_wait="${3:-60}"
    local curl_opts="${4:-}"
    local waited=0

    log_info "Waiting for $name..."
    while [ $waited -lt $max_wait ]; do
        if curl -sf $curl_opts "$url" > /dev/null 2>&1; then
            log_info "$name is ready"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    log_error "$name failed to become ready within ${max_wait}s"
    return 1
}

cleanup() {
    log_info "Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    # Wait briefly for processes to exit
    sleep 1
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

# Set TCB policy on the cloned DstackApp at TEE proxy's address.
# Usage: set_tcb_policy '{"version":1,"intel_qal":[]}'
set_tcb_policy() {
    local policy="$1"
    (cd "$AUTH_ETH_DIR" && POLICY_VAL="$policy" node -e "
const ethers = require('ethers');
(async () => {
    const provider = new ethers.JsonRpcProvider('$RPC_URL');
    const wallet = new ethers.Wallet('$DEPLOYER_KEY', provider);
    const mock = new ethers.Contract(
        '$TEE_APP_ID',
        ['function setTcbPolicy(string)'],
        wallet
    );
    await (await mock.setTcbPolicy(process.env.POLICY_VAL)).wait();
})().catch(e => { console.error(e.message); process.exit(1); });
")
}

# Run e2e-client and check if GetAppKey matches expected status.
# Usage: expect_get_app_key "ok" "test description"
#        expect_get_app_key "error" "test description"
expect_get_app_key() {
    local expected_status="$1"
    local test_name="$2"

    local output
    output=$("$E2E_CLIENT" test \
        --kms-url "https://127.0.0.1:$KMS_PORT" \
        --vm-config "$TEE_VM_CONFIG" \
        2>"$WORK_DIR/e2e-policy.log") || true

    local actual_status
    actual_status=$(echo "$output" | jq -r 'select(.test == "GetAppKey") | .status' 2>/dev/null)

    if [ "$actual_status" = "$expected_status" ]; then
        run_test "$test_name" "0"
    else
        local error_msg
        error_msg=$(echo "$output" | jq -r 'select(.test == "GetAppKey") | .error // "N/A"' 2>/dev/null)
        log_info "  Expected=$expected_status Got=$actual_status Error=$error_msg"
        run_test "$test_name" "1"
    fi
}

# Build a TDX platform TCB policy JSON from a reference object.
# Targets both TDX 1.0 and 1.5 platform class_ids.
# Usage: POLICY=$(make_tdx_policy '{"allow_dynamic_platform":false}')
make_tdx_policy() {
    local ref_json="$1"
    node -e "
const ref = JSON.parse(process.argv[1]);
const tdx10 = JSON.stringify({environment:{class_id:'9eec018b-7481-4b1c-8e1a-9f7c0c8c777f'},reference:ref});
const tdx15 = JSON.stringify({environment:{class_id:'f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3'},reference:ref});
console.log(JSON.stringify({version:1,intel_qal:[tdx10,tdx15]}));
" "$ref_json"
}

# ==================== Phase 0: Setup ====================

log_section "KMS E2E Test"
log_phase 0 "Setup"

# Parse args
SKIP_BUILD=false
for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
    esac
done

# Create temp work directory
WORK_DIR=$(mktemp -d)
CERT_DIR="$WORK_DIR/certs"
IMAGE_CACHE_DIR="$WORK_DIR/images"
mkdir -p "$CERT_DIR" "$IMAGE_CACHE_DIR"
log_info "Work directory: $WORK_DIR"
log_info "Ports: hardhat=$HARDHAT_PORT auth-eth=$AUTH_ETH_PORT kms=$KMS_PORT"
log_info "TEE proxy: $DSTACK_AGENT_ADDRESS"

# Ensure auth-eth dependencies
if [ ! -d "$AUTH_ETH_DIR/node_modules" ]; then
    log_info "Installing auth-eth dependencies..."
    (cd "$AUTH_ETH_DIR" && npm ci)
fi

# Build KMS and e2e-client
if [ "$SKIP_BUILD" = false ]; then
    log_info "Building KMS and e2e-client..."
    (cd "$REPO_ROOT" && cargo build -p dstack-kms -p kms-e2e-client 2>&1 | tail -1)
fi

KMS_BIN="$REPO_ROOT/target/debug/dstack-kms"
E2E_CLIENT="$REPO_ROOT/target/debug/kms-e2e-client"
if [ ! -x "$KMS_BIN" ]; then
    log_error "KMS binary not found at $KMS_BIN"
    exit 1
fi
if [ ! -x "$E2E_CLIENT" ]; then
    log_error "E2E client binary not found at $E2E_CLIENT"
    exit 1
fi
log_info "KMS binary: $KMS_BIN"
log_info "E2E client: $E2E_CLIENT"

# ==================== Phase 1: Probe TEE proxy ====================

log_phase 1 "Probe TEE proxy for measurements"

PROBE_OUTPUT=$("$E2E_CLIENT" probe 2>/dev/null) || {
    log_error "Failed to probe TEE proxy"
    log_error "Is the TEE proxy reachable at $DSTACK_AGENT_ADDRESS?"
    exit 1
}
log_info "TEE proxy measurements:"
echo "$PROBE_OUTPUT" | head -10

# Extract measurements for contract whitelisting
TEE_APP_ID=$(echo "$PROBE_OUTPUT" | jq -r '.app_id')
TEE_COMPOSE_HASH=$(echo "$PROBE_OUTPUT" | jq -r '.compose_hash')
TEE_DEVICE_ID=$(echo "$PROBE_OUTPUT" | jq -r '.device_id')
TEE_MR_AGGREGATED=$(echo "$PROBE_OUTPUT" | jq -r '.mr_aggregated')
TEE_OS_IMAGE_HASH=$(echo "$PROBE_OUTPUT" | jq -r '.os_image_hash')
TEE_VM_CONFIG=$(echo "$PROBE_OUTPUT" | jq -r '.vm_config')

log_info "app_id:        $TEE_APP_ID"
log_info "compose_hash:  $TEE_COMPOSE_HASH"
log_info "device_id:     $TEE_DEVICE_ID"
log_info "mr_aggregated: $TEE_MR_AGGREGATED"
log_info "os_image_hash: $TEE_OS_IMAGE_HASH"

# ==================== Phase 2: Start Hardhat & Deploy Contracts ====================

log_phase 2 "Start Hardhat node and deploy contracts"

(cd "$AUTH_ETH_DIR" && npx hardhat node --port $HARDHAT_PORT > "$WORK_DIR/hardhat.log" 2>&1) &
PIDS+=($!)
log_info "Hardhat node PID: ${PIDS[-1]}"

# Hardhat node responds to JSON-RPC, not plain HTTP GET. Use a POST check.
wait_for_hardhat() {
    local max_wait="${1:-60}"
    local waited=0
    log_info "Waiting for Hardhat node..."
    while [ $waited -lt $max_wait ]; do
        if curl -sf -X POST "http://127.0.0.1:$HARDHAT_PORT" \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' > /dev/null 2>&1; then
            log_info "Hardhat node is ready"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    log_error "Hardhat node failed to become ready within ${max_wait}s"
    cat "$WORK_DIR/hardhat.log" | tail -20
    return 1
}

wait_for_hardhat

export RPC_URL="http://127.0.0.1:$HARDHAT_PORT"
export PRIVATE_KEY="$DEPLOYER_KEY"

cd "$AUTH_ETH_DIR"

# Deploy DstackKms with DstackApp implementation
log_info "Deploying DstackKms..."
DEPLOY_OUTPUT=$(yes | npx hardhat kms:deploy --with-app-impl --network custom 2>&1) || {
    log_error "Contract deployment failed:"
    echo "$DEPLOY_OUTPUT"
    exit 1
}

# Parse KMS contract address from output
KMS_CONTRACT_ADDR=$(echo "$DEPLOY_OUTPUT" | grep -i "proxy" | grep -oE '0x[0-9a-fA-F]{40}' | tail -1)
if [ -z "$KMS_CONTRACT_ADDR" ]; then
    log_error "Failed to parse KMS contract address from deploy output:"
    echo "$DEPLOY_OUTPUT"
    exit 1
fi
log_info "DstackKms deployed at: $KMS_CONTRACT_ADDR"
export KMS_CONTRACT_ADDRESS="$KMS_CONTRACT_ADDR"

# Whitelist TEE proxy's MR, OS image hash, and device ID for KMS boot auth
log_info "Adding KMS whitelists (TEE proxy measurements)..."
npx hardhat kms:add "$TEE_MR_AGGREGATED" --network custom > /dev/null 2>&1
npx hardhat kms:add-image "$TEE_OS_IMAGE_HASH" --network custom > /dev/null 2>&1
npx hardhat kms:add-device "$TEE_DEVICE_ID" --network custom > /dev/null 2>&1
log_info "KMS whitelists configured with TEE proxy measurements"

# Create an app via factory method, whitelisting TEE proxy's compose hash
log_info "Creating DstackApp with TEE proxy compose hash..."
APP_OUTPUT=$(yes | npx hardhat kms:create-app --allow-any-device --hash "$TEE_COMPOSE_HASH" --network custom 2>&1) || {
    log_error "App creation failed:"
    echo "$APP_OUTPUT"
    exit 1
}

# Parse app ID (proxy address) from output
APP_ID=$(echo "$APP_OUTPUT" | grep -i "proxy address\|app.id" | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
if [ -z "$APP_ID" ]; then
    APP_ID=$(echo "$APP_OUTPUT" | grep -oE '0x[0-9a-fA-F]{40}' | tail -1)
fi
if [ -z "$APP_ID" ]; then
    log_error "Failed to parse App ID from output:"
    echo "$APP_OUTPUT"
    exit 1
fi
log_info "DstackApp created with ID: $APP_ID"

# Deploy DstackApp at TEE proxy's app_id address.
# The attestation embeds the TEE proxy's own app_id (not our DstackApp's address),
# so DstackKms.isAppAllowed() needs: registeredApps[teeAppId]=true AND isContract(teeAppId).
# We place the DstackApp implementation bytecode directly (no proxy needed), then initialize.
log_info "Deploying DstackApp at TEE proxy app_id..."
node -e "
const ethers = require('ethers');
(async () => {
    const provider = new ethers.JsonRpcProvider('$RPC_URL');
    const wallet = new ethers.Wallet('$DEPLOYER_KEY', provider);

    // Get DstackApp implementation address from the proxy's EIP-1967 slot
    const implSlot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
    const implAddr = '0x' + (await provider.getStorage('$APP_ID', implSlot)).slice(26);
    const implCode = await provider.getCode(implAddr);
    await provider.send('hardhat_setCode', ['$TEE_APP_ID', implCode]);

    // Initialize (storage is fresh so initializer passes)
    const app = new ethers.Contract('$TEE_APP_ID', [
        'function initialize(address,bool,bool,bytes32,bytes32)',
    ], wallet);
    await (await app.initialize(
        wallet.address, true, true,
        '0x' + '0'.repeat(64), '$TEE_COMPOSE_HASH'
    )).wait();

    // Register in DstackKms
    const nonce = await provider.getTransactionCount(wallet.address, 'latest');
    const kms = new ethers.Contract('$KMS_CONTRACT_ADDR', ['function registerApp(address)'], wallet);
    await (await kms.registerApp('$TEE_APP_ID', { nonce })).wait();
    console.log('DstackApp deployed and registered at: $TEE_APP_ID');
})().catch(e => { console.error(e.message); process.exit(1); });
" || {
    log_error "Failed to deploy DstackApp at TEE proxy app_id"
    exit 1
}

# ==================== Phase 3: Start auth-eth Server ====================

log_phase 3 "Start auth-eth server"

cd "$AUTH_ETH_DIR"
ETH_RPC_URL="http://127.0.0.1:$HARDHAT_PORT" \
KMS_CONTRACT_ADDR="$KMS_CONTRACT_ADDR" \
PORT=$AUTH_ETH_PORT \
HOST="127.0.0.1" \
npx ts-node src/main.ts > "$WORK_DIR/auth-eth.log" 2>&1 &
PIDS+=($!)
log_info "auth-eth PID: ${PIDS[-1]}"

wait_for_service "http://127.0.0.1:$AUTH_ETH_PORT/" "auth-eth" 30

# ==================== Phase 4: Start KMS ====================

log_phase 4 "Start KMS (with attestation enabled)"

# Generate config from template
sed -e "s|{{CERT_DIR}}|$CERT_DIR|g" \
    -e "s|{{IMAGE_CACHE_DIR}}|$IMAGE_CACHE_DIR|g" \
    -e "s|{{KMS_PORT}}|$KMS_PORT|g" \
    -e "s|{{AUTH_ETH_PORT}}|$AUTH_ETH_PORT|g" \
    "$SCRIPT_DIR/kms-test.toml.template" > "$WORK_DIR/kms-test.toml"

log_info "KMS config written to $WORK_DIR/kms-test.toml"

cd "$REPO_ROOT"
"$KMS_BIN" -c "$WORK_DIR/kms-test.toml" > "$WORK_DIR/kms.log" 2>&1 &
PIDS+=($!)
log_info "KMS PID: ${PIDS[-1]}"

# KMS uses HTTPS with self-signed certs
wait_for_service "https://127.0.0.1:$KMS_PORT/prpc/KMS.GetMeta" "KMS" 30 "-k"

# ==================== Phase 5: Run Tests ====================

log_phase 5 "Run tests"

# Disable set -e so test failures don't abort the script
set +e

# --- Auth-eth tests ---

log_info "--- Auth-eth API tests ---"

# Test 1: Health check
RESPONSE=$(curl -sf "http://127.0.0.1:$AUTH_ETH_PORT/" 2>/dev/null)
echo "$RESPONSE" | jq -e '.kmsContractAddr' > /dev/null 2>&1
run_test "auth-eth: GET / health check" "$?"

# Test 2: bootAuth/kms - allowed (whitelisted with TEE proxy measurements)
RESPONSE=$(curl -sf -X POST "http://127.0.0.1:$AUTH_ETH_PORT/bootAuth/kms" \
    -H "Content-Type: application/json" \
    -d "{
        \"tcbStatus\": \"UpToDate\",
        \"advisoryIds\": [],
        \"mrAggregated\": \"$TEE_MR_AGGREGATED\",
        \"mrSystem\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",
        \"osImageHash\": \"$TEE_OS_IMAGE_HASH\",
        \"appId\": \"0x0000000000000000000000000000000000000000\",
        \"composeHash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",
        \"instanceId\": \"0x0000000000000000000000000000000000000000\",
        \"deviceId\": \"$TEE_DEVICE_ID\"
    }" 2>/dev/null)
echo "$RESPONSE" | jq -e '.isAllowed == true' > /dev/null 2>&1
run_test "auth-eth: bootAuth/kms allowed (TEE proxy measurements)" "$?"

# Test 3: bootAuth/kms - rejected (non-whitelisted MR)
RESPONSE=$(curl -sf -X POST "http://127.0.0.1:$AUTH_ETH_PORT/bootAuth/kms" \
    -H "Content-Type: application/json" \
    -d '{
        "tcbStatus": "UpToDate",
        "advisoryIds": [],
        "mrAggregated": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "mrSystem": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "osImageHash": "'"$TEE_OS_IMAGE_HASH"'",
        "appId": "0x0000000000000000000000000000000000000000",
        "composeHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "instanceId": "0x0000000000000000000000000000000000000000",
        "deviceId": "'"$TEE_DEVICE_ID"'"
    }' 2>/dev/null)
echo "$RESPONSE" | jq -e '.isAllowed == false' > /dev/null 2>&1
run_test "auth-eth: bootAuth/kms rejected (bad MR)" "$?"

# Test 4: bootAuth/app - allowed (TEE proxy compose hash, any device)
RESPONSE=$(curl -sf -X POST "http://127.0.0.1:$AUTH_ETH_PORT/bootAuth/app" \
    -H "Content-Type: application/json" \
    -d "{
        \"tcbStatus\": \"UpToDate\",
        \"advisoryIds\": [],
        \"mrAggregated\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",
        \"mrSystem\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",
        \"osImageHash\": \"$TEE_OS_IMAGE_HASH\",
        \"appId\": \"$APP_ID\",
        \"composeHash\": \"$TEE_COMPOSE_HASH\",
        \"instanceId\": \"0x0000000000000000000000000000000000000000\",
        \"deviceId\": \"0x0000000000000000000000000000000000000000000000000000000000000000\"
    }" 2>/dev/null)
echo "$RESPONSE" | jq -e '.isAllowed == true' > /dev/null 2>&1
run_test "auth-eth: bootAuth/app allowed (TEE proxy compose hash)" "$?"

# Test 5: bootAuth/app - rejected (wrong compose hash)
RESPONSE=$(curl -sf -X POST "http://127.0.0.1:$AUTH_ETH_PORT/bootAuth/app" \
    -H "Content-Type: application/json" \
    -d "{
        \"tcbStatus\": \"UpToDate\",
        \"advisoryIds\": [],
        \"mrAggregated\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",
        \"mrSystem\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",
        \"osImageHash\": \"$TEE_OS_IMAGE_HASH\",
        \"appId\": \"$APP_ID\",
        \"composeHash\": \"0x2222222222222222222222222222222222222222222222222222222222222222\",
        \"instanceId\": \"0x0000000000000000000000000000000000000000\",
        \"deviceId\": \"0x0000000000000000000000000000000000000000000000000000000000000000\"
    }" 2>/dev/null)
echo "$RESPONSE" | jq -e '.isAllowed == false' > /dev/null 2>&1
run_test "auth-eth: bootAuth/app rejected (bad compose hash)" "$?"

# Test 6: GET /policy/kms
RESPONSE=$(curl -sf "http://127.0.0.1:$AUTH_ETH_PORT/policy/kms" 2>/dev/null)
echo "$RESPONSE" | jq -e '.tcbPolicy == ""' > /dev/null 2>&1
run_test "auth-eth: GET /policy/kms (empty default)" "$?"

# Test 7: GET /policy/app/:appId
RESPONSE=$(curl -sf "http://127.0.0.1:$AUTH_ETH_PORT/policy/app/$APP_ID" 2>/dev/null)
echo "$RESPONSE" | jq -e '.tcbPolicy == ""' > /dev/null 2>&1
run_test "auth-eth: GET /policy/app/:appId (empty default)" "$?"

# --- KMS unauthenticated tests ---

log_info "--- KMS API tests (unauthenticated) ---"

# Note: KMS prpc uses snake_case JSON field names (protobuf convention)

# Test 8: GetMeta (GET request auto-returns JSON)
RESPONSE=$(curl -sk "https://127.0.0.1:$KMS_PORT/prpc/KMS.GetMeta" 2>&1)
(
    echo "$RESPONSE" | jq -e '.ca_cert' > /dev/null 2>&1 &&
    echo "$RESPONSE" | jq -e '.k256_pubkey' > /dev/null 2>&1 &&
    echo "$RESPONSE" | jq -e '.is_dev == false' > /dev/null 2>&1
)
run_test "KMS: GetMeta returns metadata" "$?"

# Test 9: GetAppEnvEncryptPubKey (POST with JSON content type)
APP_ID_HEX=$(echo "$APP_ID" | sed 's/^0x//')
RESPONSE=$(curl -sk "https://127.0.0.1:$KMS_PORT/prpc/KMS.GetAppEnvEncryptPubKey?json" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"app_id\": \"$APP_ID_HEX\"}" 2>&1)
echo "$RESPONSE" | jq -e '.public_key' > /dev/null 2>&1
run_test "KMS: GetAppEnvEncryptPubKey returns public key" "$?"

# Test 10: GetTempCaCert (GET request)
RESPONSE=$(curl -sk "https://127.0.0.1:$KMS_PORT/prpc/KMS.GetTempCaCert" 2>&1)
(
    echo "$RESPONSE" | jq -e '.temp_ca_cert' > /dev/null 2>&1 &&
    echo "$RESPONSE" | jq -e '.temp_ca_key' > /dev/null 2>&1
)
run_test "KMS: GetTempCaCert returns temp CA" "$?"

# Test 11: GetAppKey without attestation should fail
RESPONSE=$(curl -sk "https://127.0.0.1:$KMS_PORT/prpc/KMS.GetAppKey?json" \
    -X POST -H "Content-Type: application/json" \
    -d '{"api_version": 1, "vm_config": "test"}' 2>&1)
# Should get an error (no app_cert in response)
echo "$RESPONSE" | jq -e '.app_cert' > /dev/null 2>&1
RESULT=$?
# We expect this to FAIL (no app_cert in response), so invert
if [ "$RESULT" -ne 0 ]; then
    run_test "KMS: GetAppKey rejected without attestation" "0"
else
    run_test "KMS: GetAppKey rejected without attestation" "1"
fi

# --- KMS authenticated tests (via TEE proxy attestation) ---

log_info "--- KMS API tests (with RA-TLS attestation) ---"

E2E_OUTPUT=$("$E2E_CLIENT" test \
    --kms-url "https://127.0.0.1:$KMS_PORT" \
    --vm-config "$TEE_VM_CONFIG" \
    2>"$WORK_DIR/e2e-client.log")
E2E_EXIT=$?

if [ $E2E_EXIT -ne 0 ]; then
    log_error "E2E client failed to run:"
    cat "$WORK_DIR/e2e-client.log"
    run_test "KMS: RA-TLS client setup" "1"
else
    # Parse each test result from JSON lines
    while IFS= read -r line; do
        TEST_NAME=$(echo "$line" | jq -r '.test // empty' 2>/dev/null)
        TEST_STATUS=$(echo "$line" | jq -r '.status // empty' 2>/dev/null)
        if [ -n "$TEST_NAME" ]; then
            if [ "$TEST_STATUS" = "ok" ]; then
                run_test "KMS: $TEST_NAME (RA-TLS)" "0"
            else
                TEST_ERROR=$(echo "$line" | jq -r '.error // "unknown error"' 2>/dev/null)
                log_info "  Error: $TEST_ERROR"
                run_test "KMS: $TEST_NAME (RA-TLS)" "1"
            fi
        fi
    done <<< "$E2E_OUTPUT"
fi

# --- KMS TCB policy tests (via cloned DstackApp at TEE proxy's app_id) ---

log_info "--- KMS TCB policy tests ---"

# Policy: empty intel_qal array → no additional validation → pass
set_tcb_policy '{"version":1,"intel_qal":[]}'
expect_get_app_key "ok" "Policy: empty intel_qal allows GetAppKey"

# Policy: unknown version → fail-close
set_tcb_policy '{"version":99}'
expect_get_app_key "error" "Policy: unsupported version rejects GetAppKey"

# Policy: malformed JSON → parse error → fail
set_tcb_policy 'not-json'
expect_get_app_key "error" "Policy: malformed JSON rejects GetAppKey"

# Policy: invalid Rego entries in intel_qal → build error → fail
set_tcb_policy '{"version":1,"intel_qal":["not valid rego"]}'
expect_get_app_key "error" "Policy: invalid Rego entry rejects GetAppKey"

# Policy: cleared (empty string) → back to no policy → pass
set_tcb_policy ''
expect_get_app_key "ok" "Policy: cleared policy allows GetAppKey"

# --- Intel QAL rule-level policy tests ---
# The TEE proxy's platform has: dynamic_platform=true, cached_keys=true.
# These policies target both TDX 1.0 and 1.5 platform class_ids.

log_info "--- KMS Intel QAL rule tests ---"

# Broad reference: permissive policy that accepts everything → pass
PERMISSIVE_REF='{"accepted_tcb_status":["UpToDate","OutOfDate","SWHardeningNeeded","ConfigurationAndSWHardeningNeeded","OutOfDateConfigurationNeeded"],"allow_dynamic_platform":true,"allow_cached_keys":true,"allow_smt_enabled":true,"collateral_grace_period":2592000}'
set_tcb_policy "$(make_tdx_policy "$PERMISSIVE_REF")"
expect_get_app_key "ok" "QAL rule: permissive policy allows GetAppKey"

# Reject dynamic_platform → fail (TEE proxy has dynamic_platform=true)
REJECT_DYN_REF='{"accepted_tcb_status":["UpToDate","OutOfDate","SWHardeningNeeded","ConfigurationAndSWHardeningNeeded","OutOfDateConfigurationNeeded"],"allow_dynamic_platform":false,"allow_cached_keys":true,"allow_smt_enabled":true,"collateral_grace_period":2592000}'
set_tcb_policy "$(make_tdx_policy "$REJECT_DYN_REF")"
expect_get_app_key "error" "QAL rule: reject dynamic_platform blocks GetAppKey"

# Reject cached_keys → fail (TEE proxy has cached_keys=true)
REJECT_CK_REF='{"accepted_tcb_status":["UpToDate","OutOfDate","SWHardeningNeeded","ConfigurationAndSWHardeningNeeded","OutOfDateConfigurationNeeded"],"allow_dynamic_platform":true,"allow_cached_keys":false,"allow_smt_enabled":true,"collateral_grace_period":2592000}'
set_tcb_policy "$(make_tdx_policy "$REJECT_CK_REF")"
expect_get_app_key "error" "QAL rule: reject cached_keys blocks GetAppKey"

# Only accept SWHardeningNeeded → fail (TEE proxy status is UpToDate, not in accepted list)
WRONG_TCB_REF='{"accepted_tcb_status":["SWHardeningNeeded"],"allow_dynamic_platform":true,"allow_cached_keys":true,"allow_smt_enabled":true,"collateral_grace_period":0}'
set_tcb_policy "$(make_tdx_policy "$WRONG_TCB_REF")"
expect_get_app_key "error" "QAL rule: mismatched TCB status blocks GetAppKey"

# Clean up: clear policy for any subsequent tests
set_tcb_policy ''

# ==================== Phase 6: Summary ====================

log_section "Test Summary"
log_info "Passed: $TESTS_PASSED"
if [ "$TESTS_FAILED" -gt 0 ]; then
    log_error "Failed: $TESTS_FAILED"
else
    log_info "Failed: $TESTS_FAILED"
fi
log_info "Total:  $((TESTS_PASSED + TESTS_FAILED))"

exit "$TESTS_FAILED"
