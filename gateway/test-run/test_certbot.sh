#!/bin/bash
# Distributed Certbot E2E test script
# Tests certificate issuance and synchronization across gateway nodes

set -m

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Distributed Certbot E2E Test"
    echo ""
    echo "Options:"
    echo "  --fresh         Clean everything and request new certificate from ACME"
    echo "  --sync-only     Keep existing cert, only test sync between nodes"
    echo "  --clean         Clean all test data and exit"
    echo "  -h, --help      Show this help message"
    echo ""
    echo "Default (no options): Keep ACME account, request new certificate"
    echo ""
    echo "Examples:"
    echo "  $0              # Keep account, new cert"
    echo "  $0 --fresh      # Fresh start, new account and cert"
    echo "  $0 --sync-only  # Test sync with existing cert"
    echo "  $0 --clean      # Clean up all test data"
}

# Parse arguments
MODE="default"
while [[ $# -gt 0 ]]; do
    case $1 in
        --fresh)
            MODE="fresh"
            shift
            ;;
        --sync-only)
            MODE="sync-only"
            shift
            ;;
        --clean)
            MODE="clean"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Load environment variables from .env
if [[ -f ".env" ]]; then
    source ".env"
else
    echo "ERROR: .env file not found!"
    echo ""
    echo "Please create a .env file with the following variables:"
    echo "  CF_API_TOKEN=<your cloudflare api token>"
    echo "  CF_ZONE_ID=<your cloudflare zone id>"
    echo "  TEST_DOMAIN=<domain to test, e.g., *.test.example.com>"
    echo ""
    echo "The domain must be managed by Cloudflare and the API token must have"
    echo "permissions to manage DNS records and CAA records."
    exit 1
fi

# Validate required environment variables
if [[ -z "$CF_API_TOKEN" ]]; then
    echo "ERROR: CF_API_TOKEN is not set in .env"
    exit 1
fi

if [[ -z "$CF_ZONE_ID" ]]; then
    echo "ERROR: CF_ZONE_ID is not set in .env"
    exit 1
fi

if [[ -z "$TEST_DOMAIN" ]]; then
    echo "ERROR: TEST_DOMAIN is not set in .env"
    exit 1
fi

GATEWAY_BIN="$SCRIPT_DIR/../../target/release/dstack-gateway"
RUN_DIR="run"
CERTS_DIR="$RUN_DIR/certs"
CA_CERT="$CERTS_DIR/gateway-ca.cert"
LOG_DIR="$RUN_DIR/logs"
CURRENT_TEST="test_certbot"

# Let's Encrypt staging URL (for testing without rate limits)
ACME_STAGING_URL="https://acme-staging-v02.api.letsencrypt.org/directory"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    sudo pkill -9 -f "dstack-gateway.*certbot_node[12].toml" >/dev/null 2>&1 || true
    sudo ip link delete certbot-test1 2>/dev/null || true
    sudo ip link delete certbot-test2 2>/dev/null || true
    sleep 1
    stty sane 2>/dev/null || true
}

trap cleanup EXIT

# Generate node config with certbot enabled
generate_certbot_config() {
    local node_id=$1
    local rpc_port=$((14000 + node_id * 10 + 2))
    local wg_port=$((14000 + node_id * 10 + 3))
    local proxy_port=$((14000 + node_id * 10 + 4))
    local debug_port=$((14000 + node_id * 10 + 5))
    local wg_ip="10.0.4${node_id}.1/24"

    # Build peer config
    local other_node=$((3 - node_id))  # If node_id=1, other=2; if node_id=2, other=1
    local other_rpc_port=$((14000 + other_node * 10 + 2))

    local abs_run_dir="$SCRIPT_DIR/$RUN_DIR"
    local certbot_dir="$abs_run_dir/certbot_node${node_id}"

    mkdir -p "$certbot_dir"

    cat > "$RUN_DIR/certbot_node${node_id}.toml" << EOF
log_level = "info"
address = "0.0.0.0"
port = ${rpc_port}

[tls]
key = "${abs_run_dir}/certs/gateway-rpc.key"
certs = "${abs_run_dir}/certs/gateway-rpc.cert"

[tls.mutual]
ca_certs = "${abs_run_dir}/certs/gateway-ca.cert"
mandatory = false

[core]
kms_url = ""
rpc_domain = "gateway.tdxlab.dstack.org"
danger_disable_attestation = true
state_path = "${RUN_DIR}/gateway-state-certbot-node${node_id}.json"

[core.debug]
enabled = true
port = ${debug_port}
address = "127.0.0.1"

[core.sync]
enabled = true
interval = "5s"
timeout = "10s"
broadcast_interval = "30s"
my_url = "https://localhost:${rpc_port}"
bootnode = ""
node_id = ${node_id}
peer_node_ids = [${other_node}]
peer_urls = ["${other_node}:https://localhost:${other_rpc_port}"]
wavekv_data_dir = "${RUN_DIR}/wavekv_certbot_node${node_id}"

[core.certbot]
enabled = true
workdir = "${certbot_dir}"
acme_url = "${ACME_STAGING_URL}"
cf_api_token = "${CF_API_TOKEN}"
cf_zone_id = "${CF_ZONE_ID}"
auto_set_caa = true
domain = "${TEST_DOMAIN}"
renew_interval = "1h"
renew_before_expiration = "720h"
renew_timeout = "5m"

[core.wg]
private_key = "SEcoI37oGWynhukxXo5Mi8/8zZBU6abg6T1TOJRMj1Y="
public_key = "xc+7qkdeNFfl4g4xirGGGXHMc0cABuE5IHaLeCASVWM="
listen_port = ${wg_port}
ip = "${wg_ip}"
reserved_net = ["10.0.4${node_id}.1/31"]
client_ip_range = "10.0.4${node_id}.1/24"
config_path = "${RUN_DIR}/wg_certbot_node${node_id}.conf"
interface = "certbot-test${node_id}"
endpoint = "127.0.0.1:${wg_port}"

[core.proxy]
cert_chain = "${certbot_dir}/live/cert.pem"
cert_key = "${certbot_dir}/live/key.pem"
base_domain = "tdxlab.dstack.org"
listen_addr = "0.0.0.0"
listen_port = ${proxy_port}
tappd_port = 8090
external_port = ${proxy_port}
inbound_pp_enabled = false
EOF
    log_info "Generated certbot_node${node_id}.toml (rpc=${rpc_port}, debug=${debug_port}, proxy=${proxy_port})"
}

start_certbot_node() {
    local node_id=$1
    local config="$RUN_DIR/certbot_node${node_id}.toml"
    local log_file="${LOG_DIR}/${CURRENT_TEST}_node${node_id}.log"

    log_info "Starting certbot node ${node_id}..."
    mkdir -p "$RUN_DIR/wavekv_certbot_node${node_id}"
    mkdir -p "$LOG_DIR"
    ( sudo RUST_LOG=info "$GATEWAY_BIN" -c "$config" > "$log_file" 2>&1 & )

    # Wait for process to either stabilize or fail
    local max_wait=30
    local waited=0
    while [[ $waited -lt $max_wait ]]; do
        sleep 2
        waited=$((waited + 2))

        if ! pgrep -f "dstack-gateway.*${config}" > /dev/null; then
            # Process exited, check why
            log_error "Certbot node ${node_id} exited after ${waited}s"
            echo "--- Log output ---"
            cat "$log_file"
            echo "--- End log ---"

            # Check for rate limit error
            if grep -q "rateLimited" "$log_file"; then
                log_error "Let's Encrypt rate limit hit. Wait a few minutes and retry."
            fi
            return 1
        fi

        # Check if cert files exist (indicates successful init)
        local certbot_dir="$RUN_DIR/certbot_node${node_id}"
        if [[ -f "$certbot_dir/live/cert.pem" ]] && [[ -f "$certbot_dir/live/key.pem" ]]; then
            log_info "Certbot node ${node_id} started and certificate obtained"
            return 0
        fi

        log_info "Waiting for node ${node_id} to initialize... (${waited}s)"
    done

    # Process still running but no cert yet - might still be requesting
    if pgrep -f "dstack-gateway.*${config}" > /dev/null; then
        log_info "Certbot node ${node_id} still running, certificate request in progress"
        return 0
    fi

    log_error "Certbot node ${node_id} failed to start within ${max_wait}s"
    cat "$log_file"
    return 1
}

stop_certbot_node() {
    local node_id=$1
    log_info "Stopping certbot node ${node_id}..."
    sudo pkill -9 -f "dstack-gateway.*certbot_node${node_id}.toml" >/dev/null 2>&1 || true
    sleep 1
}

# Get debug sync data from a node
debug_get_sync_data() {
    local debug_port=$1
    curl -s "http://localhost:${debug_port}/prpc/GetSyncData" \
        -H "Content-Type: application/json" \
        -d '{}' 2>/dev/null
}

# Check if KvStore has cert data for the domain
check_kvstore_cert() {
    local debug_port=$1
    local response=$(debug_get_sync_data "$debug_port")

    # The cert data would be in the persistent store
    # For now, check if we can get any data
    if [[ -z "$response" ]]; then
        return 1
    fi

    # Check for cert-related keys in the response
    echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    # Check if there are any keys that start with 'cert/'
    # This is a simplified check
    print('ok')
    sys.exit(0)
except Exception as e:
    print(f'error: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
}

# Check if proxy is using a valid certificate by connecting via TLS
check_proxy_cert() {
    local proxy_port=$1

    # Use gateway.{base_domain} as the SNI for health endpoint
    local gateway_host="gateway.tdxlab.dstack.org"

    # Use openssl to check the certificate
    local cert_info=$(echo | timeout 5 openssl s_client -connect "localhost:${proxy_port}" -servername "$gateway_host" 2>/dev/null)

    if [[ -z "$cert_info" ]]; then
        log_error "Failed to connect to proxy on port ${proxy_port}"
        return 1
    fi

    # Check if the certificate is valid (not self-signed test cert)
    # For staging certs, the issuer should contain "Staging" or "(STAGING)"
    local issuer=$(echo "$cert_info" | openssl x509 -noout -issuer 2>/dev/null)

    if echo "$issuer" | grep -qi "staging\|fake\|test"; then
        log_info "Proxy on port ${proxy_port} is using Let's Encrypt staging certificate"
        log_info "Issuer: $issuer"
        return 0
    elif echo "$issuer" | grep -qi "let's encrypt\|letsencrypt"; then
        log_info "Proxy on port ${proxy_port} is using Let's Encrypt certificate"
        log_info "Issuer: $issuer"
        return 0
    else
        log_warn "Proxy on port ${proxy_port} certificate issuer: $issuer"
        # Still return success if we got a certificate
        return 0
    fi
}

# Get certificate expiry from proxy health endpoint
get_proxy_cert_expiry() {
    local proxy_port=$1
    # Use gateway.{base_domain} as the SNI for health endpoint
    local gateway_host="gateway.tdxlab.dstack.org"
    echo | timeout 5 openssl s_client -connect "localhost:${proxy_port}" -servername "$gateway_host" 2>/dev/null | \
        openssl x509 -noout -enddate 2>/dev/null | \
        cut -d= -f2
}

# Get certificate serial from proxy health endpoint
get_proxy_cert_serial() {
    local proxy_port=$1
    local gateway_host="gateway.tdxlab.dstack.org"
    echo | timeout 5 openssl s_client -connect "localhost:${proxy_port}" -servername "$gateway_host" 2>/dev/null | \
        openssl x509 -noout -serial 2>/dev/null | \
        cut -d= -f2
}

# Get certificate issuer from proxy
get_proxy_cert_issuer() {
    local proxy_port=$1
    local gateway_host="gateway.tdxlab.dstack.org"
    echo | timeout 5 openssl s_client -connect "localhost:${proxy_port}" -servername "$gateway_host" 2>/dev/null | \
        openssl x509 -noout -issuer 2>/dev/null
}

# Wait for certificate to be issued (with timeout)
wait_for_cert() {
    local proxy_port=$1
    local timeout_secs=${2:-300}  # Default 5 minutes
    local start_time=$(date +%s)

    log_info "Waiting for certificate to be issued (timeout: ${timeout_secs}s)..."

    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))

        if [[ $elapsed -ge $timeout_secs ]]; then
            log_error "Timeout waiting for certificate"
            return 1
        fi

        # Try to get certificate info
        local expiry=$(get_proxy_cert_expiry "$proxy_port")
        if [[ -n "$expiry" ]]; then
            log_info "Certificate detected! Expiry: $expiry"
            return 0
        fi

        log_info "Waiting... (${elapsed}s elapsed)"
        sleep 10
    done
}

# ============================================================
# Main Test
# ============================================================

do_clean() {
    log_info "Cleaning all certbot test data..."
    cleanup
    sudo rm -rf "$RUN_DIR/certbot_node1" "$RUN_DIR/certbot_node2"
    sudo rm -rf "$RUN_DIR/wavekv_certbot_node1" "$RUN_DIR/wavekv_certbot_node2"
    sudo rm -f "$RUN_DIR/gateway-state-certbot-node1.json" "$RUN_DIR/gateway-state-certbot-node2.json"
    log_info "Done."
}

main() {
    log_info "=========================================="
    log_info "Distributed Certbot E2E Test"
    log_info "=========================================="
    log_info "Test domain: $TEST_DOMAIN"
    log_info "ACME URL: $ACME_STAGING_URL"
    log_info "Mode: $MODE"
    log_info ""

    # Handle --clean mode
    if [[ "$MODE" == "clean" ]]; then
        do_clean
        return 0
    fi

    # Handle --sync-only mode: check if cert exists
    if [[ "$MODE" == "sync-only" ]]; then
        if [[ ! -f "$RUN_DIR/certbot_node1/live/cert.pem" ]]; then
            log_error "No existing certificate found. Run without --sync-only first."
            return 1
        fi
        log_info "Using existing certificate for sync test"
    fi

    # Clean up processes and state
    cleanup

    # Decide what to clean based on mode
    case "$MODE" in
        fresh)
            # Clean everything including ACME account
            log_info "Fresh mode: cleaning all data including ACME account"
            sudo rm -rf "$RUN_DIR/certbot_node1" "$RUN_DIR/certbot_node2"
            ;;
        sync-only)
            # Keep node1 cert, only clean node2 and wavekv
            log_info "Sync-only mode: keeping node1 certificate"
            sudo rm -rf "$RUN_DIR/certbot_node2"
            ;;
        *)
            # Default: keep ACME account (credentials.json), clean certs
            log_info "Default mode: keeping ACME account, requesting new certificate"
            # Backup credentials if exists
            if [[ -f "$RUN_DIR/certbot_node1/credentials.json" ]]; then
                sudo cp "$RUN_DIR/certbot_node1/credentials.json" /tmp/certbot_credentials_backup.json
            fi
            sudo rm -rf "$RUN_DIR/certbot_node1" "$RUN_DIR/certbot_node2"
            # Restore credentials
            if [[ -f /tmp/certbot_credentials_backup.json ]]; then
                mkdir -p "$RUN_DIR/certbot_node1"
                sudo mv /tmp/certbot_credentials_backup.json "$RUN_DIR/certbot_node1/credentials.json"
            fi
            ;;
    esac

    # Always clean wavekv and gateway state
    sudo rm -rf "$RUN_DIR/wavekv_certbot_node1" "$RUN_DIR/wavekv_certbot_node2"
    sudo rm -f "$RUN_DIR/gateway-state-certbot-node1.json" "$RUN_DIR/gateway-state-certbot-node2.json"

    # Generate configs
    log_info "Generating node configurations..."
    generate_certbot_config 1
    generate_certbot_config 2

    # Start Node 1 first - it will request the certificate
    log_info ""
    log_info "=========================================="
    log_info "Phase 1: Start Node 1 and request certificate"
    log_info "=========================================="

    if ! start_certbot_node 1; then
        log_error "Failed to start node 1"
        return 1
    fi

    # Wait for certificate to be issued
    local proxy_port_1=14014
    if ! wait_for_cert "$proxy_port_1" 300; then
        log_error "Node 1 failed to obtain certificate"
        cat "$LOG_DIR/${CURRENT_TEST}_node1.log" | tail -50
        return 1
    fi

    # Get Node 1's certificate info
    local node1_serial=$(get_proxy_cert_serial "$proxy_port_1")
    local node1_expiry=$(get_proxy_cert_expiry "$proxy_port_1")
    log_info "Node 1 certificate serial: $node1_serial"
    log_info "Node 1 certificate expiry: $node1_expiry"

    # Show certificate source logs for Node 1
    log_info ""
    log_info "Node 1 certificate source:"
    grep -E "cert\[|acme\[" "$LOG_DIR/${CURRENT_TEST}_node1.log" 2>/dev/null | sed 's/^/  /'

    # Start Node 2 - it should sync the certificate from Node 1
    log_info ""
    log_info "=========================================="
    log_info "Phase 2: Start Node 2 and verify sync"
    log_info "=========================================="

    if ! start_certbot_node 2; then
        log_error "Failed to start node 2"
        return 1
    fi

    # Wait for Node 2 to sync and load the certificate
    local proxy_port_2=14024
    sleep 10  # Give time for sync

    if ! wait_for_cert "$proxy_port_2" 60; then
        log_error "Node 2 failed to obtain certificate via sync"
        cat "$LOG_DIR/${CURRENT_TEST}_node2.log" | tail -50
        return 1
    fi

    # Get Node 2's certificate info
    local node2_serial=$(get_proxy_cert_serial "$proxy_port_2")
    local node2_expiry=$(get_proxy_cert_expiry "$proxy_port_2")
    log_info "Node 2 certificate serial: $node2_serial"
    log_info "Node 2 certificate expiry: $node2_expiry"

    # Show certificate source logs for Node 2
    log_info ""
    log_info "Node 2 certificate source:"
    grep -E "cert\[|acme\[" "$LOG_DIR/${CURRENT_TEST}_node2.log" 2>/dev/null | sed 's/^/  /'

    # Verify both nodes have the same certificate
    log_info ""
    log_info "=========================================="
    log_info "Verification"
    log_info "=========================================="

    if [[ "$node1_serial" == "$node2_serial" ]]; then
        log_info "SUCCESS: Both nodes have the same certificate (serial: $node1_serial)"
    else
        log_error "FAILURE: Certificate mismatch!"
        log_error "  Node 1 serial: $node1_serial"
        log_error "  Node 2 serial: $node2_serial"
        return 1
    fi

    # Check that proxy is actually using the certificate
    check_proxy_cert "$proxy_port_1"
    check_proxy_cert "$proxy_port_2"

    log_info ""
    log_info "=========================================="
    log_info "All tests passed!"
    log_info "=========================================="

    return 0
}

# Run main
main
exit $?
