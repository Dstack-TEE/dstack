#!/bin/bash
# WaveKV integration test script

# Don't use set -e as it causes issues with cleanup and test flow
# set -e

# Disable job control messages (prevents "Killed" messages from messing up output)
set +m

# Fix terminal output - ensure proper line endings
stty -echoctl 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GATEWAY_BIN="/home/kvin/sdc/home/wavekv/dstack/target/release/dstack-gateway"
RUN_DIR="run"
CERTS_DIR="$RUN_DIR/certs"
CA_CERT="$CERTS_DIR/gateway-ca.cert"
LOG_DIR="$RUN_DIR/logs"
CURRENT_TEST=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    sudo pkill -9 -f "dstack-gateway.*node[123].toml" >/dev/null 2>&1 || true
    sudo ip link delete wavekv-test1 2>/dev/null || true
    sudo ip link delete wavekv-test2 2>/dev/null || true
    sudo ip link delete wavekv-test3 2>/dev/null || true
    sleep 1
    stty sane 2>/dev/null || true
}

trap cleanup EXIT

# Generate node configs
generate_config() {
    local node_id=$1
    local rpc_port=$((13000 + node_id * 10 + 2))
    local wg_port=$((13000 + node_id * 10 + 3))
    local proxy_port=$((13000 + node_id * 10 + 4))
    local debug_port=$((13000 + node_id * 10 + 5))
    local wg_ip="10.0.3${node_id}.1/24"
    local other_nodes=""

    # Build peer_node_ids array
    for i in 1 2 3; do
        if [[ $i -ne $node_id ]]; then
            if [[ -n "$other_nodes" ]]; then
                other_nodes="$other_nodes, $i"
            else
                other_nodes="$i"
            fi
        fi
    done

    # Use absolute paths to avoid Rocket's relative path resolution issues
    local abs_run_dir="$SCRIPT_DIR/$RUN_DIR"
    cat > "$RUN_DIR/node${node_id}.toml" << EOF
log_level = "info"
address = "0.0.0.0"
port = ${rpc_port}

[tls]
# Use absolute paths since Rocket resolves relative paths from config file directory
key = "${abs_run_dir}/certs/gateway-rpc.key"
certs = "${abs_run_dir}/certs/gateway-rpc.cert"

[tls.mutual]
ca_certs = "${abs_run_dir}/certs/gateway-ca.cert"
mandatory = false

[core]
kms_url = "https://kms.tdxlab.dstack.org:12001"
rpc_domain = "gateway.tdxlab.dstack.org"
run_in_dstack = false
state_path = "${RUN_DIR}/gateway-state-node${node_id}.json"

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
peer_node_ids = [${other_nodes}]
wavekv_data_dir = "${RUN_DIR}/wavekv_node${node_id}"

[core.certbot]
enabled = false

[core.wg]
private_key = "SEcoI37oGWynhukxXo5Mi8/8zZBU6abg6T1TOJRMj1Y="
public_key = "xc+7qkdeNFfl4g4xirGGGXHMc0cABuE5IHaLeCASVWM="
listen_port = ${wg_port}
ip = "${wg_ip}"
reserved_net = ["10.0.3${node_id}.1/31"]
client_ip_range = "10.0.3${node_id}.1/24"
config_path = "${RUN_DIR}/wg_node${node_id}.conf"
interface = "wavekv-test${node_id}"
endpoint = "127.0.0.1:${wg_port}"

[core.proxy]
cert_chain = "${RUN_DIR}/certbot/live/cert.pem"
cert_key = "${RUN_DIR}/certbot/live/key.pem"
base_domain = "tdxlab.dstack.org"
listen_addr = "0.0.0.0"
listen_port = ${proxy_port}
tappd_port = 8090
external_port = ${proxy_port}
inbound_pp_enabled = false
EOF
    log_info "Generated node${node_id}.toml (rpc=${rpc_port}, debug=${debug_port})"
}

start_node() {
    local node_id=$1
    local config="$RUN_DIR/node${node_id}.toml"
    local log_file="${LOG_DIR}/${CURRENT_TEST}_node${node_id}.log"

    log_info "Starting node ${node_id}..."
    mkdir -p "$RUN_DIR/wavekv_node${node_id}"
    mkdir -p "$LOG_DIR"
    ( sudo RUST_LOG=info "$GATEWAY_BIN" -c "$config" > "$log_file" 2>&1 & )
    sleep 2

    if pgrep -f "dstack-gateway.*${config}" > /dev/null; then
        log_info "Node ${node_id} started successfully"
        return 0
    else
        log_error "Node ${node_id} failed to start"
        cat "$log_file"
        return 1
    fi
}

stop_node() {
    local node_id=$1
    log_info "Stopping node ${node_id}..."
    sudo pkill -9 -f "dstack-gateway.*node${node_id}.toml" >/dev/null 2>&1 || true
    sleep 1
    # Reset terminal to fix any broken line endings
    stty sane 2>/dev/null || true
}

get_status() {
    local port=$1
    curl -sk --cacert "$CA_CERT" "https://localhost:${port}/wavekv/status" 2>/dev/null
}

get_n_keys() {
    local port=$1
    get_status "$port" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['persistent']['n_keys'])" 2>/dev/null || echo "0"
}

# Register CVM via debug port (no attestation required)
# Usage: debug_register_cvm <debug_port> <client_public_key> <app_id> <instance_id>
# Returns: JSON response
debug_register_cvm() {
    local debug_port=$1
    local public_key=$2
    local app_id=${3:-"testapp"}
    local instance_id=${4:-"testinstance"}
    curl -s \
        -X POST "http://localhost:${debug_port}/prpc/RegisterCvm" \
        -H "Content-Type: application/json" \
        -d "{\"client_public_key\": \"$public_key\", \"app_id\": \"$app_id\", \"instance_id\": \"$instance_id\"}" 2>/dev/null
}

# Check if debug service is available
# Usage: check_debug_service <debug_port>
check_debug_service() {
    local debug_port=$1
    local response=$(curl -s -X POST "http://localhost:${debug_port}/prpc/Info" \
        -H "Content-Type: application/json" -d '{}' 2>/dev/null)
    if echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'base_domain' in d" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Verify register response is successful (has wg config, no error)
# Usage: verify_register_response <response>
verify_register_response() {
    local response="$1"
    echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if 'error' in d:
        print(f'ERROR: {d[\"error\"]}', file=sys.stderr)
        sys.exit(1)
    assert 'wg' in d, 'missing wg config'
    assert 'client_ip' in d['wg'], 'missing client_ip'
    print(d['wg']['client_ip'])
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
}

# Get sync data from debug port (peer_addrs, nodes, instances)
# Usage: debug_get_sync_data <debug_port>
# Returns: JSON response with my_node_id, peer_addrs, nodes, instances
debug_get_sync_data() {
    local debug_port=$1
    curl -s -X POST "http://localhost:${debug_port}/prpc/GetSyncData" \
        -H "Content-Type: application/json" -d '{}' 2>/dev/null
}

# Check if node has synced peer address from another node
# Usage: has_peer_addr <debug_port> <peer_node_id>
# Returns: 0 if peer address exists, 1 otherwise
has_peer_addr() {
    local debug_port=$1
    local peer_node_id=$2
    local response=$(debug_get_sync_data "$debug_port")
    echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    peer_addrs = d.get('peer_addrs', [])
    for pa in peer_addrs:
        if pa.get('node_id') == $peer_node_id:
            sys.exit(0)
    sys.exit(1)
except:
    sys.exit(1)
" 2>/dev/null
}

# Check if node has synced node info from another node
# Usage: has_node_info <debug_port> <peer_node_id>
# Returns: 0 if node info exists, 1 otherwise
has_node_info() {
    local debug_port=$1
    local peer_node_id=$2
    local response=$(debug_get_sync_data "$debug_port")
    echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    nodes = d.get('nodes', [])
    for n in nodes:
        if n.get('node_id') == $peer_node_id:
            sys.exit(0)
    sys.exit(1)
except:
    sys.exit(1)
" 2>/dev/null
}

# Get number of peer addresses from sync data
# Usage: get_n_peer_addrs <debug_port>
get_n_peer_addrs() {
    local debug_port=$1
    local response=$(debug_get_sync_data "$debug_port")
    echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(len(d.get('peer_addrs', [])))
except:
    print(0)
" 2>/dev/null
}

# Get number of node infos from sync data
# Usage: get_n_nodes <debug_port>
get_n_nodes() {
    local debug_port=$1
    local response=$(debug_get_sync_data "$debug_port")
    echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(len(d.get('nodes', [])))
except:
    print(0)
" 2>/dev/null
}

# Get number of instances from sync data
# Usage: get_n_instances <debug_port>
get_n_instances() {
    local debug_port=$1
    local response=$(debug_get_sync_data "$debug_port")
    echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(len(d.get('instances', [])))
except:
    print(0)
" 2>/dev/null
}

# =============================================================================
# Test 1: Single node persistence
# =============================================================================
test_persistence() {
    log_info "========== Test 1: Persistence =========="
    cleanup

    generate_config 1

    # Start node and let it write some data
    start_node 1

    local port=13012
    local initial_keys=$(get_n_keys $port)
    log_info "Initial keys: $initial_keys"

    # The gateway auto-writes some data (peer_addr, etc)
    sleep 2
    local keys_after_write=$(get_n_keys $port)
    log_info "Keys after startup: $keys_after_write"

    # Stop and restart
    stop_node 1
    log_info "Restarting node 1..."
    start_node 1

    local keys_after_restart=$(get_n_keys $port)
    log_info "Keys after restart: $keys_after_restart"

    if [[ "$keys_after_restart" -ge "$keys_after_write" ]]; then
        log_info "Persistence test PASSED"
        return 0
    else
        log_error "Persistence test FAILED: expected >= $keys_after_write keys, got $keys_after_restart"
        return 1
    fi
}

# =============================================================================
# Test 2: Multi-node sync
# =============================================================================
test_multi_node_sync() {
    log_info "========== Test 2: Multi-node Sync =========="
    cleanup

    # Clean up old data
    rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2" "$RUN_DIR/wavekv_node3"

    generate_config 1
    generate_config 2

    start_node 1
    start_node 2

    local debug_port1=13015
    local debug_port2=13025

    # Wait for sync
    log_info "Waiting for nodes to sync..."
    sleep 10

    # Use debug RPC to check actual synced data
    local peer_addrs1=$(get_n_peer_addrs $debug_port1)
    local peer_addrs2=$(get_n_peer_addrs $debug_port2)
    local nodes1=$(get_n_nodes $debug_port1)
    local nodes2=$(get_n_nodes $debug_port2)

    log_info "Node 1: peer_addrs=$peer_addrs1, nodes=$nodes1"
    log_info "Node 2: peer_addrs=$peer_addrs2, nodes=$nodes2"

    # For true sync, each node should have:
    # - At least 2 peer addresses (both nodes' addresses)
    # - At least 2 node infos (both nodes' info)
    local sync_ok=true

    if ! has_peer_addr $debug_port1 2; then
        log_error "Node 1 missing peer_addr for node 2"
        sync_ok=false
    fi
    if ! has_peer_addr $debug_port2 1; then
        log_error "Node 2 missing peer_addr for node 1"
        sync_ok=false
    fi
    if ! has_node_info $debug_port1 2; then
        log_error "Node 1 missing node_info for node 2"
        sync_ok=false
    fi
    if ! has_node_info $debug_port2 1; then
        log_error "Node 2 missing node_info for node 1"
        sync_ok=false
    fi

    if [[ "$sync_ok" == "true" ]]; then
        log_info "Multi-node sync test PASSED"
        return 0
    else
        log_error "Multi-node sync test FAILED: nodes did not sync peer data"
        log_info "Sync data from node 1: $(debug_get_sync_data $debug_port1)"
        log_info "Sync data from node 2: $(debug_get_sync_data $debug_port2)"
        return 1
    fi
}

# =============================================================================
# Test 3: Node recovery after disconnect
# =============================================================================
test_node_recovery() {
    log_info "========== Test 3: Node Recovery =========="
    cleanup

    rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2"

    generate_config 1
    generate_config 2

    start_node 1
    start_node 2

    local debug_port1=13015
    local debug_port2=13025

    # Wait for initial sync
    sleep 5

    # Stop node 2
    log_info "Stopping node 2 to simulate disconnect..."
    stop_node 2

    # Wait and let node 1 continue
    sleep 3

    # Check node 1 has its own data
    local peer_addrs1_before=$(get_n_peer_addrs $debug_port1)
    log_info "Node 1 peer_addrs before node 2 restart: $peer_addrs1_before"

    # Restart node 2
    log_info "Restarting node 2..."
    start_node 2

    # Wait for sync
    sleep 10

    # After recovery, node 2 should have synced node 1's data
    local sync_ok=true

    if ! has_peer_addr $debug_port2 1; then
        log_error "Node 2 missing peer_addr for node 1 after recovery"
        sync_ok=false
    fi
    if ! has_node_info $debug_port2 1; then
        log_error "Node 2 missing node_info for node 1 after recovery"
        sync_ok=false
    fi

    if [[ "$sync_ok" == "true" ]]; then
        log_info "Node recovery test PASSED"
        return 0
    else
        log_error "Node recovery test FAILED: node 2 did not sync data from node 1"
        log_info "Sync data from node 2: $(debug_get_sync_data $debug_port2)"
        return 1
    fi
}

# =============================================================================
# Test 4: Status endpoint structure
# =============================================================================
test_status_endpoint() {
    log_info "========== Test 4: Status Endpoint =========="
    cleanup

    generate_config 1
    start_node 1

    local port=13012
    local status=$(get_status $port)

    # Verify all expected fields exist
    local checks_passed=0
    local total_checks=6

    echo "$status" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['enabled'] == True, 'enabled should be True'
assert 'persistent' in d, 'missing persistent'
assert 'ephemeral' in d, 'missing ephemeral'
assert d['persistent']['wal_enabled'] == True, 'persistent wal should be enabled'
assert d['ephemeral']['wal_enabled'] == False, 'ephemeral wal should be disabled'
assert 'peers' in d['persistent'], 'missing peers in persistent'
print('All status checks passed')
" && checks_passed=1

    if [[ $checks_passed -eq 1 ]]; then
        log_info "Status endpoint test PASSED"
        return 0
    else
        log_error "Status endpoint test FAILED"
        return 1
    fi
}

# =============================================================================
# Test 5: Cross-node data sync verification
# =============================================================================
test_cross_node_data_sync() {
    log_info "========== Test 5: Cross-node Data Sync =========="
    cleanup

    rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2"

    generate_config 1
    generate_config 2

    start_node 1
    start_node 2

    local debug_port1=13015
    local debug_port2=13025

    # Wait for initial connection
    sleep 5

    # Verify debug service is available
    if ! check_debug_service $debug_port1; then
        log_error "Debug service not available on node 1"
        return 1
    fi

    # Register a client on node 1 via debug port
    log_info "Registering client on node 1 via debug port..."
    local register_response=$(debug_register_cvm $debug_port1 "testkey12345678901234567890123456789012345=" "app1" "inst1")
    log_info "Register response: $register_response"

    # Verify registration succeeded
    local client_ip=$(verify_register_response "$register_response")
    if [[ -z "$client_ip" ]]; then
        log_error "Registration failed"
        return 1
    fi
    log_info "Registered client with IP: $client_ip"

    # Wait for sync
    log_info "Waiting for sync..."
    sleep 10

    # Check instance count on both nodes - this is the key verification
    local instances1=$(get_n_instances $debug_port1)
    local instances2=$(get_n_instances $debug_port2)

    log_info "Node 1 instances: $instances1, Node 2 instances: $instances2"

    # The registered instance must appear on node 2 (synced from node 1)
    if [[ "$instances1" -ge 1 ]] && [[ "$instances2" -ge 1 ]]; then
        log_info "Cross-node data sync test PASSED (instance synced to node 2)"
        return 0
    else
        log_error "Cross-node data sync test FAILED: instances1=$instances1, instances2=$instances2 (both should be >= 1)"
        log_info "Sync data from node 1: $(debug_get_sync_data $debug_port1)"
        log_info "Sync data from node 2: $(debug_get_sync_data $debug_port2)"
        return 1
    fi
}

# =============================================================================
# Test 6: prpc DebugRegisterCvm endpoint (on separate debug port)
# =============================================================================
test_prpc_register() {
    log_info "========== Test 6: prpc DebugRegisterCvm =========="
    cleanup

    generate_config 1
    start_node 1

    local debug_port=13015

    # Verify debug service is available first
    if ! check_debug_service $debug_port; then
        log_error "Debug service not available"
        return 1
    fi
    log_info "Debug service is available"

    # Register via debug port
    local register_response=$(debug_register_cvm $debug_port "prpctest12345678901234567890123456789012=" "deadbeef" "cafebabe")
    log_info "Register response: $register_response"

    # Verify registration succeeded
    local client_ip=$(verify_register_response "$register_response")
    if [[ -z "$client_ip" ]]; then
        log_error "prpc DebugRegisterCvm test FAILED"
        return 1
    fi

    log_info "DebugRegisterCvm success: client_ip=$client_ip"
    log_info "prpc DebugRegisterCvm test PASSED"
    return 0
}

# =============================================================================
# Test 7: prpc Info endpoint
# =============================================================================
test_prpc_info() {
    log_info "========== Test 7: prpc Info =========="
    cleanup

    generate_config 1
    start_node 1

    local port=13012

    # Call Info via prpc
    # Note: trim: "Tproxy." removes "Tproxy.Gateway." prefix, so endpoint is just /prpc/Info
    local info_response=$(curl -sk --cacert "$CA_CERT" \
        -X POST "https://localhost:${port}/prpc/Info" \
        -H "Content-Type: application/json" \
        -d '{}' 2>/dev/null)

    log_info "Info response: $info_response"

    # Verify response has expected fields and no error
    echo "$info_response" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'error' in d:
    print(f'ERROR: {d[\"error\"]}', file=sys.stderr)
    sys.exit(1)
assert 'base_domain' in d, 'missing base_domain'
assert 'external_port' in d, 'missing external_port'
print('prpc Info check passed')
" && {
        log_info "prpc Info test PASSED"
        return 0
    } || {
        log_error "prpc Info test FAILED"
        return 1
    }
}

# =============================================================================
# Test 8: Client registration and data persistence
# =============================================================================
test_client_registration_persistence() {
    log_info "========== Test 8: Client Registration Persistence =========="
    cleanup

    rm -rf "$RUN_DIR/wavekv_node1"

    generate_config 1
    start_node 1

    local debug_port=13015
    local rpc_port=13012

    # Verify debug service is available
    if ! check_debug_service $debug_port; then
        log_error "Debug service not available"
        return 1
    fi

    # Register a client via debug port
    log_info "Registering client..."
    local register_response=$(debug_register_cvm $debug_port "persisttest1234567890123456789012345678901=" "persist_app" "persist_inst")
    log_info "Register response: $register_response"

    # Verify registration succeeded
    local client_ip=$(verify_register_response "$register_response")
    if [[ -z "$client_ip" ]]; then
        log_error "Registration failed"
        return 1
    fi

    # Get initial key count
    local keys_before=$(get_n_keys $rpc_port)
    log_info "Keys before restart: $keys_before"

    # Restart node
    stop_node 1
    start_node 1

    # Check keys after restart
    local keys_after=$(get_n_keys $rpc_port)
    log_info "Keys after restart: $keys_after"

    if [[ "$keys_after" -ge "$keys_before" ]] && [[ "$keys_before" -gt 2 ]]; then
        log_info "Client registration persistence test PASSED"
        return 0
    else
        log_error "Client registration persistence test FAILED: keys_before=$keys_before, keys_after=$keys_after"
        return 1
    fi
}

# =============================================================================
# Test 9: Stress test - multiple writes
# =============================================================================
test_stress_writes() {
    log_info "========== Test 9: Stress Test =========="
    cleanup

    rm -rf "$RUN_DIR/wavekv_node1"

    generate_config 1
    start_node 1

    local debug_port=13015
    local rpc_port=13012
    local num_clients=10
    local success_count=0

    # Verify debug service is available
    if ! check_debug_service $debug_port; then
        log_error "Debug service not available"
        return 1
    fi

    log_info "Registering $num_clients clients via debug port..."
    for i in $(seq 1 $num_clients); do
        local key=$(printf "stresstest%02d12345678901234567890123456=" "$i")
        local app_id=$(printf "stressapp%02d" "$i")
        local inst_id=$(printf "stressinst%02d" "$i")
        local response=$(debug_register_cvm $debug_port "$key" "$app_id" "$inst_id")
        if verify_register_response "$response" >/dev/null 2>&1; then
            ((success_count++))
        fi
    done

    log_info "Successfully registered $success_count/$num_clients clients"

    sleep 2

    local keys_after=$(get_n_keys $rpc_port)
    log_info "Keys after stress test: $keys_after"

    # We expect successful registrations to create keys
    if [[ "$success_count" -eq "$num_clients" ]] && [[ "$keys_after" -gt 2 ]]; then
        log_info "Stress test PASSED"
        return 0
    else
        log_error "Stress test FAILED: success_count=$success_count, keys_after=$keys_after"
        return 1
    fi
}

# =============================================================================
# Test 10: Network partition simulation
# =============================================================================
test_network_partition() {
    log_info "========== Test 10: Network Partition Recovery =========="
    cleanup

    rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2"

    generate_config 1
    generate_config 2

    start_node 1
    start_node 2

    local debug_port1=13015
    local debug_port2=13025

    # Let them sync initially
    sleep 5

    # Verify debug service is available
    if ! check_debug_service $debug_port1; then
        log_error "Debug service not available on node 1"
        return 1
    fi

    # Stop node 2 (simulate partition)
    log_info "Simulating network partition - stopping node 2..."
    stop_node 2

    # Register clients on node 1 while node 2 is down
    log_info "Registering clients on node 1 during partition..."
    local success_count=0
    for i in $(seq 1 3); do
        local key=$(printf "partition%02d123456789012345678901234567=" "$i")
        local response=$(debug_register_cvm $debug_port1 "$key" "partition_app$i" "partition_inst$i")
        if verify_register_response "$response" >/dev/null 2>&1; then
            ((success_count++))
        fi
    done
    log_info "Registered $success_count/3 clients during partition"

    local instances1_during=$(get_n_instances $debug_port1)
    log_info "Node 1 instances during partition: $instances1_during"

    # Restore node 2
    log_info "Healing partition - restarting node 2..."
    start_node 2

    # Wait for sync
    sleep 15

    # Node 2 should have caught up with node 1's instances after recovery
    local instances1_after=$(get_n_instances $debug_port1)
    local instances2_after=$(get_n_instances $debug_port2)

    log_info "Node 1 instances after recovery: $instances1_after"
    log_info "Node 2 instances after recovery: $instances2_after"

    # Verify node 2 synced all instances from node 1
    if [[ "$success_count" -eq 3 ]] && [[ "$instances1_during" -ge 3 ]] && [[ "$instances2_after" -ge "$instances1_during" ]]; then
        log_info "Network partition recovery test PASSED"
        return 0
    else
        log_error "Network partition recovery test FAILED: success_count=$success_count, instances1_during=$instances1_during, instances2_after=$instances2_after"
        log_info "Sync data from node 2: $(debug_get_sync_data $debug_port2)"
        return 1
    fi
}

# =============================================================================
# Test 11: Three-node cluster
# =============================================================================
test_three_node_cluster() {
    log_info "========== Test 11: Three-node Cluster =========="
    cleanup

    rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2" "$RUN_DIR/wavekv_node3"

    generate_config 1
    generate_config 2
    generate_config 3

    start_node 1
    start_node 2
    start_node 3

    local debug_port1=13015
    local debug_port2=13025
    local debug_port3=13035

    # Wait for cluster to form
    sleep 10

    # Verify debug service is available
    if ! check_debug_service $debug_port1; then
        log_error "Debug service not available on node 1"
        return 1
    fi

    # Register client on node 1
    log_info "Registering client on node 1..."
    local response=$(debug_register_cvm $debug_port1 "threenode12345678901234567890123456789=" "threenode_app" "threenode_inst")
    local client_ip=$(verify_register_response "$response")
    if [[ -z "$client_ip" ]]; then
        log_error "Registration failed"
        return 1
    fi
    log_info "Registered client with IP: $client_ip"

    # Wait for sync across all nodes
    sleep 15

    # Check instances on all three nodes
    local instances1=$(get_n_instances $debug_port1)
    local instances2=$(get_n_instances $debug_port2)
    local instances3=$(get_n_instances $debug_port3)

    log_info "Node 1 instances: $instances1"
    log_info "Node 2 instances: $instances2"
    log_info "Node 3 instances: $instances3"

    # All nodes should have synced the registered instance
    if [[ "$instances1" -ge 1 ]] && [[ "$instances2" -ge 1 ]] && [[ "$instances3" -ge 1 ]]; then
        log_info "Three-node cluster test PASSED"
        return 0
    else
        log_error "Three-node cluster test FAILED: instances1=$instances1, instances2=$instances2, instances3=$instances3 (all should be >= 1)"
        log_info "Sync data from node 1: $(debug_get_sync_data $debug_port1)"
        log_info "Sync data from node 2: $(debug_get_sync_data $debug_port2)"
        log_info "Sync data from node 3: $(debug_get_sync_data $debug_port3)"
        return 1
    fi
}

# =============================================================================
# Test 12: WAL file integrity
# =============================================================================
test_wal_integrity() {
    log_info "========== Test 12: WAL File Integrity =========="
    cleanup

    rm -rf "$RUN_DIR/wavekv_node1"

    generate_config 1
    start_node 1

    local debug_port=13015
    local success_count=0

    # Verify debug service is available
    if ! check_debug_service $debug_port; then
        log_error "Debug service not available"
        return 1
    fi

    # Register some clients via debug port
    for i in $(seq 1 5); do
        local key=$(printf "waltest%02d1234567890123456789012345678901=" "$i")
        local response=$(debug_register_cvm $debug_port "$key" "wal_app$i" "wal_inst$i")
        if verify_register_response "$response" >/dev/null 2>&1; then
            ((success_count++))
        fi
    done
    log_info "Registered $success_count/5 clients"

    if [[ "$success_count" -ne 5 ]]; then
        log_error "Failed to register all clients"
        return 1
    fi

    sleep 2
    stop_node 1

    # Check WAL file exists and has content
    local wal_file="$RUN_DIR/wavekv_node1/node_1.wal"
    if [[ -f "$wal_file" ]]; then
        local wal_size=$(stat -c%s "$wal_file" 2>/dev/null || stat -f%z "$wal_file" 2>/dev/null)
        log_info "WAL file size: $wal_size bytes"

        if [[ "$wal_size" -gt 100 ]]; then
            log_info "WAL file integrity test PASSED"
            return 0
        else
            log_error "WAL file integrity test FAILED: WAL file too small ($wal_size bytes)"
            return 1
        fi
    else
        log_error "WAL file not found: $wal_file"
        return 1
    fi
}

# =============================================================================
# Clean command - remove all generated files
# =============================================================================
clean() {
    log_info "Cleaning up generated files..."

    # Kill any running gateway processes
    sudo pkill -9 -f "dstack-gateway.*node[123].toml" >/dev/null 2>&1 || true

    # Remove WireGuard interfaces
    sudo ip link delete wavekv-test1 2>/dev/null || true
    sudo ip link delete wavekv-test2 2>/dev/null || true
    sudo ip link delete wavekv-test3 2>/dev/null || true

    # Remove run directory (contains all generated files including certs)
    rm -rf "$RUN_DIR"

    log_info "Cleanup complete"
}

# =============================================================================
# Ensure proxy certificates exist (RPC certs are auto-fetched from KMS)
# =============================================================================
ensure_certs() {
    # Create directories
    mkdir -p "$CERTS_DIR"
    mkdir -p "$RUN_DIR/certbot/live"

    # Generate proxy certificates (for TLS termination)
    local proxy_cert_dir="$RUN_DIR/certbot/live"
    if [[ ! -f "$proxy_cert_dir/cert.pem" ]] || [[ ! -f "$proxy_cert_dir/key.pem" ]]; then
        log_info "Creating proxy certificates..."
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$proxy_cert_dir/key.pem" \
            -out "$proxy_cert_dir/cert.pem" \
            -days 365 \
            -subj "/CN=localhost" \
            2>/dev/null
    fi
}

# =============================================================================
# Main
# =============================================================================
main() {
    # Handle clean command
    if [[ "${1:-}" == "clean" ]]; then
        clean
        exit 0
    fi

    log_info "Starting WaveKV integration tests..."

    if [[ ! -f "$GATEWAY_BIN" ]]; then
        log_error "Gateway binary not found: $GATEWAY_BIN"
        log_info "Please run: cargo build --release"
        exit 1
    fi

    # Ensure all certificates exist (RPC + proxy)
    ensure_certs

    local failed=0
    local passed=0

    run_test() {
        local test_name=$1
        CURRENT_TEST="$test_name"
        if $test_name; then
            ((passed++))
        else
            ((failed++))
        fi
        cleanup
    }

    # Run selected test or all tests
    local test_filter="${1:-all}"

    if [[ "$test_filter" == "all" ]] || [[ "$test_filter" == "quick" ]]; then
        run_test test_persistence
        run_test test_status_endpoint
        run_test test_prpc_register
        run_test test_prpc_info
        run_test test_wal_integrity
    fi

    if [[ "$test_filter" == "all" ]] || [[ "$test_filter" == "sync" ]]; then
        run_test test_multi_node_sync
        run_test test_node_recovery
        run_test test_cross_node_data_sync
    fi

    if [[ "$test_filter" == "all" ]] || [[ "$test_filter" == "advanced" ]]; then
        run_test test_client_registration_persistence
        run_test test_stress_writes
        run_test test_network_partition
        run_test test_three_node_cluster
    fi

    echo ""
    log_info "=========================================="
    log_info "Tests passed: $passed"
    if [[ $failed -gt 0 ]]; then
        log_error "Tests failed: $failed"
    fi
    log_info "=========================================="

    return $failed
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
