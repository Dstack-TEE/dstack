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
	# Kill only dstack-gateway processes started by this test (matching our specific config path)
	# Use absolute path to avoid killing system dstack-gateway processes
	pkill -9 -f "dstack-gateway -c ${SCRIPT_DIR}/${RUN_DIR}/node" >/dev/null 2>&1 || true
	pkill -9 -f "dstack-gateway.*${SCRIPT_DIR}/${RUN_DIR}/node" >/dev/null 2>&1 || true
	sleep 1
	# Only delete WireGuard interfaces with sudo (these are our test interfaces)
	sudo ip link delete wavekv-test1 2>/dev/null || true
	sudo ip link delete wavekv-test2 2>/dev/null || true
	sudo ip link delete wavekv-test3 2>/dev/null || true
	# Clean up all wavekv data directories to prevent peer list contamination
	rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2" "$RUN_DIR/wavekv_node3" 2>/dev/null || true
	rm -f "$RUN_DIR/gateway-state-node"*.json 2>/dev/null || true
	sleep 1
	stty sane 2>/dev/null || true
}

trap cleanup EXIT

# Generate node configs
# Usage: generate_config <node_id> [bootnode_url]
generate_config() {
	local node_id=$1
	local bootnode_url=${2:-""}
	local rpc_port=$((13000 + node_id * 10 + 2))
	local wg_port=$((13000 + node_id * 10 + 3))
	local proxy_port=$((13000 + node_id * 10 + 4))
	local debug_port=$((13000 + node_id * 10 + 5))
	local admin_port=$((13000 + node_id * 10 + 6))
	local wg_ip="10.0.3${node_id}.1/24"

	# Use absolute paths to avoid Rocket's relative path resolution issues
	local abs_run_dir="$SCRIPT_DIR/$RUN_DIR"
	cat >"$RUN_DIR/node${node_id}.toml" <<EOF
log_level = "info"
address = "0.0.0.0:${rpc_port}"

[tls]
# Use absolute paths since Rocket resolves relative paths from config file directory
key = "${abs_run_dir}/certs/gateway-rpc.key"
certs = "${abs_run_dir}/certs/gateway-rpc.cert"

[tls.mutual]
ca_certs = "${abs_run_dir}/certs/gateway-ca.cert"
mandatory = false

[core]
# Empty kms_url to skip auto-cert generation (we use pre-generated certs)
kms_url = ""
rpc_domain = "gateway.tdxlab.dstack.org"
state_path = "${RUN_DIR}/gateway-state-node${node_id}.json"

[core.debug]
insecure_enable_debug_rpc = true
insecure_skip_attestation = true
address = "127.0.0.1:${debug_port}"

[core.admin]
enabled = true
address = "127.0.0.1:${admin_port}"

[core.sync]
enabled = true
interval = "5s"
timeout = "10s"
my_url = "https://localhost:${rpc_port}"
bootnode = "${bootnode_url}"
node_id = ${node_id}
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
	log_info "Generated node${node_id}.toml (rpc=${rpc_port}, debug=${debug_port}, admin=${admin_port}, bootnode=${bootnode_url:-none})"
}

wait_for_port_free() {
	local port=$1
	local max_wait=10
	local waited=0
	while [[ $waited -lt $max_wait ]]; do
		if ! netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
			return 0
		fi
		sleep 1
		((waited++))
	done
	return 1
}

ensure_wg_interface() {
	local node_id=$1
	local iface="wavekv-test${node_id}"

	# Check if interface exists, create if not
	if ! ip link show "$iface" >/dev/null 2>&1; then
		log_info "Creating WireGuard interface ${iface}..."
		sudo ip link add "$iface" type wireguard || {
			log_error "Failed to create WireGuard interface ${iface}"
			return 1
		}
	fi
	return 0
}

start_node() {
	local node_id=$1
	local config="${SCRIPT_DIR}/${RUN_DIR}/node${node_id}.toml"
	local log_file="${LOG_DIR}/${CURRENT_TEST}_node${node_id}.log"

	# Calculate ports for this node
	local admin_port=$((13000 + node_id * 10 + 6))
	local rpc_port=$((13000 + node_id * 10 + 2))

	log_info "Starting node ${node_id}..."

	# Kill any existing test process for this node first (use absolute path to be precise)
	pkill -9 -f "dstack-gateway -c ${config}" >/dev/null 2>&1 || true
	pkill -9 -f "dstack-gateway.*${config}" >/dev/null 2>&1 || true
	sleep 1

	# Wait for ports to be free
	if ! wait_for_port_free $admin_port; then
		log_error "Port $admin_port still in use after waiting"
		netstat -tlnp 2>/dev/null | grep ":${admin_port} " || true
		return 1
	fi
	if ! wait_for_port_free $rpc_port; then
		log_error "Port $rpc_port still in use after waiting"
		netstat -tlnp 2>/dev/null | grep ":${rpc_port} " || true
		return 1
	fi

	# Ensure WireGuard interface exists before starting
	if ! ensure_wg_interface "$node_id"; then
		return 1
	fi

	mkdir -p "$RUN_DIR/wavekv_node${node_id}"
	mkdir -p "$LOG_DIR"
	(RUST_LOG=info "$GATEWAY_BIN" -c "$config" >"$log_file" 2>&1 &)
	sleep 2

	if pgrep -f "dstack-gateway.*${config}" >/dev/null; then
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
	local config="${SCRIPT_DIR}/${RUN_DIR}/node${node_id}.toml"
	local admin_port=$((13000 + node_id * 10 + 6))

	log_info "Stopping node ${node_id}..."
	# Kill only the specific test process using absolute config path
	pkill -9 -f "dstack-gateway -c ${config}" >/dev/null 2>&1 || true
	pkill -9 -f "dstack-gateway.*${config}" >/dev/null 2>&1 || true
	sleep 1

	# Verify the port is free, otherwise force kill by PID
	if ! wait_for_port_free $admin_port; then
		log_warn "Node ${node_id} port still in use, forcing cleanup..."
		# Find and kill the process holding the port
		local pid=$(netstat -tlnp 2>/dev/null | grep ":${admin_port} " | awk '{print $7}' | cut -d'/' -f1)
		if [[ -n "$pid" ]]; then
			kill -9 "$pid" 2>/dev/null || true
			sleep 1
		fi
	fi

	# Reset terminal to fix any broken line endings
	stty sane 2>/dev/null || true
}

# Get WaveKV status via Admin.WaveKvStatus RPC
# Usage: get_status <admin_port>
get_status() {
	local admin_port=$1
	curl -s -X POST "http://localhost:${admin_port}/prpc/Admin.WaveKvStatus" \
		-H "Content-Type: application/json" \
		-d '{}' 2>/dev/null
}

get_n_keys() {
	local admin_port=$1
	get_status "$admin_port" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['persistent']['n_keys'])" 2>/dev/null || echo "0"
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
	local response=$(curl -s -X POST "http://localhost:${debug_port}/prpc/Debug.Info" \
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
	curl -s -X POST "http://localhost:${debug_port}/prpc/Debug.GetSyncData" \
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
except Exception as e:
    sys.exit(1)
"
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
except Exception as e:
    sys.exit(1)
"
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

# Get number of instances from KvStore sync data
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

# Get Proxy State from debug port (in-memory state)
# Usage: debug_get_proxy_state <debug_port>
# Returns: JSON response with instances and allocated_addresses
debug_get_proxy_state() {
	local debug_port=$1
	curl -s -X POST "http://localhost:${debug_port}/prpc/GetProxyState" \
		-H "Content-Type: application/json" -d '{}' 2>/dev/null
}

# Get number of instances from ProxyState (in-memory)
# Usage: get_n_proxy_state_instances <debug_port>
get_n_proxy_state_instances() {
	local debug_port=$1
	local response=$(debug_get_proxy_state "$debug_port")
	echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(len(d.get('instances', [])))
except:
    print(0)
" 2>/dev/null
}

# Check KvStore and ProxyState instance consistency
# Usage: check_instance_consistency <debug_port>
# Returns: 0 if consistent, 1 otherwise
check_instance_consistency() {
	local debug_port=$1
	local kvstore_instances=$(get_n_instances "$debug_port")
	local proxystate_instances=$(get_n_proxy_state_instances "$debug_port")

	if [[ "$kvstore_instances" -eq "$proxystate_instances" ]]; then
		return 0
	else
		log_error "Instance count mismatch: KvStore=$kvstore_instances, ProxyState=$proxystate_instances"
		return 1
	fi
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

	local admin_port=13016
	local initial_keys=$(get_n_keys $admin_port)
	log_info "Initial keys: $initial_keys"

	# The gateway auto-writes some data (peer_addr, etc)
	sleep 2
	local keys_after_write=$(get_n_keys $admin_port)
	log_info "Keys after startup: $keys_after_write"

	# Stop and restart
	stop_node 1
	log_info "Restarting node 1..."
	start_node 1

	local keys_after_restart=$(get_n_keys $admin_port)
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

	# Clean up all state files to ensure fresh start
	rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2" "$RUN_DIR/wavekv_node3"
	rm -f "$RUN_DIR/gateway-state-node1.json" "$RUN_DIR/gateway-state-node2.json" "$RUN_DIR/gateway-state-node3.json"

	generate_config 1
	generate_config 2

	start_node 1
	start_node 2

	# Register peers so nodes can discover each other
	setup_peers 1 2

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

	# Clean up all state files to ensure fresh start
	rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2"
	rm -f "$RUN_DIR/gateway-state-node1.json" "$RUN_DIR/gateway-state-node2.json"

	generate_config 1
	generate_config 2

	start_node 1
	start_node 2

	# Register peers so nodes can discover each other
	setup_peers 1 2

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

	# Re-register peers after restart
	setup_peers 1 2

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
# Test 4: Status endpoint structure (Admin.WaveKvStatus RPC)
# =============================================================================
test_status_endpoint() {
	log_info "========== Test 4: Status Endpoint =========="
	cleanup

	generate_config 1
	start_node 1

	local admin_port=13016
	local status=$(get_status $admin_port)

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
		log_info "Status response: $status"
		return 1
	fi
}

# =============================================================================
# Test 5: Cross-node data sync verification (KvStore + ProxyState)
# =============================================================================
test_cross_node_data_sync() {
	log_info "========== Test 5: Cross-node Data Sync =========="
	cleanup

	generate_config 1
	generate_config 2

	start_node 1
	start_node 2

	# Register peers so nodes can discover each other
	setup_peers 1 2

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

	# Wait for sync (need at least 3 sync intervals of 5s for data to propagate)
	log_info "Waiting for sync..."
	sleep 20

	# Check KvStore instance count on both nodes
	local kv_instances1=$(get_n_instances $debug_port1)
	local kv_instances2=$(get_n_instances $debug_port2)

	# Check ProxyState instance count on both nodes
	local ps_instances1=$(get_n_proxy_state_instances $debug_port1)
	local ps_instances2=$(get_n_proxy_state_instances $debug_port2)

	log_info "Node 1: KvStore=$kv_instances1, ProxyState=$ps_instances1"
	log_info "Node 2: KvStore=$kv_instances2, ProxyState=$ps_instances2"

	local test_passed=true

	# Verify KvStore sync
	if [[ "$kv_instances1" -lt 1 ]] || [[ "$kv_instances2" -lt 1 ]]; then
		log_error "KvStore sync failed: kv_instances1=$kv_instances1, kv_instances2=$kv_instances2"
		test_passed=false
	fi

	# Verify ProxyState sync (node 2 should have loaded instance from KvStore)
	if [[ "$ps_instances1" -lt 1 ]] || [[ "$ps_instances2" -lt 1 ]]; then
		log_error "ProxyState sync failed: ps_instances1=$ps_instances1, ps_instances2=$ps_instances2"
		test_passed=false
	fi

	# Verify consistency on each node
	if [[ "$kv_instances1" -ne "$ps_instances1" ]]; then
		log_error "Node 1 inconsistent: KvStore=$kv_instances1, ProxyState=$ps_instances1"
		test_passed=false
	fi
	if [[ "$kv_instances2" -ne "$ps_instances2" ]]; then
		log_error "Node 2 inconsistent: KvStore=$kv_instances2, ProxyState=$ps_instances2"
		test_passed=false
	fi

	if [[ "$test_passed" == "true" ]]; then
		log_info "Cross-node data sync test PASSED (KvStore and ProxyState consistent)"
		return 0
	else
		log_info "KvStore from node 1: $(debug_get_sync_data $debug_port1)"
		log_info "KvStore from node 2: $(debug_get_sync_data $debug_port2)"
		log_info "ProxyState from node 1: $(debug_get_proxy_state $debug_port1)"
		log_info "ProxyState from node 2: $(debug_get_proxy_state $debug_port2)"
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
	local admin_port=13016

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
	local keys_before=$(get_n_keys $admin_port)
	log_info "Keys before restart: $keys_before"

	# Restart node
	stop_node 1
	start_node 1

	# Check keys after restart
	local keys_after=$(get_n_keys $admin_port)
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
	local admin_port=13016
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

	local keys_after=$(get_n_keys $admin_port)
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
# Test 10: Network partition simulation (KvStore + ProxyState consistency)
# =============================================================================
test_network_partition() {
	log_info "========== Test 10: Network Partition Recovery =========="
	cleanup

	# Clean up all state files to ensure fresh start
	rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2"
	rm -f "$RUN_DIR/gateway-state-node1.json" "$RUN_DIR/gateway-state-node2.json"

	generate_config 1
	generate_config 2

	start_node 1
	start_node 2

	# Register peers so nodes can discover each other
	setup_peers 1 2

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

	local kv1_during=$(get_n_instances $debug_port1)
	local ps1_during=$(get_n_proxy_state_instances $debug_port1)
	log_info "Node 1 during partition: KvStore=$kv1_during, ProxyState=$ps1_during"

	# Restore node 2
	log_info "Healing partition - restarting node 2..."
	start_node 2

	# Re-register peers after restart
	setup_peers 1 2

	# Wait for sync
	sleep 15

	# Check KvStore and ProxyState on both nodes after recovery
	local kv1_after=$(get_n_instances $debug_port1)
	local kv2_after=$(get_n_instances $debug_port2)
	local ps1_after=$(get_n_proxy_state_instances $debug_port1)
	local ps2_after=$(get_n_proxy_state_instances $debug_port2)

	log_info "Node 1 after recovery: KvStore=$kv1_after, ProxyState=$ps1_after"
	log_info "Node 2 after recovery: KvStore=$kv2_after, ProxyState=$ps2_after"

	local test_passed=true

	# Verify basic sync
	if [[ "$success_count" -ne 3 ]] || [[ "$kv1_during" -lt 3 ]]; then
		log_error "Registration or KvStore write failed during partition"
		test_passed=false
	fi

	# Verify node 2 synced KvStore
	if [[ "$kv2_after" -lt "$kv1_during" ]]; then
		log_error "Node 2 KvStore sync failed: kv2_after=$kv2_after, expected >= $kv1_during"
		test_passed=false
	fi

	# Verify node 2 ProxyState sync
	if [[ "$ps2_after" -lt "$kv1_during" ]]; then
		log_error "Node 2 ProxyState sync failed: ps2_after=$ps2_after, expected >= $kv1_during"
		test_passed=false
	fi

	# Verify consistency on each node
	if [[ "$kv1_after" -ne "$ps1_after" ]]; then
		log_error "Node 1 inconsistent: KvStore=$kv1_after, ProxyState=$ps1_after"
		test_passed=false
	fi
	if [[ "$kv2_after" -ne "$ps2_after" ]]; then
		log_error "Node 2 inconsistent: KvStore=$kv2_after, ProxyState=$ps2_after"
		test_passed=false
	fi

	if [[ "$test_passed" == "true" ]]; then
		log_info "Network partition recovery test PASSED (KvStore and ProxyState consistent)"
		return 0
	else
		log_info "KvStore from node 2: $(debug_get_sync_data $debug_port2)"
		log_info "ProxyState from node 2: $(debug_get_proxy_state $debug_port2)"
		return 1
	fi
}

# =============================================================================
# Test 11: Three-node cluster (KvStore + ProxyState consistency)
# =============================================================================
test_three_node_cluster() {
	log_info "========== Test 11: Three-node Cluster =========="
	cleanup

	# Clean up all state files to ensure fresh start
	rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2" "$RUN_DIR/wavekv_node3"
	rm -f "$RUN_DIR/gateway-state-node1.json" "$RUN_DIR/gateway-state-node2.json" "$RUN_DIR/gateway-state-node3.json"

	generate_config 1
	generate_config 2
	generate_config 3

	start_node 1
	start_node 2
	start_node 3

	# Register peers so all nodes can discover each other
	setup_peers 1 2 3

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

	# Wait for sync across all nodes (need at least 2 sync intervals of 5s)
	sleep 20

	# Check KvStore instances on all three nodes
	local kv1=$(get_n_instances $debug_port1)
	local kv2=$(get_n_instances $debug_port2)
	local kv3=$(get_n_instances $debug_port3)

	# Check ProxyState instances on all three nodes
	local ps1=$(get_n_proxy_state_instances $debug_port1)
	local ps2=$(get_n_proxy_state_instances $debug_port2)
	local ps3=$(get_n_proxy_state_instances $debug_port3)

	log_info "Node 1: KvStore=$kv1, ProxyState=$ps1"
	log_info "Node 2: KvStore=$kv2, ProxyState=$ps2"
	log_info "Node 3: KvStore=$kv3, ProxyState=$ps3"

	local test_passed=true

	# Verify KvStore sync on all nodes
	if [[ "$kv1" -lt 1 ]] || [[ "$kv2" -lt 1 ]] || [[ "$kv3" -lt 1 ]]; then
		log_error "KvStore sync failed: kv1=$kv1, kv2=$kv2, kv3=$kv3"
		test_passed=false
	fi

	# Verify ProxyState sync on all nodes
	if [[ "$ps1" -lt 1 ]] || [[ "$ps2" -lt 1 ]] || [[ "$ps3" -lt 1 ]]; then
		log_error "ProxyState sync failed: ps1=$ps1, ps2=$ps2, ps3=$ps3"
		test_passed=false
	fi

	# Verify consistency on each node
	if [[ "$kv1" -ne "$ps1" ]] || [[ "$kv2" -ne "$ps2" ]] || [[ "$kv3" -ne "$ps3" ]]; then
		log_error "Inconsistency detected between KvStore and ProxyState"
		test_passed=false
	fi

	if [[ "$test_passed" == "true" ]]; then
		log_info "Three-node cluster test PASSED (KvStore and ProxyState consistent)"
		return 0
	else
		log_info "KvStore from node 1: $(debug_get_sync_data $debug_port1)"
		log_info "KvStore from node 2: $(debug_get_sync_data $debug_port2)"
		log_info "KvStore from node 3: $(debug_get_sync_data $debug_port3)"
		log_info "ProxyState from node 1: $(debug_get_proxy_state $debug_port1)"
		log_info "ProxyState from node 2: $(debug_get_proxy_state $debug_port2)"
		log_info "ProxyState from node 3: $(debug_get_proxy_state $debug_port3)"
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
# Test 13: Three-node cluster with bootnode (no dynamic peer setup)
# =============================================================================
test_three_node_bootnode() {
	log_info "========== Test 13: Three-node Cluster with Bootnode =========="
	cleanup

	# Clean up all state files to ensure fresh start
	rm -rf "$RUN_DIR/wavekv_node1" "$RUN_DIR/wavekv_node2" "$RUN_DIR/wavekv_node3"
	rm -f "$RUN_DIR/gateway-state-node1.json" "$RUN_DIR/gateway-state-node2.json" "$RUN_DIR/gateway-state-node3.json"

	# Node 1 is the bootnode (no bootnode config)
	# Node 2 and 3 use node 1 as bootnode
	local bootnode_url="https://localhost:13012"

	generate_config 1 ""
	generate_config 2 "$bootnode_url"
	generate_config 3 "$bootnode_url"

	# Start node 1 first (bootnode)
	start_node 1
	sleep 2

	# Start node 2 and 3, they will discover each other via bootnode
	start_node 2
	start_node 3

	local debug_port1=13015
	local debug_port2=13025
	local debug_port3=13035

	# Wait for cluster to form via bootnode discovery
	log_info "Waiting for nodes to discover each other via bootnode..."
	sleep 15

	# Verify debug service is available on all nodes
	for port in $debug_port1 $debug_port2 $debug_port3; do
		if ! check_debug_service $port; then
			log_error "Debug service not available on port $port"
			return 1
		fi
	done

	# Check peer discovery - each node should know about the others
	local peer_addrs1=$(get_n_peer_addrs $debug_port1)
	local peer_addrs2=$(get_n_peer_addrs $debug_port2)
	local peer_addrs3=$(get_n_peer_addrs $debug_port3)

	log_info "Peer addresses: node1=$peer_addrs1, node2=$peer_addrs2, node3=$peer_addrs3"

	# Register client on node 2 (not the bootnode)
	log_info "Registering client on node 2..."
	local response=$(debug_register_cvm $debug_port2 "bootnode12345678901234567890123456789=" "bootnode_app" "bootnode_inst")
	local client_ip=$(verify_register_response "$response")
	if [[ -z "$client_ip" ]]; then
		log_error "Registration failed"
		return 1
	fi
	log_info "Registered client with IP: $client_ip"

	# Wait for sync across all nodes
	sleep 20

	# Check KvStore instances on all three nodes
	local kv1=$(get_n_instances $debug_port1)
	local kv2=$(get_n_instances $debug_port2)
	local kv3=$(get_n_instances $debug_port3)

	# Check ProxyState instances on all three nodes
	local ps1=$(get_n_proxy_state_instances $debug_port1)
	local ps2=$(get_n_proxy_state_instances $debug_port2)
	local ps3=$(get_n_proxy_state_instances $debug_port3)

	log_info "Node 1 (bootnode): KvStore=$kv1, ProxyState=$ps1"
	log_info "Node 2: KvStore=$kv2, ProxyState=$ps2"
	log_info "Node 3: KvStore=$kv3, ProxyState=$ps3"

	local test_passed=true

	# Verify peer discovery worked (each node should have at least 2 peer addresses)
	if [[ "$peer_addrs1" -lt 2 ]] || [[ "$peer_addrs2" -lt 2 ]] || [[ "$peer_addrs3" -lt 2 ]]; then
		log_error "Peer discovery via bootnode failed: peer_addrs1=$peer_addrs1, peer_addrs2=$peer_addrs2, peer_addrs3=$peer_addrs3"
		test_passed=false
	fi

	# Verify KvStore sync on all nodes
	if [[ "$kv1" -lt 1 ]] || [[ "$kv2" -lt 1 ]] || [[ "$kv3" -lt 1 ]]; then
		log_error "KvStore sync failed: kv1=$kv1, kv2=$kv2, kv3=$kv3"
		test_passed=false
	fi

	# Verify ProxyState sync on all nodes
	if [[ "$ps1" -lt 1 ]] || [[ "$ps2" -lt 1 ]] || [[ "$ps3" -lt 1 ]]; then
		log_error "ProxyState sync failed: ps1=$ps1, ps2=$ps2, ps3=$ps3"
		test_passed=false
	fi

	# Verify consistency on each node
	if [[ "$kv1" -ne "$ps1" ]] || [[ "$kv2" -ne "$ps2" ]] || [[ "$kv3" -ne "$ps3" ]]; then
		log_error "Inconsistency detected between KvStore and ProxyState"
		test_passed=false
	fi

	if [[ "$test_passed" == "true" ]]; then
		log_info "Three-node bootnode cluster test PASSED"
		return 0
	else
		log_info "Sync data from node 1: $(debug_get_sync_data $debug_port1)"
		log_info "Sync data from node 2: $(debug_get_sync_data $debug_port2)"
		log_info "Sync data from node 3: $(debug_get_sync_data $debug_port3)"
		return 1
	fi
}

# =============================================================================
# Admin RPC helper functions
# =============================================================================

# Call Admin.SetNodeUrl RPC
# Usage: admin_set_node_url <admin_port> <node_id> <url>
admin_set_node_url() {
	local admin_port=$1
	local node_id=$2
	local url=$3
	curl -s -X POST "http://localhost:${admin_port}/prpc/Admin.SetNodeUrl" \
		-H "Content-Type: application/json" \
		-d "{\"id\": $node_id, \"url\": \"$url\"}" 2>/dev/null
}

# Register peers between nodes via Admin RPC
# This is needed since we removed peer_node_ids/peer_urls from config
# Usage: setup_peers <node_ids...>
# Example: setup_peers 1 2 3  # Sets up peers between nodes 1, 2, and 3
setup_peers() {
	local node_ids=("$@")

	for src_node in "${node_ids[@]}"; do
		local src_admin_port=$((13000 + src_node * 10 + 6))

		for dst_node in "${node_ids[@]}"; do
			if [[ "$src_node" != "$dst_node" ]]; then
				local dst_rpc_port=$((13000 + dst_node * 10 + 2))
				local dst_url="https://localhost:${dst_rpc_port}"
				admin_set_node_url "$src_admin_port" "$dst_node" "$dst_url"
			fi
		done
	done

	# Wait for peers to be registered
	sleep 1
}

# Call Admin.SetNodeStatus RPC
# Usage: admin_set_node_status <admin_port> <node_id> <status>
# status: "up" or "down"
admin_set_node_status() {
	local admin_port=$1
	local node_id=$2
	local status=$3
	curl -s -X POST "http://localhost:${admin_port}/prpc/Admin.SetNodeStatus" \
		-H "Content-Type: application/json" \
		-d "{\"id\": $node_id, \"status\": \"$status\"}" 2>/dev/null
}

# Call Admin.Status RPC to get all nodes
# Usage: admin_get_status <admin_port>
admin_get_status() {
	local admin_port=$1
	curl -s -X POST "http://localhost:${admin_port}/prpc/Admin.Status" \
		-H "Content-Type: application/json" \
		-d '{}' 2>/dev/null
}

# Get peer URL from sync data
# Usage: get_peer_url <debug_port> <node_id>
get_peer_url_from_sync() {
	local debug_port=$1
	local node_id=$2
	local response=$(debug_get_sync_data "$debug_port")
	echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for pa in d.get('peer_addrs', []):
        if pa.get('node_id') == $node_id:
            print(pa.get('url', ''))
            sys.exit(0)
    print('')
except:
    print('')
" 2>/dev/null
}

# =============================================================================
# Test 14: Admin.SetNodeUrl RPC
# =============================================================================
test_admin_set_node_url() {
	log_info "========== Test 14: Admin.SetNodeUrl RPC =========="
	cleanup

	rm -rf "$RUN_DIR/wavekv_node1"

	generate_config 1
	start_node 1

	local admin_port=13016
	local debug_port=13015

	# Verify debug service is available
	if ! check_debug_service $debug_port; then
		log_error "Debug service not available"
		return 1
	fi

	# Set URL for a new node (node 2) via Admin RPC
	local new_url="https://new-node2.example.com:8011"
	log_info "Setting node 2 URL via Admin.SetNodeUrl..."
	local response=$(admin_set_node_url $admin_port 2 "$new_url")
	log_info "SetNodeUrl response: $response"

	# Check if the response contains an error
	if echo "$response" | grep -q '"error"'; then
		log_error "SetNodeUrl returned error: $response"
		return 1
	fi

	# Wait for data to be written
	sleep 2

	# Verify the URL was stored in KvStore
	local stored_url=$(get_peer_url_from_sync $debug_port 2)
	log_info "Stored URL for node 2: $stored_url"

	if [[ "$stored_url" == "$new_url" ]]; then
		log_info "Admin.SetNodeUrl test PASSED"
		return 0
	else
		log_error "Admin.SetNodeUrl test FAILED: expected '$new_url', got '$stored_url'"
		log_info "Sync data: $(debug_get_sync_data $debug_port)"
		return 1
	fi
}

# =============================================================================
# Test 15: Admin.SetNodeStatus RPC
# =============================================================================
test_admin_set_node_status() {
	log_info "========== Test 15: Admin.SetNodeStatus RPC =========="
	cleanup

	rm -rf "$RUN_DIR/wavekv_node1"

	generate_config 1
	start_node 1

	local admin_port=13016
	local debug_port=13015

	# Verify debug service is available
	if ! check_debug_service $debug_port; then
		log_error "Debug service not available"
		return 1
	fi

	# First set a URL for node 2 so we have a peer
	admin_set_node_url $admin_port 2 "https://node2.example.com:8011"
	sleep 1

	# Set node 2 status to "down"
	log_info "Setting node 2 status to 'down' via Admin.SetNodeStatus..."
	local response=$(admin_set_node_status $admin_port 2 "down")
	log_info "SetNodeStatus response: $response"

	# Check if the response contains an error
	if echo "$response" | grep -q '"error"'; then
		log_error "SetNodeStatus returned error: $response"
		return 1
	fi

	sleep 1

	# Set node 2 status back to "up"
	log_info "Setting node 2 status to 'up' via Admin.SetNodeStatus..."
	response=$(admin_set_node_status $admin_port 2 "up")
	log_info "SetNodeStatus response: $response"

	if echo "$response" | grep -q '"error"'; then
		log_error "SetNodeStatus returned error: $response"
		return 1
	fi

	# Test invalid status
	log_info "Testing invalid status..."
	response=$(admin_set_node_status $admin_port 2 "invalid")
	if echo "$response" | grep -q '"error"'; then
		log_info "Invalid status correctly rejected"
	else
		log_warn "Invalid status was not rejected (may be acceptable)"
	fi

	log_info "Admin.SetNodeStatus test PASSED"
	return 0
}

# =============================================================================
# Clean command - remove all generated files
# =============================================================================
clean() {
	log_info "Cleaning up generated files..."

	# Kill only test gateway processes (matching our specific config path)
	pkill -9 -f "dstack-gateway -c ${SCRIPT_DIR}/${RUN_DIR}/node" >/dev/null 2>&1 || true
	pkill -9 -f "dstack-gateway.*${SCRIPT_DIR}/${RUN_DIR}/node" >/dev/null 2>&1 || true
	sleep 1

	# Remove WireGuard interfaces (only our test interfaces need sudo)
	sudo ip link delete wavekv-test1 2>/dev/null || true
	sudo ip link delete wavekv-test2 2>/dev/null || true
	sudo ip link delete wavekv-test3 2>/dev/null || true

	# Remove run directory (contains all generated files including certs)
	rm -rf "$RUN_DIR"

	log_info "Cleanup complete"
}

# =============================================================================
# Ensure all certificates exist (CA + RPC + proxy)
# =============================================================================
ensure_certs() {
	# Create directories
	mkdir -p "$CERTS_DIR"
	mkdir -p "$RUN_DIR/certbot/live"

	# Generate CA certificate if not exists
	if [[ ! -f "$CERTS_DIR/gateway-ca.key" ]] || [[ ! -f "$CERTS_DIR/gateway-ca.cert" ]]; then
		log_info "Creating CA certificate..."
		openssl genrsa -out "$CERTS_DIR/gateway-ca.key" 2048 2>/dev/null
		openssl req -x509 -new -nodes \
			-key "$CERTS_DIR/gateway-ca.key" \
			-sha256 -days 365 \
			-out "$CERTS_DIR/gateway-ca.cert" \
			-subj "/CN=Test CA/O=WaveKV Test" \
			2>/dev/null
	fi

	# Generate RPC certificate signed by CA if not exists
	if [[ ! -f "$CERTS_DIR/gateway-rpc.key" ]] || [[ ! -f "$CERTS_DIR/gateway-rpc.cert" ]]; then
		log_info "Creating RPC certificate signed by CA..."
		openssl genrsa -out "$CERTS_DIR/gateway-rpc.key" 2048 2>/dev/null
		openssl req -new \
			-key "$CERTS_DIR/gateway-rpc.key" \
			-out "$CERTS_DIR/gateway-rpc.csr" \
			-subj "/CN=localhost" \
			2>/dev/null
		# Create certificate with SAN for localhost
		cat >"$CERTS_DIR/ext.cnf" <<EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EXTEOF
		openssl x509 -req \
			-in "$CERTS_DIR/gateway-rpc.csr" \
			-CA "$CERTS_DIR/gateway-ca.cert" \
			-CAkey "$CERTS_DIR/gateway-ca.key" \
			-CAcreateserial \
			-out "$CERTS_DIR/gateway-rpc.cert" \
			-days 365 \
			-sha256 \
			-extfile "$CERTS_DIR/ext.cnf" \
			2>/dev/null
		rm -f "$CERTS_DIR/gateway-rpc.csr" "$CERTS_DIR/ext.cnf"
	fi

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

	# Handle cfg command - generate node configuration
	if [[ "${1:-}" == "cfg" ]]; then
		local node_id="${2:-}"
		if [[ -z "$node_id" ]]; then
			log_error "Usage: $0 cfg <node_id>"
			log_info "Example: $0 cfg 1"
			exit 1
		fi

		# Ensure certificates exist
		ensure_certs

		# Generate config for the specified node
		generate_config "$node_id"
		log_info "Configuration generated: $RUN_DIR/node${node_id}.toml"
		exit 0
	fi

	# Handle case command - run specific test case
	if [[ "${1:-}" == "case" ]]; then
		local test_case="${2:-}"
		if [[ -z "$test_case" ]]; then
			log_error "Usage: $0 case <testcase>"
			log_info "Available test cases:"
			log_info "  - test_persistence"
			log_info "  - test_multi_node_sync"
			log_info "  - test_node_recovery"
			log_info "  - test_status_endpoint"
			log_info "  - test_cross_node_data_sync"
			log_info "  - test_prpc_register"
			log_info "  - test_prpc_info"
			log_info "  - test_client_registration_persistence"
			log_info "  - test_stress_writes"
			log_info "  - test_network_partition"
			log_info "  - test_three_node_cluster"
			log_info "  - test_three_node_bootnode"
			log_info "  - test_wal_integrity"
			log_info "  - test_admin_set_node_url"
			log_info "  - test_admin_set_node_status"
			exit 1
		fi

		# Check if gateway binary exists
		if [[ ! -f "$GATEWAY_BIN" ]]; then
			log_error "Gateway binary not found: $GATEWAY_BIN"
			log_info "Please run: cargo build --release"
			exit 1
		fi

		# Ensure certificates exist
		ensure_certs

		# Check if test function exists
		if ! declare -f "$test_case" >/dev/null; then
			log_error "Test case not found: $test_case"
			log_info "Use '$0 case' to see available test cases"
			exit 1
		fi

		# Run the specific test
		log_info "Running test case: $test_case"
		CURRENT_TEST="$test_case"
		if $test_case; then
			log_info "Test PASSED: $test_case"
			cleanup
			exit 0
		else
			log_error "Test FAILED: $test_case"
			cleanup
			exit 1
		fi
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
		run_test test_three_node_bootnode
	fi

	if [[ "$test_filter" == "all" ]] || [[ "$test_filter" == "admin" ]]; then
		run_test test_admin_set_node_url
		run_test test_admin_set_node_status
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
