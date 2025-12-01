#!/bin/bash
# Gateway cluster management script for manual testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GATEWAY_BIN="${SCRIPT_DIR}/../../target/release/dstack-gateway"
RUN_DIR="run"
CERTS_DIR="$RUN_DIR/certs"
CA_CERT="$CERTS_DIR/gateway-ca.cert"
LOG_DIR="$RUN_DIR/logs"
TMUX_SESSION="gateway-cluster"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_help() {
    echo "Gateway Cluster Management Script"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  start   Start a 3-node gateway cluster in tmux"
    echo "  stop    Stop the cluster (keep tmux session)"
    echo "  reg     Register a random instance"
    echo "  status  Show cluster status"
    echo "  clean   Destroy cluster and clean all data"
    echo "  attach  Attach to tmux session"
    echo "  help    Show this help"
    echo ""
}

# Generate certificates
generate_certs() {
    mkdir -p "$CERTS_DIR"
    mkdir -p "$RUN_DIR/certbot/live"

    # Generate CA certificate
    if [[ ! -f "$CERTS_DIR/gateway-ca.key" ]]; then
        log_info "Creating CA certificate..."
        openssl genrsa -out "$CERTS_DIR/gateway-ca.key" 2048 2>/dev/null
        openssl req -x509 -new -nodes \
            -key "$CERTS_DIR/gateway-ca.key" \
            -sha256 -days 365 \
            -out "$CERTS_DIR/gateway-ca.cert" \
            -subj "/CN=Test CA/O=Gateway Test" \
            2>/dev/null
    fi

    # Generate RPC certificate signed by CA
    if [[ ! -f "$CERTS_DIR/gateway-rpc.key" ]]; then
        log_info "Creating RPC certificate..."
        openssl genrsa -out "$CERTS_DIR/gateway-rpc.key" 2048 2>/dev/null
        openssl req -new \
            -key "$CERTS_DIR/gateway-rpc.key" \
            -out "$CERTS_DIR/gateway-rpc.csr" \
            -subj "/CN=localhost" \
            2>/dev/null
        cat > "$CERTS_DIR/ext.cnf" << EXTEOF
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

    # Generate proxy certificates
    local proxy_cert_dir="$RUN_DIR/certbot/live"
    if [[ ! -f "$proxy_cert_dir/cert.pem" ]]; then
        log_info "Creating proxy certificates..."
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$proxy_cert_dir/key.pem" \
            -out "$proxy_cert_dir/cert.pem" \
            -days 365 \
            -subj "/CN=localhost" \
            2>/dev/null
    fi

    # Generate unique WireGuard key pair for each node
    for i in 1 2 3; do
        if [[ ! -f "$CERTS_DIR/wg-node${i}.key" ]]; then
            log_info "Generating WireGuard keys for node ${i}..."
            wg genkey > "$CERTS_DIR/wg-node${i}.key"
            wg pubkey < "$CERTS_DIR/wg-node${i}.key" > "$CERTS_DIR/wg-node${i}.pub"
        fi
    done
}

# Generate node config
generate_config() {
    local node_id=$1
    local rpc_port=$((13000 + node_id * 10 + 2))
    local wg_port=$((13000 + node_id * 10 + 3))
    local proxy_port=$((13000 + node_id * 10 + 4))
    local debug_port=$((13000 + node_id * 10 + 5))
    local admin_port=$((13000 + node_id * 10 + 6))
    local wg_ip="10.0.3${node_id}.1/24"
    local other_nodes=""
    local peer_urls=""

    # Read WireGuard keys for this node
    local wg_private_key=$(cat "$CERTS_DIR/wg-node${node_id}.key")
    local wg_public_key=$(cat "$CERTS_DIR/wg-node${node_id}.pub")

    for i in 1 2 3; do
        if [[ $i -ne $node_id ]]; then
            local peer_rpc_port=$((13000 + i * 10 + 2))
            if [[ -n "$other_nodes" ]]; then
                other_nodes="$other_nodes, $i"
                peer_urls="$peer_urls, \"$i:https://localhost:$peer_rpc_port\""
            else
                other_nodes="$i"
                peer_urls="\"$i:https://localhost:$peer_rpc_port\""
            fi
        fi
    done

    local abs_run_dir="$SCRIPT_DIR/$RUN_DIR"
    cat > "$RUN_DIR/node${node_id}.toml" << EOF
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
rpc_domain = "gateway.test.local"
danger_disable_attestation = true
state_path = "${RUN_DIR}/gateway-state-node${node_id}.json"

[core.debug]
enabled = true
port = ${debug_port}
address = "127.0.0.1"

[core.admin]
enabled = true
port = ${admin_port}
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
peer_urls = [${peer_urls}]
wavekv_data_dir = "${RUN_DIR}/wavekv_node${node_id}"

[core.certbot]
enabled = false

[core.wg]
private_key = "${wg_private_key}"
public_key = "${wg_public_key}"
listen_port = ${wg_port}
ip = "${wg_ip}"
reserved_net = ["10.0.3${node_id}.1/31"]
client_ip_range = "10.0.3${node_id}.1/24"
config_path = "${RUN_DIR}/wg_node${node_id}.conf"
interface = "gw-test${node_id}"
endpoint = "127.0.0.1:${wg_port}"

[core.proxy]
cert_chain = "${RUN_DIR}/certbot/live/cert.pem"
cert_key = "${RUN_DIR}/certbot/live/key.pem"
base_domain = "test.local"
listen_addr = "0.0.0.0"
listen_port = ${proxy_port}
tappd_port = 8090
external_port = ${proxy_port}
inbound_pp_enabled = false

[core.recycle]
enabled = true
interval = "30s"
timeout = "120s"
node_timeout = "300s"
EOF
}

# Build gateway binary
build_gateway() {
    if [[ ! -f "$GATEWAY_BIN" ]]; then
        log_info "Building gateway..."
        (cd "$SCRIPT_DIR/.." && cargo build --release)
    fi
}

# Start cluster
cmd_start() {
    build_gateway
    generate_certs

    # Check if tmux session exists
    if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        log_warn "Cluster already running. Use 'clean' to restart."
        cmd_status
        return 0
    fi

    log_info "Generating configs..."
    mkdir -p "$RUN_DIR" "$LOG_DIR"
    for i in 1 2 3; do
        generate_config $i
        mkdir -p "$RUN_DIR/wavekv_node${i}"
    done

    log_info "Starting cluster in tmux session '$TMUX_SESSION'..."

    # Create wrapper scripts that keep running even if gateway exits
    for i in 1 2 3; do
        cat > "$RUN_DIR/run_node${i}.sh" << RUNEOF
#!/bin/bash
cd "$SCRIPT_DIR"
while true; do
    echo "Starting node ${i}..."
    sudo RUST_LOG=info $GATEWAY_BIN -c $RUN_DIR/node${i}.toml 2>&1 | tee -a $LOG_DIR/node${i}.log
    echo "Node ${i} exited. Press Ctrl+C to stop, or wait 3s to restart..."
    sleep 3
done
RUNEOF
        chmod +x "$RUN_DIR/run_node${i}.sh"
    done

    # Create tmux session
    tmux new-session -d -s "$TMUX_SESSION" -n "node1"
    tmux send-keys -t "$TMUX_SESSION:node1" "$RUN_DIR/run_node1.sh" Enter

    sleep 1

    # Add windows for other nodes
    tmux new-window -t "$TMUX_SESSION" -n "node2"
    tmux send-keys -t "$TMUX_SESSION:node2" "$RUN_DIR/run_node2.sh" Enter

    tmux new-window -t "$TMUX_SESSION" -n "node3"
    tmux send-keys -t "$TMUX_SESSION:node3" "$RUN_DIR/run_node3.sh" Enter

    # Add a shell window
    tmux new-window -t "$TMUX_SESSION" -n "shell"

    sleep 3

    log_info "Cluster started!"
    echo ""
    cmd_status
    echo ""
    log_info "Use '$0 attach' to view logs"
}

# Stop cluster
cmd_stop() {
    log_info "Stopping cluster..."
    sudo pkill -9 -f "dstack-gateway.*node[123].toml" 2>/dev/null || true
    sudo ip link delete gw-test1 2>/dev/null || true
    sudo ip link delete gw-test2 2>/dev/null || true
    sudo ip link delete gw-test3 2>/dev/null || true
    log_info "Cluster stopped"
}

# Clean everything
cmd_clean() {
    cmd_stop

    # Kill tmux session
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true

    log_info "Cleaning data..."
    sudo rm -rf "$RUN_DIR/wavekv_node"*
    sudo rm -f "$RUN_DIR/gateway-state-node"*.json
    rm -f "$RUN_DIR/wg_node"*.conf
    rm -f "$RUN_DIR/node"*.toml
    rm -f "$RUN_DIR/run_node"*.sh
    rm -rf "$LOG_DIR"

    log_info "Cleaned"
}

# Show status
cmd_status() {
    echo -e "${BLUE}=== Gateway Cluster Status ===${NC}"
    echo ""

    for i in 1 2 3; do
        local rpc_port=$((13000 + i * 10 + 2))
        local proxy_port=$((13000 + i * 10 + 4))
        local debug_port=$((13000 + i * 10 + 5))
        local admin_port=$((13000 + i * 10 + 6))

        if pgrep -f "dstack-gateway.*node${i}.toml" > /dev/null 2>&1; then
            echo -e "Node $i: ${GREEN}RUNNING${NC}"
        else
            echo -e "Node $i: ${RED}STOPPED${NC}"
        fi
        echo "  RPC:   https://localhost:${rpc_port}"
        echo "  Proxy: https://localhost:${proxy_port}"
        echo "  Debug: http://localhost:${debug_port}"
        echo "  Admin: http://localhost:${admin_port}"
        echo ""
    done

    # Show instance count from first running node
    for i in 1 2 3; do
        local debug_port=$((13000 + i * 10 + 5))
        if pgrep -f "dstack-gateway.*node${i}.toml" > /dev/null 2>&1; then
            local response=$(curl -s -X POST "http://localhost:${debug_port}/prpc/GetSyncData" \
                -H "Content-Type: application/json" -d '{}' 2>/dev/null)
            if [[ -n "$response" ]]; then
                local n_instances=$(echo "$response" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('instances', [])))" 2>/dev/null || echo "?")
                local n_nodes=$(echo "$response" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('nodes', [])))" 2>/dev/null || echo "?")
                echo -e "${BLUE}Cluster State:${NC}"
                echo "  Nodes: $n_nodes"
                echo "  Instances: $n_instances"
            fi
            break
        fi
    done
}

# Register a random instance
cmd_reg() {
    # Find a running node
    local debug_port=""
    for i in 1 2 3; do
        local port=$((13000 + i * 10 + 5))
        if pgrep -f "dstack-gateway.*node${i}.toml" > /dev/null 2>&1; then
            debug_port=$port
            break
        fi
    done

    if [[ -z "$debug_port" ]]; then
        log_error "No running nodes found. Start cluster first."
        exit 1
    fi

    # Generate random WireGuard key pair
    local private_key=$(wg genkey)
    local public_key=$(echo "$private_key" | wg pubkey)

    # Generate random IDs
    local app_id="app-$(openssl rand -hex 4)"
    local instance_id="inst-$(openssl rand -hex 4)"

    log_info "Registering instance..."
    log_info "  App ID: $app_id"
    log_info "  Instance ID: $instance_id"
    log_info "  Public Key: $public_key"

    local response=$(curl -s \
        -X POST "http://localhost:${debug_port}/prpc/RegisterCvm" \
        -H "Content-Type: application/json" \
        -d "{\"client_public_key\": \"$public_key\", \"app_id\": \"$app_id\", \"instance_id\": \"$instance_id\"}" 2>/dev/null)

    if echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'wg' in d" 2>/dev/null; then
        local client_ip=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['wg']['client_ip'])" 2>/dev/null)
        log_info "Registered successfully!"
        echo -e "  Client IP: ${GREEN}$client_ip${NC}"
        echo ""
        echo "Instance details:"
        echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    else
        log_error "Registration failed:"
        echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
        exit 1
    fi
}

# Attach to tmux
cmd_attach() {
    if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        tmux attach -t "$TMUX_SESSION"
    else
        log_error "No cluster running"
        exit 1
    fi
}

# Main
case "${1:-help}" in
    start)
        cmd_start
        ;;
    stop)
        cmd_stop
        ;;
    clean)
        cmd_clean
        ;;
    status)
        cmd_status
        ;;
    reg)
        cmd_reg
        ;;
    attach)
        cmd_attach
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
