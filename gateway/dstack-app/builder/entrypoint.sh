#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -e

DATA_DIR="/data"
GATEWAY_BASE_DIR="$DATA_DIR/gateway"
CONFIG_PATH="$GATEWAY_BASE_DIR/gateway.toml"
CERTS_DIR="$GATEWAY_BASE_DIR/certs"
WG_KEY_PATH="$GATEWAY_BASE_DIR/wg.key"
mkdir -p $GATEWAY_BASE_DIR/
mkdir -p $DATA_DIR/wireguard/

# Generate or load WireGuard keys
if [ -f "$WG_KEY_PATH" ]; then
    PRIVATE_KEY=$(cat "$WG_KEY_PATH")
else
    PRIVATE_KEY=$(wg genkey)
    echo "$PRIVATE_KEY" >"$WG_KEY_PATH"
    chmod 600 "$WG_KEY_PATH" # Secure the private key file
fi
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

validate_env() {
    if [[ "$1" =~ \" ]]; then
        echo "Invalid environment variable"
        exit 1
    fi
}

validate_env "$WG_ENDPOINT"
validate_env "$NODE_ID"
validate_env "$WG_IP"
validate_env "$WG_RESERVED_NET"
validate_env "$WG_CLIENT_RANGE"

# Validate $NODE_ID, must be a number
if [[ ! "$NODE_ID" =~ ^[0-9]+$ ]]; then
    echo "Invalid NODE_ID: $NODE_ID"
    exit 1
fi

SYNC_ENABLED=$([ -z "$BOOTNODE_URL" ] && echo "false" || echo "true")

echo "WG_IP: $WG_IP"
echo "WG_RESERVED_NET: $WG_RESERVED_NET"
echo "WG_CLIENT_RANGE: $WG_CLIENT_RANGE"
echo "SYNC_ENABLED: $SYNC_ENABLED"
echo "RPC_DOMAIN: $RPC_DOMAIN"

# Create gateway.toml configuration
cat >$CONFIG_PATH <<EOF
keep_alive = 10
log_level = "info"
address = "0.0.0.0:8000"

[tls]
key = "$CERTS_DIR/gateway-rpc.key"
certs = "$CERTS_DIR/gateway-rpc.cert"

[tls.mutual]
ca_certs = "$CERTS_DIR/gateway-ca.cert"
mandatory = false

[core]
set_ulimit = true
rpc_domain = "$RPC_DOMAIN"

[core.sync]
enabled = $SYNC_ENABLED
node_id = $NODE_ID
interval = "${SYNC_INTERVAL:-1m}"
timeout = "${SYNC_TIMEOUT:-2m}"
my_url = "$MY_URL"
bootnode = "$BOOTNODE_URL"
data_dir = "$DATA_DIR"
persist_interval = "${SYNC_PERSIST_INTERVAL:-5m}"
sync_connections_enabled = ${SYNC_CONNECTIONS_ENABLED:-true}
sync_connections_interval = "${SYNC_CONNECTIONS_INTERVAL:-30s}"

[core.admin]
enabled = true
address = "${ADMIN_LISTEN_ADDR:-0.0.0.0}"
port = ${ADMIN_LISTEN_PORT:-8001}

[core.wg]
public_key = "$PUBLIC_KEY"
private_key = "$PRIVATE_KEY"
ip = "$WG_IP"
reserved_net = ["$WG_RESERVED_NET"]
listen_port = 51820
client_ip_range = "$WG_CLIENT_RANGE"
config_path = "$DATA_DIR/wireguard/wg-ds-gw.conf"
interface = "wg-ds-gw"
endpoint = "$WG_ENDPOINT"

[core.proxy]
tls_crypto_provider = "aws-lc-rs"
tls_versions = ["1.2"]
listen_addr = "0.0.0.0"
listen_port = "${PROXY_LISTEN_PORT:-443}"
connect_top_n = 3
localhost_enabled = false
app_address_ns_compat = true
workers = ${PROXY_WORKERS:-32}
max_connections_per_app = ${MAX_CONNECTIONS_PER_APP:-0}

[core.proxy.timeouts]
connect = "${TIMEOUT_CONNECT:-5s}"
handshake = "${TIMEOUT_HANDSHAKE:-5s}"
cache_top_n = "${TIMEOUT_CACHE_TOP_N:-30s}"
dns_resolve = "${TIMEOUT_DNS_RESOLVE:-5s}"
data_timeout_enabled = ${TIMEOUT_DATA_ENABLED:-true}
idle = "${TIMEOUT_IDLE:-10m}"
write = "${TIMEOUT_WRITE:-5s}"
shutdown = "${TIMEOUT_SHUTDOWN:-5s}"
total = "${TIMEOUT_TOTAL:-5h}"

[core.recycle]
enabled = true
interval = "5m"
timeout = "10h"
node_timeout = "10m"
EOF

echo "Configuration file generated: $CONFIG_PATH"
exec "$@"
