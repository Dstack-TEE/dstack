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

CERTBOT_WORKDIR="$DATA_DIR/rproxy/certs"

if [ "$ACME_STAGING" = "yes" ]; then
    ACME_URL="https://acme-staging-v02.api.letsencrypt.org/directory"
else
    ACME_URL="https://acme-v02.api.letsencrypt.org/directory"
fi

if [ -f "$CONFIG_PATH" ]; then
    echo "Configuration file already exists: $CONFIG_PATH"
    # exit 0
fi

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

validate_env "$MY_URL"
validate_env "$BOOTNODE_URL"
validate_env "$CF_API_TOKEN"
validate_env "$SRV_DOMAIN"
validate_env "$WG_ENDPOINT"

# Validate $SUBNET_INDEX, valid range is 0-15
if [[ ! "$SUBNET_INDEX" =~ ^[0-9]+$ ]] || [ "$SUBNET_INDEX" -lt 0 ] || [ "$SUBNET_INDEX" -gt 15 ]; then
    echo "Invalid SUBNET_INDEX: $SUBNET_INDEX"
    exit 1
fi

SYNC_ENABLED=$([ -z "$BOOTNODE_URL" ] && echo "false" || echo "true")
# The IP address of this dstack-gateway node
IP="10.4.0.$((SUBNET_INDEX + 1))/16"
# Reserving 5 bits(32 IPs) for server use
RESERVED_NET="10.4.0.0/27"
# The client IP range this dstack-gateway node can allocate
CLIENT_RANGE="10.4.$((SUBNET_INDEX * 16)).0/20"

if [ -z "$RPC_DOMAIN" ]; then
    RPC_DOMAIN="gateway.$SRV_DOMAIN"
fi

echo "IP: $IP"
echo "RESERVED_NET: $RESERVED_NET"
echo "CLIENT_RANGE: $CLIENT_RANGE"
echo "SYNC_ENABLED: $SYNC_ENABLED"
echo "RPC_DOMAIN: $RPC_DOMAIN"

# Create gateway.toml configuration
cat >$CONFIG_PATH <<EOF
keep_alive = 10
log_level = "info"
address = "0.0.0.0"
port = 8000

[tls]
key = "$CERTS_DIR/gateway-rpc.key"
certs = "$CERTS_DIR/gateway-rpc.cert"

[tls.mutual]
ca_certs = "$CERTS_DIR/gateway-ca.cert"
mandatory = false

[core]
state_path = "$DATA_DIR/gateway-state.json"
set_ulimit = true
rpc_domain = "$RPC_DOMAIN"
run_in_dstack = true

[core.sync]
enabled = $SYNC_ENABLED
interval = "30s"
my_url = "$MY_URL"
bootnode = "$BOOTNODE_URL"

[core.admin]
enabled = true
address = "0.0.0.0"
port = 8001

[core.certbot]
enabled = true
workdir = "$CERTBOT_WORKDIR"
acme_url = "$ACME_URL"
cf_api_token = "$CF_API_TOKEN"
auto_set_caa = true
domain = "*.$SRV_DOMAIN"
renew_interval = "1h"
renew_before_expiration = "10d"
renew_timeout = "5m"
max_dns_wait = "${CERTBOT_MAX_DNS_WAIT:-5m}"
dns_txt_ttl = "${CERTBOT_DNS_TXT_TTL:-60}"

[core.wg]
public_key = "$PUBLIC_KEY"
private_key = "$PRIVATE_KEY"
ip = "$IP"
reserved_net = ["$RESERVED_NET"]
listen_port = 51820
client_ip_range = "$CLIENT_RANGE"
config_path = "$DATA_DIR/wireguard/wg-ds-gw.conf"
interface = "wg-ds-gw"
endpoint = "$WG_ENDPOINT"

[core.proxy]
cert_chain = "$CERTBOT_WORKDIR/live/cert.pem"
cert_key = "$CERTBOT_WORKDIR/live/key.pem"
base_domain = "$SRV_DOMAIN"
listen_addr = "0.0.0.0"
listen_port = 443
connect_top_n = 3
localhost_enabled = false

[core.proxy.timeouts]
connect = "5s"
handshake = "5s"
cache_top_n = "30s"
data_timeout_enabled = true
idle = "10m"
write = "5s"
shutdown = "5s"
total = "5h"

[core.proxy.yamux]
listen_addr = "${YAMUX_LISTEN_ADDR:-0.0.0.0}"
listen_port = ${YAMUX_LISTEN_PORT:-0}
## Set to 0 to disable max connection receive window limit.
max_connection_receive_window = ${YAMUX_MAX_CONNECTION_RECEIVE_WINDOW:-1073741824}
max_num_streams = ${YAMUX_MAX_NUM_STREAMS:-512}
read_after_close = ${YAMUX_READ_AFTER_CLOSE:-true}
split_send_size = ${YAMUX_SPLIT_SEND_SIZE:-16384}
ping_timeout = "${YAMUX_PING_TIMEOUT:-15s}"

[core.recycle]
enabled = true
interval = "5m"
timeout = "10h"
EOF

echo "Configuration file have been generated in $CONFIG_PATH"
exec "$@"
