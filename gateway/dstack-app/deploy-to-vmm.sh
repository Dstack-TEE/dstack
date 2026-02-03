#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

APP_COMPOSE_FILE=""

usage() {
  echo "Usage: $0 [-c <app compose file>]"
  echo "  -c  App compose file"
}

while getopts "c:h" opt; do
  case $opt in
    c)
      APP_COMPOSE_FILE=$OPTARG
      ;;
    h)
      usage
      exit 0
      ;;
    \?)
      usage
      exit 1
      ;;
  esac
done

# Check if .env exists
if [ -f ".env" ]; then
  # Load variables from .env
  echo "Loading environment variables from .env file..."
  set -a
  source .env
  set +a
else
  # Create a template .env file
  echo "Creating template .env file..."
  cat >.env <<EOF
# Required environment variables for dstack-gateway deployment
# Please uncomment and set values for the following variables:

# The URL of the dstack-vmm RPC service
# VMM_RPC=unix:../../../build/vmm.sock

# Cloudflare API token for DNS challenge
# CF_API_TOKEN=your_cloudflare_api_token

# Service domain
# SRV_DOMAIN=test5.dstack.phala.network

# Public IP address
PUBLIC_IP=$(curl -s4 ifconfig.me)

# Node ID for this gateway instance.
# Must be unique across all gateway instances in the network.
# Must be 32-bit unsigned integer (0-4294967295)
# Must be non-zero if deploying multiple gateways (1-4294967295)
NODE_ID=1

# The dstack-gateway application ID. Register the app in DstackKms first to get the app ID.
# GATEWAY_APP_ID=31884c4b7775affe4c99735f6c2aff7d7bc6cfcd

# Whether to use ACME staging (yes/no)
ACME_STAGING=no

# Networking mode: bridge or user (default: user)
# NET_MODE=bridge

# Subnet index. 0~15
SUBNET_INDEX=0

# My URL
# MY_URL=https://gateway.test5.dstack.phala.network:9202

# Bootnode URL
# BOOTNODE_URL=https://gateway.test2.dstack.phala.network:9202

# dstack OS image name
OS_IMAGE=dstack-0.5.5

# Set defaults for variables that might not be in .env
GATEWAY_IMAGE=dstacktee/dstack-gateway@sha256:a7b7e3144371b053ba21d6ac18141afd49e3cd767ca2715599aa0e2703b3a11a

# Port configurations
GATEWAY_RPC_ADDR=0.0.0.0:9202
GATEWAY_ADMIN_RPC_ADDR=127.0.0.1:9203
GATEWAY_SERVING_PORT=9204
GATEWAY_SERVING_NUM_PORTS=1
GUEST_AGENT_ADDR=127.0.0.1:9206
WG_ADDR=0.0.0.0:9202

# The token used to launch the App
APP_LAUNCH_TOKEN=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

EOF
  echo "Please edit the .env file and set the required variables, then run this script again."
  exit 1
fi

# Define required environment variables
required_env_vars=(
  "VMM_RPC"
  "CF_API_TOKEN"
  "SRV_DOMAIN"
  "PUBLIC_IP"
  "WG_ADDR"
  "GATEWAY_APP_ID"
  "MY_URL"
  "APP_LAUNCH_TOKEN"
  "NODE_ID"
  "KMS_URL"
  # "BOOTNODE_URL"
)

# Validate required environment variables
for var in "${required_env_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Error: Required environment variable $var is not set."
    echo "Please edit the .env file and set a value for $var, then run this script again."
    exit 1
  fi
done

CLI="../../vmm/src/vmm-cli.py --url $VMM_RPC"

WG_PORT=$(echo $WG_ADDR | cut -d':' -f2)
COMPOSE_TMP=$(mktemp)

cp docker-compose.yaml "$COMPOSE_TMP"

subvar() {
  sed -i "s|\${$1}|${!1}|g" "$COMPOSE_TMP"
}

subvar GATEWAY_IMAGE

# Default RPC_DOMAIN from SRV_DOMAIN if not set
if [ -z "$RPC_DOMAIN" ]; then
  RPC_DOMAIN="gateway.$SRV_DOMAIN"
fi

# Calculate WireGuard IP allocation from SUBNET_INDEX
WG_IP_PREFIX="10.$((SUBNET_INDEX + 240)).0"
WG_IP="${WG_IP_PREFIX}.1/12"
WG_RESERVED_NET="${WG_IP_PREFIX}.1/32"
WG_CLIENT_RANGE="${WG_IP_PREFIX}.0/16"

# Calculate listen port for proxy
if [ "${GATEWAY_SERVING_NUM_PORTS:-1}" -gt 1 ]; then
  PROXY_LISTEN_PORT="443-$((443 + GATEWAY_SERVING_NUM_PORTS - 1))"
else
  PROXY_LISTEN_PORT=443
fi

echo "Docker compose file:"
cat "$COMPOSE_TMP"

# Update .env file with current values
cat <<EOF >.app_env
WG_ENDPOINT=$PUBLIC_IP:$WG_PORT
MY_URL=$MY_URL
BOOTNODE_URL=$BOOTNODE_URL
WG_IP=$WG_IP
WG_RESERVED_NET=$WG_RESERVED_NET
WG_CLIENT_RANGE=$WG_CLIENT_RANGE
APP_LAUNCH_TOKEN=$APP_LAUNCH_TOKEN
RPC_DOMAIN=$RPC_DOMAIN
NODE_ID=$NODE_ID
PROXY_LISTEN_PORT=$PROXY_LISTEN_PORT
EOF

if [ -n "$APP_COMPOSE_FILE" ]; then
  cp "$APP_COMPOSE_FILE" .app-compose.json
else

  EXPECTED_TOKEN_HASH=$(echo -n "$APP_LAUNCH_TOKEN" | sha256sum | cut -d' ' -f1)
  cat >.prelaunch.sh <<'EOF'
EXPECTED_TOKEN_HASH=$(jq -j .launch_token_hash app-compose.json)
if [ "$EXPECTED_TOKEN_HASH" == "null" ]; then
    echo "Skipped APP_LAUNCH_TOKEN check"
else
  ACTUAL_TOKEN_HASH=$(echo -n "$APP_LAUNCH_TOKEN" | sha256sum | cut -d' ' -f1)
  if [ "$EXPECTED_TOKEN_HASH" != "$ACTUAL_TOKEN_HASH" ]; then
      echo "Error: Incorrect APP_LAUNCH_TOKEN, please make sure set the correct APP_LAUNCH_TOKEN in env"
      reboot
      exit 1
  else
      echo "APP_LAUNCH_TOKEN checked OK"
  fi
fi
EOF

  $CLI compose \
    --docker-compose "$COMPOSE_TMP" \
    --name dstack-gateway \
    --kms \
    --env-file .app_env \
    --public-logs \
    --public-sysinfo \
    --no-instance-id \
    --secure-time \
    --prelaunch-script .prelaunch.sh \
    --output .app-compose.json > /dev/null
fi

# Set launch_token_hash in app-compose.json
mv .app-compose.json .app-compose.json.tmp
jq \
  --arg token_hash "$EXPECTED_TOKEN_HASH" \
  '.launch_token_hash = $token_hash' \
  .app-compose.json.tmp > .app-compose.json

COMPOSE_HASH=$(sha256sum .app-compose.json | cut -d' ' -f1)
echo "Compose hash: 0x$COMPOSE_HASH"

# Remove the temporary file as it is no longer needed
rm "$COMPOSE_TMP"

echo "Configuration:"
echo "VMM_RPC: $VMM_RPC"
echo "SRV_DOMAIN: $SRV_DOMAIN"
echo "PUBLIC_IP: $PUBLIC_IP"
echo "GATEWAY_APP_ID: $GATEWAY_APP_ID"
echo "MY_URL: $MY_URL"
echo "BOOTNODE_URL: $BOOTNODE_URL"
echo "WG_IP: $WG_IP"
echo "WG_RESERVED_NET: $WG_RESERVED_NET"
echo "WG_CLIENT_RANGE: $WG_CLIENT_RANGE"
echo "WG_ADDR: $WG_ADDR"
echo "GATEWAY_RPC_ADDR: $GATEWAY_RPC_ADDR"
echo "GATEWAY_ADMIN_RPC_ADDR: $GATEWAY_ADMIN_RPC_ADDR"
echo "GATEWAY_SERVING_PORT: $GATEWAY_SERVING_PORT (x$GATEWAY_SERVING_NUM_PORTS)"
echo "GUEST_AGENT_ADDR: $GUEST_AGENT_ADDR"
echo "RPC_DOMAIN: $RPC_DOMAIN"
if [ -t 0 ]; then
  # Only ask for confirmation if running in an interactive terminal
  read -p "Continue? [y/N] " -n 1 -r
  echo

  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 1
  fi
fi

echo "Deploying dstack-gateway to dstack-vmm..."

DEPLOY_ARGS=(
  --name dstack-gateway
  --app-id "$GATEWAY_APP_ID"
  --compose .app-compose.json
  --env-file .app_env
  --kms-url "$KMS_URL"
  --image "$OS_IMAGE"
  --vcpu 32
  --memory 32G
)

if [ "${NET_MODE:-bridge}" = "bridge" ]; then
  DEPLOY_ARGS+=(--net bridge)
else
  DEPLOY_ARGS+=(
    --port "tcp:$GATEWAY_RPC_ADDR:8000"
    --port "tcp:$GATEWAY_ADMIN_RPC_ADDR:8001"
    --port "tcp:$GUEST_AGENT_ADDR:8090"
    --port "udp:$WG_ADDR:51820"
  )
  # Map serving port range: host ports starting at GATEWAY_SERVING_PORT
  # to container ports starting at 443
  SERVING_END=$((GATEWAY_SERVING_PORT + GATEWAY_SERVING_NUM_PORTS - 1))
  for hp in $(seq "$GATEWAY_SERVING_PORT" "$SERVING_END"); do
    cp=$((443 + hp - GATEWAY_SERVING_PORT))
    DEPLOY_ARGS+=(--port "tcp:0.0.0.0:${hp}:${cp}")
  done
fi

$CLI deploy "${DEPLOY_ARGS[@]}"

# Bootstrap Admin RPC configuration
# Wait for the gateway admin API to be ready, then configure DNS credentials, domain, and certbot
vmm_curl() {
  # Calls VMM RPC via curl, handling both unix socket and HTTP URLs
  local path="$1"; shift
  if [[ "$VMM_RPC" == unix:* ]]; then
    local sock="${VMM_RPC#unix:}"
    curl --unix-socket "$sock" -sf "http://localhost$path" "$@"
  else
    curl -sf "${VMM_RPC}${path}" "$@"
  fi
}

get_vm_id() {
  # Resolve VM ID from name via VMM Status RPC
  local vm_name="$1"
  local status
  status=$(vmm_curl "/prpc/Status" -X POST -H "Content-Type: application/json" -d '{}' 2>/dev/null) || true
  echo "$status" | jq -r --arg name "$vm_name" '.vms[]? | select(.name == $name) | .id' 2>/dev/null | head -1
}

get_admin_addr() {
  # In bridge mode, get guest IP from VMM guest API and use port 8001
  # In other modes, use the configured GATEWAY_ADMIN_RPC_ADDR
  if [ "${NET_MODE:-bridge}" = "bridge" ]; then
    local vm_id
    vm_id=$(get_vm_id "dstack-gateway")
    if [ -z "$vm_id" ]; then
      echo "WARN: could not find VM ID for dstack-gateway" >&2
      echo "$GATEWAY_ADMIN_RPC_ADDR"
      return
    fi
    echo "Bridge mode: VM ID=$vm_id, waiting for guest network info..." >&2
    local max_retries=30
    local retry=0
    while [ $retry -lt $max_retries ]; do
      local net_info
      net_info=$(vmm_curl "/guest/NetworkInfo" \
        -X POST -H "Content-Type: application/json" \
        -d "{\"id\":\"$vm_id\"}" 2>/dev/null) || true
      if [ -n "$net_info" ]; then
        local guest_ip
        guest_ip=$(echo "$net_info" | jq -r '
          .interfaces[]? |
          select(.name != "lo") |
          .addresses[]? |
          .address' 2>/dev/null | head -1)
        if [ -n "$guest_ip" ] && [ "$guest_ip" != "null" ]; then
          echo "  Guest IP: $guest_ip" >&2
          echo "${guest_ip}:8001"
          return
        fi
      fi
      retry=$((retry + 1))
      sleep 5
    done
    echo "WARN: could not get guest IP, falling back to $GATEWAY_ADMIN_RPC_ADDR" >&2
  fi
  echo "$GATEWAY_ADMIN_RPC_ADDR"
}

bootstrap_admin() {
  local admin_addr
  admin_addr=$(get_admin_addr)
  local max_retries=60
  local retry=0

  echo "Waiting for gateway admin API at $admin_addr..."
  while [ $retry -lt $max_retries ]; do
    if curl -sf "http://$admin_addr/prpc/Status" >/dev/null 2>&1; then
      break
    fi
    retry=$((retry + 1))
    sleep 5
  done

  if [ $retry -eq $max_retries ]; then
    echo "WARN: admin API not ready after $max_retries retries, skipping bootstrap"
    echo "You can configure the gateway manually via the Web UI at http://$admin_addr"
    return
  fi

  echo "Admin API ready, bootstrapping configuration..."

  # Set ACME URL
  if [ "$ACME_STAGING" = "yes" ]; then
    ACME_URL="https://acme-staging-v02.api.letsencrypt.org/directory"
  else
    ACME_URL="https://acme-v02.api.letsencrypt.org/directory"
  fi

  echo "Setting certbot config (ACME URL: $ACME_URL)..."
  curl -sf -X POST "http://$admin_addr/prpc/SetCertbotConfig" \
    -H "Content-Type: application/json" \
    -d '{"acme_url":"'"$ACME_URL"'","renew_interval_secs":3600,"renew_before_expiration_secs":864000,"renew_timeout_secs":300}' >/dev/null \
    && echo "  Certbot config set" || echo "  WARN: failed to set certbot config"

  # Create DNS credential if CF_API_TOKEN is provided and no credentials exist yet
  if [ -n "$CF_API_TOKEN" ]; then
    existing=$(curl -sf "http://$admin_addr/prpc/ListDnsCredentials" 2>/dev/null)
    cred_count=$(echo "$existing" | jq -r '.credentials | length' 2>/dev/null || echo "0")

    if [ "$cred_count" = "0" ]; then
      echo "Creating default DNS credential..."
      curl -sf -X POST "http://$admin_addr/prpc/CreateDnsCredential" \
        -H "Content-Type: application/json" \
        -d '{"name":"cloudflare","provider_type":"cloudflare","cf_api_token":"'"$CF_API_TOKEN"'","set_as_default":true}' >/dev/null \
        && echo "  DNS credential created" || echo "  WARN: failed to create DNS credential"
    else
      echo "  DNS credentials already exist ($cred_count), skipping"
    fi
  fi

  # Add ZT-Domain if SRV_DOMAIN is provided and domain doesn't exist yet
  if [ -n "$SRV_DOMAIN" ]; then
    existing=$(curl -sf "http://$admin_addr/prpc/ListZtDomains" 2>/dev/null)
    has_domain=$(echo "$existing" | jq -r '.domains[]? | select(.domain=="'"$SRV_DOMAIN"'") | .domain' 2>/dev/null)

    if [ -z "$has_domain" ]; then
      echo "Adding ZT-Domain: $SRV_DOMAIN..."
      curl -sf -X POST "http://$admin_addr/prpc/AddZtDomain" \
        -H "Content-Type: application/json" \
        -d '{"domain":"'"$SRV_DOMAIN"'","port":443,"priority":100}' >/dev/null \
        && echo "  ZT-Domain added" || echo "  WARN: failed to add ZT-Domain"
    else
      echo "  ZT-Domain $SRV_DOMAIN already exists, skipping"
    fi
  fi

  echo "Bootstrap complete"
  echo "Gateway Web UI: http://$admin_addr"
}

bootstrap_admin
