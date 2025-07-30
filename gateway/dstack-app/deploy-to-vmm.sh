#!/bin/bash

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

# Cloudflare Zone ID
# CF_ZONE_ID=your_zone_id

# Service domain
# SRV_DOMAIN=test5.dstack.phala.network

# Public IP address
PUBLIC_IP=$(curl -s4 ifconfig.me)

# The dstack-gateway application ID. Register the app in DstackKms first to get the app ID.
# GATEWAY_APP_ID=31884c4b7775affe4c99735f6c2aff7d7bc6cfcd

# Whether to use ACME staging (yes/no)
ACME_STAGING=yes

# Subnet index. 0~15
SUBNET_INDEX=0

# My URL
# MY_URL=https://gateway.test5.dstack.phala.network:9202

# Bootnode URL
# BOOTNODE_URL=https://gateway.test2.dstack.phala.network:9202

# dstack OS image name
OS_IMAGE=dstack-0.5.0

# Set defaults for variables that might not be in .env
GIT_REV=HEAD

# Port configurations
GATEWAY_RPC_ADDR=0.0.0.0:9202
GATEWAY_ADMIN_RPC_ADDR=127.0.0.1:9203
GATEWAY_SERVING_ADDR=0.0.0.0:9204
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
  "CF_ZONE_ID"
  "SRV_DOMAIN"
  "PUBLIC_IP"
  "WG_ADDR"
  "GATEWAY_APP_ID"
  "MY_URL"
  "APP_LAUNCH_TOKEN"
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

GIT_REV=$(git rev-parse $GIT_REV)

cp docker-compose.yaml "$COMPOSE_TMP"

subvar() {
  sed -i "s|\${$1}|${!1}|g" "$COMPOSE_TMP"
}

subvar GIT_REV
subvar ACME_STAGING

echo "Docker compose file:"
cat "$COMPOSE_TMP"

# Update .env file with current values
cat <<EOF >.app_env
CF_API_TOKEN=$CF_API_TOKEN
CF_ZONE_ID=$CF_ZONE_ID
SRV_DOMAIN=$SRV_DOMAIN
WG_ENDPOINT=$PUBLIC_IP:$WG_PORT
MY_URL=$MY_URL
BOOTNODE_URL=$BOOTNODE_URL
SUBNET_INDEX=$SUBNET_INDEX
APP_LAUNCH_TOKEN=$APP_LAUNCH_TOKEN
RPC_DOMAIN=$RPC_DOMAIN
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
    --prelaunch-script .prelaunch.sh \
    --output .app-compose.json
fi

# Set launch_token_hash in app-compose.json
mv .app-compose.json .app-compose.json.tmp
jq \
  --arg token_hash "$EXPECTED_TOKEN_HASH" \
  '.launch_token_hash = $token_hash' \
  .app-compose.json.tmp > .app-compose.json

# Remove the temporary file as it is no longer needed
rm "$COMPOSE_TMP"

echo "Configuration:"
echo "VMM_RPC: $VMM_RPC"
echo "SRV_DOMAIN: $SRV_DOMAIN"
echo "PUBLIC_IP: $PUBLIC_IP"
echo "GATEWAY_APP_ID: $GATEWAY_APP_ID"
echo "MY_URL: $MY_URL"
echo "BOOTNODE_URL: $BOOTNODE_URL"
echo "SUBNET_INDEX: $SUBNET_INDEX"
echo "WG_ADDR: $WG_ADDR"
echo "GATEWAY_RPC_ADDR: $GATEWAY_RPC_ADDR"
echo "GATEWAY_ADMIN_RPC_ADDR: $GATEWAY_ADMIN_RPC_ADDR"
echo "GATEWAY_SERVING_ADDR: $GATEWAY_SERVING_ADDR"
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

$CLI deploy \
  --name dstack-gateway \
  --app-id "$GATEWAY_APP_ID" \
  --compose .app-compose.json \
  --env-file .app_env \
  --image $OS_IMAGE \
  --port tcp:$GATEWAY_RPC_ADDR:8000 \
  --port tcp:$GATEWAY_ADMIN_RPC_ADDR:8001 \
  --port tcp:$GATEWAY_SERVING_ADDR:443 \
  --port tcp:$GUEST_AGENT_ADDR:8090 \
  --port udp:$WG_ADDR:51820 \
  --vcpu 32 \
  --memory 32G \

