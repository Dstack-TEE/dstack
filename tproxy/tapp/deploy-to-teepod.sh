#!/bin/bash

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
# Required environment variables for Tproxy deployment
# Please uncomment and set values for the following variables:

# The URL of the TEEPOD RPC service
# TEEPOD_RPC=unix:../../../build/teepod.sock

# Cloudflare API token for DNS challenge
# CF_API_TOKEN=your_cloudflare_api_token

# Cloudflare Zone ID
# CF_ZONE_ID=your_zone_id

# Service domain
# SRV_DOMAIN=test5.dstack.phala.network

# Public IP address
PUBLIC_IP=$(curl -s4 ifconfig.me)

# Tproxy application ID. Register the app in KmsAuth first to get the app ID.
# TPROXY_APP_ID=31884c4b7775affe4c99735f6c2aff7d7bc6cfcd

# Whether to use ACME staging (yes/no)
ACME_STAGING=yes

# Subnet index. 0~15
SUBNET_INDEX=0

# My URL
# MY_URL=https://tproxy.test5.dstack.phala.network:9202

# Bootnode URL
# BOOTNODE_URL=https://tproxy.test2.dstack.phala.network:9202

# DStack OS image name
OS_IMAGE=dstack-0.4.0

# Set defaults for variables that might not be in .env
GIT_REV=HEAD

# Port configurations
TPROXY_RPC_ADDR=0.0.0.0:9202
TPROXY_ADMIN_RPC_ADDR=127.0.0.1:9203
TPROXY_SERVING_ADDR=0.0.0.0:9204
TAPPD_ADDR=127.0.0.1:9206
WG_ADDR=0.0.0.0:9202

EOF
  echo "Please edit the .env file and set the required variables, then run this script again."
  exit 1
fi

# Define required environment variables
required_env_vars=(
  "TEEPOD_RPC"
  "CF_API_TOKEN"
  "CF_ZONE_ID"
  "SRV_DOMAIN"
  "PUBLIC_IP"
  "WG_ADDR"
  "TPROXY_APP_ID"
  "MY_URL"
  "BOOTNODE_URL"
)

# Validate required environment variables
for var in "${required_env_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Error: Required environment variable $var is not set."
    echo "Please edit the .env file and set a value for $var, then run this script again."
    exit 1
  fi
done

CLI="../../teepod/src/teepod-cli.py --url $TEEPOD_RPC"

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
EOF

$CLI compose \
  --docker-compose "$COMPOSE_TMP" \
  --name tproxy \
  --kms \
  --env-file .app_env \
  --public-logs \
  --public-sysinfo \
  --no-instance-id \
  --output .app-compose.json

# Remove the temporary file as it is no longer needed
rm "$COMPOSE_TMP"

echo "Configuration:"
echo "TEEPOD_RPC: $TEEPOD_RPC"
echo "SRV_DOMAIN: $SRV_DOMAIN"
echo "PUBLIC_IP: $PUBLIC_IP"
echo "TPROXY_APP_ID: $TPROXY_APP_ID"
echo "MY_URL: $MY_URL"
echo "BOOTNODE_URL: $BOOTNODE_URL"
echo "SUBNET_INDEX: $SUBNET_INDEX"
echo "WG_ADDR: $WG_ADDR"
echo "TPROXY_RPC_ADDR: $TPROXY_RPC_ADDR"
echo "TPROXY_ADMIN_RPC_ADDR: $TPROXY_ADMIN_RPC_ADDR"
echo "TPROXY_SERVING_ADDR: $TPROXY_SERVING_ADDR"
echo "TAPPD_ADDR: $TAPPD_ADDR"

if [ -t 0 ]; then
  # Only ask for confirmation if running in an interactive terminal
  read -p "Continue? [y/N] " -n 1 -r
  echo

  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 1
  fi
fi

echo "Deploying Tproxy to Teepod..."

$CLI deploy \
  --name tproxy \
  --app-id "$TPROXY_APP_ID" \
  --compose .app-compose.json \
  --env-file .app_env \
  --image $OS_IMAGE \
  --port tcp:$TPROXY_RPC_ADDR:8000 \
  --port tcp:$TPROXY_ADMIN_RPC_ADDR:8001 \
  --port tcp:$TPROXY_SERVING_ADDR:443 \
  --port tcp:$TAPPD_ADDR:8090 \
  --port udp:$WG_ADDR:51820 \
  --vcpu 8 \
  --memory 8G \

