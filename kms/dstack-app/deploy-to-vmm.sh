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
# Required environment variables for KMS deployment
# Please uncomment and set values for the following variables:

# The URL of the dstack-vmm RPC service used to deploy the KMS app
# VMM_RPC=unix:../../../build/vmm.sock

# The address of the KMS contract
# KMS_CONTRACT_ADDR=0x59E4a36B01a87fD9D1A4C12377253FE9a7b018Ba

# The address of the auth-api service listening on Host machine
# AUTH_API_RPC_ADDR=0.0.0.0:8001

# The address of the KMS service listening on Host machine
# KMS_RPC_ADDR=0.0.0.0:9201

# The address of the guest agent service listening on Host machine
# GUEST_AGENT_ADDR=127.0.0.1:9205

# The URL of the dstack app image download URL
# IMAGE_DOWNLOAD_URL=https://files.kvin.wang/images/mr_{OS_IMAGE_HASH}.tar.gz

# Image hash verification feature flag
VERIFY_IMAGE=true

# The URL of the Ethereum RPC service
ETH_RPC_URL=https://rpc.phala.network

# The Git repository to deploy
GIT_REPOSITORY=https://github.com/Dstack-TEE/dstack.git

# The Git revision to deploy
GIT_REV=HEAD

# The dstack OS image name to use for the KMS app
OS_IMAGE=dstack-0.5.0

# The admin token for the KMS app
ADMIN_TOKEN=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
EOF
  echo "Please edit the .env file and set the required variables, then run this script again."
  exit 1
fi

required_env_vars=(
  "VMM_RPC"
  "KMS_RPC_ADDR"
  "AUTH_API_RPC_ADDR"
  "GUEST_AGENT_ADDR"
  "KMS_CONTRACT_ADDR"
  "ETH_RPC_URL"
  "IMAGE_DOWNLOAD_URL"
  "VERIFY_IMAGE"
  "GIT_REPOSITORY"
)

for var in "${required_env_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Error: Required environment variable $var is not set."
    echo "Please edit the .env file and set a value for $var, then run this script again."
    exit 1
  fi
done

CLI="../../vmm/src/vmm-cli.py --url $VMM_RPC"

COMPOSE_TMP=$(mktemp)

GIT_REV=$(git rev-parse $GIT_REV)

ADMIN_TOKEN_HASH=$(echo -n $ADMIN_TOKEN | sha256sum | cut -d' ' -f1)

cp compose-dev.yaml "$COMPOSE_TMP"

subvar() {
  sed -i "s|\${$1}|${!1}|g" "$COMPOSE_TMP"
}

subvar ETH_RPC_URL
subvar KMS_CONTRACT_ADDR
subvar GIT_REV
subvar IMAGE_DOWNLOAD_URL
subvar ADMIN_TOKEN_HASH
subvar VERIFY_IMAGE
subvar GIT_REPOSITORY

echo "Docker compose file:"
cat "$COMPOSE_TMP"

if [ -t 0 ]; then
  # Only ask for confirmation if running in an interactive terminal
  read -p "Continue? [y/N] " -n 1 -r
  echo

  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 1
  fi
fi

$CLI compose \
  --docker-compose "$COMPOSE_TMP" \
  --name kms \
  --local-key-provider \
  --public-logs \
  --public-sysinfo \
  --secure-time \
  --no-instance-id \
  --output .app-compose.json

# Remove the temporary file as it is no longer needed
rm "$COMPOSE_TMP"

echo "Deploying KMS to dstack-vmm..."

$CLI deploy \
  --name kms \
  --compose .app-compose.json \
  --image $OS_IMAGE \
  --port tcp:$KMS_RPC_ADDR:8000 \
  --port tcp:$AUTH_API_RPC_ADDR:8001 \
  --port tcp:$GUEST_AGENT_ADDR:8090 \
  --vcpu 8 \
  --memory 8G \
  --disk 50G
