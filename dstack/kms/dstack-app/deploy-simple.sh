#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Deploy KMS with external auth-simple webhook
# auth-simple runs outside the CVM (operator infrastructure)

set -e

# Check if .env.simple exists
if [ -f ".env.simple" ]; then
  echo "Loading environment variables from .env.simple file..."
  set -a
  source .env.simple
  set +a
else
  # Create a template .env.simple file
  echo "Creating template .env.simple file..."
  cat >.env.simple <<EOF
# Environment variables for KMS deployment with auth-simple
# auth-simple runs OUTSIDE the CVM on operator infrastructure

# Required: The URL of the dstack-vmm RPC service
# VMM_RPC=unix:../../../build/vmm.sock

# Required: External auth-simple webhook URL (running on operator infrastructure)
# AUTH_WEBHOOK_URL=http://your-auth-server:3001

# Required: The address of the KMS service listening on Host machine
# KMS_RPC_ADDR=0.0.0.0:9201

# Required: The address of the guest agent service listening on Host machine
# GUEST_AGENT_ADDR=127.0.0.1:9205

# Required: The URL of the dstack app image download URL
# IMAGE_DOWNLOAD_URL=https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.5/dstack-0.5.5.tar.gz

# Image hash verification feature flag
VERIFY_IMAGE=true

# The dstack OS image name to use for the KMS app
OS_IMAGE=dstack-0.5.5

# The dstack KMS image name to use for the KMS app
KMS_IMAGE=dstacktee/dstack-kms@sha256:11ac59f524a22462ccd2152219b0bec48a28ceb734e32500152d4abefab7a62a

# The admin token for the KMS app (auto-generated)
ADMIN_TOKEN=\$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
EOF
  echo "Please edit .env.simple and set the required variables, then run this script again."
  exit 1
fi

required_env_vars=(
  "VMM_RPC"
  "AUTH_WEBHOOK_URL"
  "KMS_RPC_ADDR"
  "GUEST_AGENT_ADDR"
  "IMAGE_DOWNLOAD_URL"
  "VERIFY_IMAGE"
)

for var in "${required_env_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Error: Required environment variable $var is not set."
    echo "Please edit .env.simple and set a value for $var, then run this script again."
    exit 1
  fi
done

CLI="../../vmm/src/vmm-cli.py --url $VMM_RPC"

COMPOSE_TMP=$(mktemp)

ADMIN_TOKEN_HASH=$(echo -n $ADMIN_TOKEN | sha256sum | cut -d' ' -f1)

cp compose-simple.yaml "$COMPOSE_TMP"

subvar() {
  sed -i "s|\${$1}|${!1}|g" "$COMPOSE_TMP"
}

subvar AUTH_WEBHOOK_URL
subvar IMAGE_DOWNLOAD_URL
subvar ADMIN_TOKEN_HASH
subvar VERIFY_IMAGE
subvar KMS_IMAGE

echo "Docker compose file:"
cat "$COMPOSE_TMP"

echo ""
echo "Configuration:"
echo "  AUTH_WEBHOOK_URL: $AUTH_WEBHOOK_URL"
echo "  KMS_RPC_ADDR: $KMS_RPC_ADDR"
echo "  OS_IMAGE: $OS_IMAGE"
echo ""

if [ -t 0 ]; then
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

rm "$COMPOSE_TMP"

echo "Deploying KMS to dstack-vmm..."

$CLI deploy \
  --name kms \
  --compose .app-compose.json \
  --image $OS_IMAGE \
  --port tcp:$KMS_RPC_ADDR:8000 \
  --port tcp:$GUEST_AGENT_ADDR:8090 \
  --vcpu 8 \
  --memory 8G \
  --disk 50G

echo ""
echo "KMS deployed successfully!"
echo ""
echo "Next steps:"
echo "1. Open http://127.0.0.1:${KMS_RPC_ADDR##*:}/ in your browser"
echo "2. Bootstrap the KMS with your domain"
echo "3. Add the KMS mrAggregated to your auth-simple config"
