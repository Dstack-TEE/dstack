#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Deploy KMS with an external dstack-auth webhook.
# dstack-auth runs outside the CVM, on the operator host. Start it first:
#   cargo build --release -p dstack-auth
#   dstack-auth --config auth-config.json --port 3001
# See docs/dstack-auth-operations.md.

set -e

# Check if .env.simple exists
if [ -f ".env.simple" ]; then
  echo "Loading environment variables from .env.simple file..."
  set -a
  # shellcheck source=/dev/null
  source .env.simple
  set +a
else
  # Create a template .env.simple file
  echo "Creating template .env.simple file..."
  cat >.env.simple <<EOF
# Environment variables for KMS deployment with dstack-auth
# dstack-auth runs OUTSIDE the CVM on the operator host

# Required: The URL of the dstack-vmm RPC service
# VMM_RPC=unix:../../../build/vmm.sock

# Required: dstack-auth webhook URL as seen from inside the CVM. With QEMU
# user-mode networking the host is 10.0.2.2; dstack-auth's default
# 127.0.0.1 bind is reachable there.
# AUTH_WEBHOOK_URL=http://10.0.2.2:3001

# Required: The address of the KMS service listening on Host machine
# KMS_RPC_ADDR=0.0.0.0:9201

# Optional: the address of the KMS admin listener on the Host machine, which
# other KMS nodes onboard from with ADMIN_TOKEN; firewall it to KMS nodes only
# KMS_ADMIN_ADDR=127.0.0.1:9203

# Required: The address of the guest agent service listening on Host machine
# GUEST_AGENT_ADDR=127.0.0.1:9205

# Required: The URL of the dstack app image download URL
# IMAGE_DOWNLOAD_URL=https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.5/dstack-0.5.5.tar.gz

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
)

for var in "${required_env_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Error: Required environment variable $var is not set."
    echo "Please edit .env.simple and set a value for $var, then run this script again."
    exit 1
  fi
done

CLI=(../../vmm/src/vmm-cli.py --url "$VMM_RPC")

COMPOSE_TMP=$(mktemp)

# Used indirectly by subvar.
# shellcheck disable=SC2034
ADMIN_TOKEN_HASH=$(printf '%s' "$ADMIN_TOKEN" | sha256sum | cut -d' ' -f1)

cp compose-simple.yaml "$COMPOSE_TMP"

subvar() {
  sed -i "s|\${$1}|${!1}|g" "$COMPOSE_TMP"
}

subvar AUTH_WEBHOOK_URL
subvar IMAGE_DOWNLOAD_URL
subvar ADMIN_TOKEN_HASH
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
  read -r -p "Continue? [y/N] " -n 1
  echo

  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 1
  fi
fi

"${CLI[@]}" compose \
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

"${CLI[@]}" deploy \
  --name kms \
  --compose .app-compose.json \
  --image "$OS_IMAGE" \
  --port "tcp:$KMS_RPC_ADDR:8000" \
  ${KMS_ADMIN_ADDR:+--port "tcp:$KMS_ADMIN_ADDR:8002"} \
  --port "tcp:$GUEST_AGENT_ADDR:8090" \
  --vcpu 8 \
  --memory 8G \
  --disk 50G

echo ""
echo "KMS deployed successfully!"
echo ""
echo "Next steps:"
echo "1. Open http://127.0.0.1:${KMS_RPC_ADDR##*:}/ in your browser"
echo "2. Add the KMS mrAggregated (Onboard.GetAttestationInfo) to your dstack-auth config"
echo "3. Bootstrap the KMS with your domain"
