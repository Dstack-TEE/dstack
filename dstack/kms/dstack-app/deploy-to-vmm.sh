#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
# SPDX-FileCopyrightText: © 2025 Test in Prod <contact@testinprod.io>
#
# SPDX-License-Identifier: Apache-2.0

set -e

# Write rpc.json with the given endpoint unless the file exists.
init_rpc_json() {
  [ -f rpc.json ] || jq -n --arg url "$1" '{quorum: "1/1", endpoints: [$url], keys: {}}' >rpc.json
}

# Check if .env exists
if [ -f ".env" ]; then
  # Load variables from .env
  echo "Loading environment variables from .env file..."
  set -a
  # shellcheck source=/dev/null
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

# Optional: the address of the KMS admin listener on the Host machine, which
# other KMS nodes onboard from with ADMIN_TOKEN; firewall it to KMS nodes only
# KMS_ADMIN_ADDR=127.0.0.1:9203

# The address of the guest agent service listening on Host machine
# GUEST_AGENT_ADDR=127.0.0.1:9205

# The URL of the dstack app image download URL
# IMAGE_DOWNLOAD_URL=https://download.dstack.org/os-images/mr_{OS_IMAGE_HASH}.tar.gz

# rpc.json lists the Ethereum RPC endpoints and how many of them must answer
# every read alike, as n/m. All of it is measured and public. Write an API key
# as \${NAME} in an endpoint, give NAME an allowed_envs spec under keys, and set
# its value here: values reach the CVM through its unmeasured user config and
# stay out of the measurement. For example:
#   {
#     "quorum": "2/3",
#     "endpoints": [
#       "https://eth-mainnet.g.alchemy.com/v2/\${ALCHEMY_KEY}",
#       "https://mainnet.infura.io/v3/\${INFURA_KEY}",
#       "https://ethereum-rpc.publicnode.com"
#     ],
#     "keys": {
#       "ALCHEMY_KEY": "/[A-Za-z0-9_-]{32}/",
#       "INFURA_KEY": "/[0-9a-f]{32}/"
#     }
#   }
# A spec must keep its key to one URL path segment, so that the key cannot
# change an endpoint or add one. Keys need dstack OS 0.6.7 or later.
# ALCHEMY_KEY=
# INFURA_KEY=

# The block the auth-api reads policy at: latest, safe or finalized (default).
# Use finalized on L1; an OP-stack chain read through Helios requires latest.
# ETH_BLOCK_TAG=finalized

# Reject decisions if the RPC reports a different chain ID (empty: no check).
# ETH_CHAIN_ID=

# Read this many blocks behind the block ETH_BLOCK_TAG resolves to (default: 0).
# ETH_FINALITY_CONFIRMATIONS=0

# Reject decisions if the block read is older than this many seconds (empty: no
# check). Required when rpc.json lists more than one endpoint; leave room for
# ETH_BLOCK_TAG, as finalized on Ethereum mainnet is about 13 minutes old.
# ETH_MAX_BLOCK_AGE=

# Delegate app authorization to this service instead of the on-chain app
# contract (empty: app policy stays on chain).
# APP_AUTH_URL=

# The Git repository to deploy
GIT_REPOSITORY=https://github.com/Dstack-TEE/dstack.git

# The Git revision to deploy
GIT_REV=HEAD

# The dstack OS image name to use for the KMS app
OS_IMAGE=dstack-0.5.5

# The dstack KMS image name to use for the KMS app
KMS_IMAGE=dstacktee/dstack-kms@sha256:11ac59f524a22462ccd2152219b0bec48a28ceb734e32500152d4abefab7a62a

# The admin token for the KMS app
ADMIN_TOKEN=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 32 | head -n 1)
EOF
  init_rpc_json https://rpc.phala.network
  echo "Please edit the .env file and set the required variables, then run this script again."
  exit 1
fi

# An .env that predates rpc.json names its one endpoint in ETH_RPC_URL.
init_rpc_json "${ETH_RPC_URL:-https://rpc.phala.network}"
if [ -n "${ETH_RPC_URL:-}" ] && ! jq -e --arg url "$ETH_RPC_URL" '.endpoints == [$url]' rpc.json >/dev/null; then
  echo "Warning: ETH_RPC_URL in .env is ignored, as rpc.json names the RPC endpoints."
fi
if ! UNDECLARED=$(jq -r '[.endpoints[] | scan("\\$\\{(\\w+)\\}")[]] - (.keys | keys) | join(" ")' rpc.json); then
  echo "Error: rpc.json is invalid."
  exit 1
fi
if [ -n "$UNDECLARED" ]; then
  echo "Error: rpc.json gives no spec under keys for: $UNDECLARED"
  exit 1
fi
if [ -z "${ETH_MAX_BLOCK_AGE:-}" ] && jq -e '.endpoints | length > 1' rpc.json >/dev/null; then
  echo "Error: set ETH_MAX_BLOCK_AGE in .env: the auth-api requires it with several RPC endpoints."
  exit 1
fi
mapfile -t RPC_KEYS < <(jq -r '.keys | keys[]' rpc.json)
mapfile -t ENV_SPECS < <(jq -r '.keys | to_entries[] | "--env-spec", "\(.key): \(.value)"' rpc.json)

required_env_vars=(
  "VMM_RPC"
  "KMS_RPC_ADDR"
  "AUTH_API_RPC_ADDR"
  "GUEST_AGENT_ADDR"
  "KMS_CONTRACT_ADDR"
  "IMAGE_DOWNLOAD_URL"
  "GIT_REPOSITORY"
  "${RPC_KEYS[@]}"
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

GIT_REV=$(git rev-parse "$GIT_REV")

# shellcheck disable=SC2034  # consumed via `subvar` into compose-*.yaml
ADMIN_TOKEN_HASH=$(echo -n "$ADMIN_TOKEN" | sha256sum | cut -d' ' -f1)

cp compose-dev.yaml "$COMPOSE_TMP"

subvar() {
  sed -i "s|\${$1}|${!1}|g" "$COMPOSE_TMP"
}

ETH_BLOCK_TAG=${ETH_BLOCK_TAG:-finalized}
ETH_CHAIN_ID=${ETH_CHAIN_ID:-}
ETH_FINALITY_CONFIRMATIONS=${ETH_FINALITY_CONFIRMATIONS:-0}
ETH_MAX_BLOCK_AGE=${ETH_MAX_BLOCK_AGE:-}
APP_AUTH_URL=${APP_AUTH_URL:-}
# One endpoint per line of the block scalar in compose-dev.yaml.
# shellcheck disable=SC2034  # consumed via `subvar` into compose-*.yaml
ETH_RPC_URLS=$(jq -r '.endpoints | join("\\n        ")' rpc.json)
# shellcheck disable=SC2034
ETH_RPC_QUORUM=$(jq -r .quorum rpc.json)
subvar ETH_RPC_URLS
subvar ETH_RPC_QUORUM
subvar ETH_BLOCK_TAG
subvar ETH_CHAIN_ID
subvar ETH_FINALITY_CONFIRMATIONS
subvar ETH_MAX_BLOCK_AGE
subvar APP_AUTH_URL
subvar KMS_CONTRACT_ADDR
subvar GIT_REV
subvar IMAGE_DOWNLOAD_URL
subvar ADMIN_TOKEN_HASH
subvar GIT_REPOSITORY
subvar KMS_IMAGE

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
  "${ENV_SPECS[@]}" \
  ${RPC_KEYS:+--init-script <(echo "dstack-util import-env ${RPC_KEYS[*]}")} \
  --output .app-compose.json

# Remove the temporary file as it is no longer needed
rm "$COMPOSE_TMP"

# The user config holds the keys under env, apart from the fields dstack
# defines. The import-env init script copies them into the env file and refuses
# one that breaks its allowed_envs spec. mktemp keeps the keys readable by this
# user only.
USER_CONFIG=$(mktemp)
trap 'rm -f "$USER_CONFIG"' EXIT
jq '{env: .keys | with_entries(.value = env[.key])}' rpc.json >"$USER_CONFIG"

echo "Deploying KMS to dstack-vmm..."

$CLI deploy \
  --name kms \
  --compose .app-compose.json \
  --image "$OS_IMAGE" \
  --port tcp:"$KMS_RPC_ADDR":8000 \
  ${KMS_ADMIN_ADDR:+--port "tcp:$KMS_ADMIN_ADDR:8002"} \
  --port tcp:"$AUTH_API_RPC_ADDR":8001 \
  --port tcp:"$GUEST_AGENT_ADDR":8090 \
  ${RPC_KEYS:+--user-config "$USER_CONFIG"} \
  --vcpu 8 \
  --memory 8G \
  --disk 50G
