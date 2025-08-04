#!/bin/bash
# Script to set up local Anvil chain and deploy contracts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env.test"

echo "🔧 Setting up local test environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if anvil is available
if ! command -v anvil &> /dev/null; then
    echo -e "${RED}❌ Error: anvil not found. Install Foundry first:${NC}"
    echo "curl -L https://foundry.paradigm.xyz | bash"
    echo "foundryup"
    exit 1
fi

# Clean up any existing Anvil process
echo "🧹 Cleaning up existing Anvil processes..."
pkill -f "anvil" || true
sleep 1

# Start Anvil in the background
echo "🚀 Starting Anvil local node..."
anvil \
    --host 0.0.0.0 \
    --port 8545 \
    --accounts 10 \
    --balance 1000 \
    --block-time 1 \
    > "$PROJECT_ROOT/anvil.log" 2>&1 &

ANVIL_PID=$!
echo "   Anvil PID: $ANVIL_PID"

# Wait for Anvil to be ready
echo "⏳ Waiting for Anvil to start..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8545 > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Anvil is ready!${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}❌ Anvil failed to start within 30 seconds${NC}"
        cat "$PROJECT_ROOT/anvil.log"
        exit 1
    fi
    sleep 1
done

# Deploy contracts
echo "📦 Deploying contracts..."
cd "$PROJECT_ROOT"

# Use the first Anvil account private key
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Run deployment and capture output
DEPLOY_OUTPUT=$(PRIVATE_KEY=$PRIVATE_KEY \
    ETHERSCAN_API_KEY=dummy \
    forge script script/Deploy.s.sol:DeployScript \
    --broadcast \
    --rpc-url http://127.0.0.1:8545 \
    -vvv 2>&1)

echo "$DEPLOY_OUTPUT" > "$PROJECT_ROOT/deploy.log"

# Extract contract addresses
KMS_PROXY=$(echo "$DEPLOY_OUTPUT" | grep "DstackKms proxy deployed to:" | awk '{print $NF}')
APP_IMPL=$(echo "$DEPLOY_OUTPUT" | grep "DstackApp implementation deployed to:" | awk '{print $NF}')
KMS_IMPL=$(echo "$DEPLOY_OUTPUT" | grep "DstackKms implementation deployed to:" | awk '{print $NF}')

if [ -z "$KMS_PROXY" ] || [ -z "$APP_IMPL" ]; then
    echo -e "${RED}❌ Failed to extract contract addresses from deployment${NC}"
    echo "Check deploy.log for details"
    kill $ANVIL_PID 2>/dev/null
    exit 1
fi

# Save environment variables
cat > "$ENV_FILE" << EOF
# Auto-generated test environment configuration
# Generated at: $(date)

# Anvil Configuration
ANVIL_PID=$ANVIL_PID
ETH_RPC_URL=http://127.0.0.1:8545
CHAIN_ID=31337

# Deployed Contracts
KMS_CONTRACT_ADDR=$KMS_PROXY
APP_IMPLEMENTATION=$APP_IMPL
KMS_IMPLEMENTATION=$KMS_IMPL

# Test Account (Anvil account #0)
DEPLOYER_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
DEPLOYER_PRIVATE_KEY=$PRIVATE_KEY
EOF

echo -e "${GREEN}✅ Local chain setup complete!${NC}"
echo ""
echo "📊 Deployment Summary:"
echo "   Chain ID: 31337"
echo "   RPC URL: http://127.0.0.1:8545"
echo "   KMS Proxy: $KMS_PROXY"
echo "   App Implementation: $APP_IMPL"
echo ""
echo "📄 Configuration saved to: $ENV_FILE"
echo ""
echo "🔍 Logs available at:"
echo "   Anvil: $PROJECT_ROOT/anvil.log"
echo "   Deploy: $PROJECT_ROOT/deploy.log"
echo ""
echo -e "${YELLOW}ℹ️  To stop Anvil: kill $ANVIL_PID${NC}"
echo -e "${YELLOW}ℹ️  To run tests: ./scripts/run-tests.sh${NC}"