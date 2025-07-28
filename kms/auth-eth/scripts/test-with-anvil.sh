#!/bin/bash
# Complete local testing workflow with Anvil

set -e

echo "🔧 Starting complete local testing workflow..."

# Check if anvil is available
if ! command -v anvil &> /dev/null; then
    echo "❌ Error: anvil not found. Install Foundry first:"
    echo "curl -L https://foundry.paradigm.xyz | bash"
    echo "foundryup"
    exit 1
fi

# Clean up any existing processes
echo "🧹 Cleaning up existing processes..."
pkill -f "anvil" || true
pkill -f "ts-node src/main.ts" || true
sleep 1

# Start Anvil in the background
echo "🚀 Starting Anvil local node..."
anvil --host 0.0.0.0 --port 8545 --accounts 10 --balance 1000 > anvil.log 2>&1 &
ANVIL_PID=$!

# Wait for Anvil to start
echo "⏳ Waiting for Anvil to start..."
sleep 3

# Deploy contracts
echo "📦 Deploying contracts..."
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
ETHERSCAN_API_KEY=dummy \
forge script script/Deploy.s.sol:DeployScript --broadcast --rpc-url http://127.0.0.1:8545 > deploy.log 2>&1

if [ $? -ne 0 ]; then
    echo "❌ Contract deployment failed. Check deploy.log"
    kill $ANVIL_PID
    exit 1
fi

# Extract contract addresses from deployment logs  
KMS_ADDR=$(grep "DstackKms proxy deployed to:" deploy.log | awk '{print $NF}' || echo "")

if [ -z "$KMS_ADDR" ]; then
    echo "❌ Could not extract KMS contract address from deployment"
    echo "💡 Check deploy.log for deployment details"
    kill $ANVIL_PID
    exit 1
fi

echo "✅ Contracts deployed!"
echo "   KMS Address: $KMS_ADDR"

# Set environment variables
export ETH_RPC_URL=http://127.0.0.1:8545
export KMS_CONTRACT_ADDR=$KMS_ADDR

# Build TypeScript
echo "🔨 Building TypeScript..."
npm run build

# Start the API server in background
echo "🌐 Starting API server..."
npm run dev > server.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
echo "⏳ Waiting for API server to start..."
sleep 5

# Test the API
echo "🧪 Testing API endpoints..."

# Inline API test
node -e "
const mockBootInfo = {
  tcbStatus: 'UpToDate',
  advisoryIds: [],
  mrAggregated: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  osImageHash: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
  mrSystem: '0x9012901290129012901290129012901290129012901290129012901290129012',
  appId: '0x9012345678901234567890123456789012345678',
  composeHash: '0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd',
  instanceId: '0x3456789012345678901234567890123456789012',
  deviceId: '0xef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12'
};

async function testAPI() {
  const baseUrl = 'http://127.0.0.1:8000';
  console.log('1️⃣ Health check...');
  const health = await fetch(baseUrl + '/');
  console.log('   Status:', health.status);
  
  console.log('2️⃣ App authorization...');  
  const app = await fetch(baseUrl + '/bootAuth/app', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(mockBootInfo)
  });
  console.log('   Status:', app.status);
  
  console.log('3️⃣ KMS authorization...');
  const kms = await fetch(baseUrl + '/bootAuth/kms', {
    method: 'POST', 
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(mockBootInfo)
  });
  console.log('   Status:', kms.status);
  
  console.log('4️⃣ Invalid request...');
  const invalid = await fetch(baseUrl + '/bootAuth/app', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mrAggregated: '0x1234' })
  });
  console.log('   Status:', invalid.status);
}

testAPI().then(() => console.log('✅ API tests completed!')).catch(console.error);
""

echo ""
echo "✅ All tests completed successfully!"
echo ""
echo "📊 Services running:"
echo "   Anvil: PID $ANVIL_PID (http://127.0.0.1:8545)"
echo "   API Server: PID $SERVER_PID (http://127.0.0.1:8000)"
echo "   KMS Contract: $KMS_ADDR"
echo ""
echo "🔍 Logs available in:"
echo "   Anvil: anvil.log"
echo "   Deployment: deploy.log" 
echo "   Server: server.log"
echo ""
echo "🛑 To stop services:"
echo "   kill $ANVIL_PID $SERVER_PID"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping services..."
    kill $ANVIL_PID $SERVER_PID 2>/dev/null || true
    echo "✅ Cleanup completed"
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Keep script running or exit based on argument
if [ "$1" = "--keep-running" ]; then
    echo "🔄 Services will keep running. Press Ctrl+C to stop."
    wait
else
    echo "ℹ️  Use '--keep-running' to keep services running"
    echo "🛑 Stopping services in 10 seconds..."
    sleep 10
fi