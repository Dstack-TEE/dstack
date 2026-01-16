#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Script to run all tests against the local chain

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env.test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "🧪 Running test suite..."

# Check if environment file exists
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}❌ Error: Environment file not found at $ENV_FILE${NC}"
    echo -e "${YELLOW}Please run ./scripts/setup-local-chain.sh first${NC}"
    exit 1
fi

# Load environment variables
source "$ENV_FILE"

# Export for child processes
export ETH_RPC_URL
export KMS_CONTRACT_ADDR
export APP_IMPLEMENTATION

# Check if Anvil is running
if ! kill -0 $ANVIL_PID 2>/dev/null; then
    echo -e "${RED}❌ Error: Anvil is not running (PID: $ANVIL_PID)${NC}"
    echo -e "${YELLOW}Please run ./scripts/setup-local-chain.sh first${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Local chain is running${NC}"
echo "   KMS Contract: $KMS_CONTRACT_ADDR"
echo "   App Implementation: $APP_IMPLEMENTATION"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Build TypeScript
echo -e "${BLUE}🔨 Building TypeScript...${NC}"
npm run build

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Start API server
echo -e "${BLUE}🌐 Starting API server...${NC}"
npm run dev > "$PROJECT_ROOT/server-test.log" 2>&1 &
SERVER_PID=$!

# Wait for server to be ready
echo "⏳ Waiting for API server to start..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8000 > /dev/null 2>&1; then
        echo -e "${GREEN}✅ API server is ready!${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}❌ API server failed to start within 30 seconds${NC}"
        cat "$PROJECT_ROOT/server-test.log"
        exit 1
    fi
    sleep 1
done

# Run Jest unit tests
echo ""
echo -e "${BLUE}📋 Running Jest unit tests...${NC}"
npm test

# Run integration tests
echo ""
echo -e "${BLUE}🔗 Running integration tests...${NC}"

# Create and run integration test
cat > "$PROJECT_ROOT/integration-test.js" << 'EOF'
const { ethers } = require('ethers');

async function runIntegrationTests() {
    const baseUrl = 'http://127.0.0.1:8000';
    const rpcUrl = process.env.ETH_RPC_URL;
    const kmsAddress = process.env.KMS_CONTRACT_ADDR;
    
    console.log('Testing against:');
    console.log('  API URL:', baseUrl);
    console.log('  RPC URL:', rpcUrl);
    console.log('  KMS Contract:', kmsAddress);
    console.log('');
    
    const testData = {
        tcbStatus: 'UpToDate',
        advisoryIds: [],
        mrAggregated: '0x' + '1234567890abcdef'.repeat(4),
        osImageHash: '0x' + 'abcdefabcdefabcd'.repeat(4),
        mrSystem: '0x' + '9012901290129012'.repeat(4),
        appId: '0x9012345678901234567890123456789012345678',
        composeHash: '0x' + 'abcdabcdabcdabcd'.repeat(4),
        instanceId: '0x3456789012345678901234567890123456789012',
        deviceId: '0x' + 'ef12ef12ef12ef12'.repeat(4)
    };
    
    const tests = [
        {
            name: 'Health Check',
            run: async () => {
                const res = await fetch(baseUrl + '/');
                const data = await res.json();
                return { 
                    passed: res.status === 200 && data.kmsContractAddr === kmsAddress,
                    details: `Status: ${res.status}, Contract: ${data.kmsContractAddr}`
                };
            }
        },
        {
            name: 'App Authorization',
            run: async () => {
                const res = await fetch(baseUrl + '/bootAuth/app', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(testData)
                });
                const data = await res.json();
                return {
                    passed: res.status === 200 && data.hasOwnProperty('isAllowed'),
                    details: `Status: ${res.status}, Response: ${JSON.stringify(data)}`
                };
            }
        },
        {
            name: 'KMS Authorization',
            run: async () => {
                const res = await fetch(baseUrl + '/bootAuth/kms', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(testData)
                });
                const data = await res.json();
                return {
                    passed: res.status === 200 && data.hasOwnProperty('isAllowed'),
                    details: `Status: ${res.status}, Response: ${JSON.stringify(data)}`
                };
            }
        },
        {
            name: 'Invalid Request Validation',
            run: async () => {
                const res = await fetch(baseUrl + '/bootAuth/app', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mrAggregated: '0x1234' })
                });
                return {
                    passed: res.status === 400,
                    details: `Status: ${res.status} (expected 400)`
                };
            }
        },
        {
            name: 'Contract Interaction',
            run: async () => {
                const provider = new ethers.JsonRpcProvider(rpcUrl);
                const abi = ['function owner() view returns (address)'];
                const contract = new ethers.Contract(kmsAddress, abi, provider);
                const owner = await contract.owner();
                return {
                    passed: ethers.isAddress(owner),
                    details: `Owner: ${owner}`
                };
            }
        }
    ];
    
    let passed = 0;
    let failed = 0;
    
    for (const test of tests) {
        try {
            const result = await test.run();
            if (result.passed) {
                console.log(`✅ ${test.name}`);
                console.log(`   ${result.details}`);
                passed++;
            } else {
                console.log(`❌ ${test.name}`);
                console.log(`   ${result.details}`);
                failed++;
            }
        } catch (error) {
            console.log(`❌ ${test.name}`);
            console.log(`   Error: ${error.message}`);
            failed++;
        }
    }
    
    console.log('');
    console.log(`Summary: ${passed} passed, ${failed} failed`);
    
    return failed === 0;
}

runIntegrationTests().then(success => {
    process.exit(success ? 0 : 1);
}).catch(error => {
    console.error('Test runner error:', error);
    process.exit(1);
});
EOF

node "$PROJECT_ROOT/integration-test.js"
INTEGRATION_RESULT=$?

# Clean up integration test file
rm -f "$PROJECT_ROOT/integration-test.js"

# Run Foundry tests
echo ""
echo -e "${BLUE}🔨 Running Foundry tests...${NC}"
ETHERSCAN_API_KEY=dummy forge test --ffi --rpc-url $ETH_RPC_URL
FOUNDRY_RESULT=$?

# Summary
echo ""
echo "📊 Test Summary:"
echo "   Jest Tests: ${GREEN}✅ Passed${NC}"
if [ $INTEGRATION_RESULT -eq 0 ]; then
    echo "   Integration Tests: ${GREEN}✅ Passed${NC}"
else
    echo "   Integration Tests: ${RED}❌ Failed${NC}"
fi
if [ $FOUNDRY_RESULT -eq 0 ]; then
    echo "   Foundry Tests: ${GREEN}✅ Passed${NC}"
else
    echo "   Foundry Tests: ${RED}❌ Failed${NC}"
fi

# Exit with appropriate code
if [ $INTEGRATION_RESULT -ne 0 ] || [ $FOUNDRY_RESULT -ne 0 ]; then
    exit 1
fi

echo ""
echo -e "${GREEN}✅ All tests passed!${NC}"