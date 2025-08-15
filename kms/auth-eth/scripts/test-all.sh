#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Complete test runner - sets up chain and runs all tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🚀 Complete Test Suite"
echo "===================="
echo ""

# Setup local chain
echo "Step 1: Setting up local chain..."
"$SCRIPT_DIR/setup-local-chain.sh"

echo ""
echo "Step 2: Running tests..."
"$SCRIPT_DIR/run-tests.sh" "$@"

# Load env to get PID
source "$SCRIPT_DIR/../.env.test"

echo ""
echo -e "${GREEN}✅ Complete test suite finished!${NC}"
echo ""
echo -e "${YELLOW}ℹ️  To stop the local chain: kill $ANVIL_PID${NC}"
echo -e "${YELLOW}ℹ️  To run tests again: ./scripts/run-tests.sh${NC}"