#!/bin/bash
# Cleanup script to stop all test processes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env.test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🧹 Cleaning up test environment..."

# Kill any running API servers
echo "Stopping API servers..."
pkill -f "ts-node src/main.ts" || true
pkill -f "node dist/main.js" || true

# Load environment if exists
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
    
    # Kill Anvil if PID is set
    if [ ! -z "$ANVIL_PID" ]; then
        echo "Stopping Anvil (PID: $ANVIL_PID)..."
        kill $ANVIL_PID 2>/dev/null || true
    fi
fi

# Kill any other Anvil processes
echo "Stopping any other Anvil processes..."
pkill -f "anvil" || true

# Clean up files
echo "Removing temporary files..."
rm -f "$PROJECT_ROOT/.env.test"
rm -f "$PROJECT_ROOT/anvil.log"
rm -f "$PROJECT_ROOT/deploy.log"
rm -f "$PROJECT_ROOT/server-test.log"
rm -f "$PROJECT_ROOT/integration-test.js"

echo -e "${GREEN}✅ Cleanup complete!${NC}"