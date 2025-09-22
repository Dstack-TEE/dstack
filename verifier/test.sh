#!/bin/bash

# SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_ROOT/target/debug/dstack-verifier"
LOG_FILE="/tmp/verifier-test.log"
FIXTURE_FILE="$SCRIPT_DIR/fixtures/quote-report.json"

echo -e "${YELLOW}dstack-verifier Test Script${NC}"
echo "=================================="

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    pkill -f dstack-verifier 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

# Build the project
echo -e "${YELLOW}Building dstack-verifier...${NC}"
cd "$PROJECT_ROOT"
cargo build --bin dstack-verifier --quiet

if [ ! -f "$BINARY" ]; then
    echo -e "${RED}Error: Binary not found at $BINARY${NC}"
    exit 1
fi

# Start the server
echo -e "${YELLOW}Starting dstack-verifier server...${NC}"
"$BINARY" >"$LOG_FILE" 2>&1 &
SERVER_PID=$!

# Wait for server to start
echo -e "${YELLOW}Waiting for server to start...${NC}"
for i in {1..10}; do
    if curl -s http://localhost:8080/health >/dev/null 2>&1; then
        echo -e "${GREEN}Server started successfully${NC}"
        break
    fi
    if [ $i -eq 10 ]; then
        echo -e "${RED}Server failed to start${NC}"
        echo "Server logs:"
        cat "$LOG_FILE"
        exit 1
    fi
    sleep 1
done

# Check if fixture file exists
if [ ! -f "$FIXTURE_FILE" ]; then
    echo -e "${RED}Error: Fixture file not found at $FIXTURE_FILE${NC}"
    exit 1
fi

# Run the verification test
echo -e "${YELLOW}Running verification test...${NC}"
echo "Using fixture: $FIXTURE_FILE"

RESPONSE=$(curl -s -X POST http://localhost:8080/verify \
    -H "Content-Type: application/json" \
    -d @"$FIXTURE_FILE")

# Parse and display results
echo -e "\n${YELLOW}Test Results:${NC}"
echo "============="

IS_VALID=$(echo "$RESPONSE" | jq -r '.is_valid')
QUOTE_VERIFIED=$(echo "$RESPONSE" | jq -r '.details.quote_verified')
EVENT_LOG_VERIFIED=$(echo "$RESPONSE" | jq -r '.details.event_log_verified')
OS_IMAGE_VERIFIED=$(echo "$RESPONSE" | jq -r '.details.os_image_hash_verified')
TCB_STATUS=$(echo "$RESPONSE" | jq -r '.details.tcb_status')
REASON=$(echo "$RESPONSE" | jq -r '.reason // "null"')

echo -e "Overall Valid: $([ "$IS_VALID" = "true" ] && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}") $IS_VALID"
echo -e "Quote Verified: $([ "$QUOTE_VERIFIED" = "true" ] && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}") $QUOTE_VERIFIED"
echo -e "Event Log Verified: $([ "$EVENT_LOG_VERIFIED" = "true" ] && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}") $EVENT_LOG_VERIFIED"
echo -e "OS Image Verified: $([ "$OS_IMAGE_VERIFIED" = "true" ] && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}") $OS_IMAGE_VERIFIED"
echo -e "TCB Status: ${GREEN}$TCB_STATUS${NC}"

if [ "$REASON" != "null" ]; then
    echo -e "${RED}Failure Reason:${NC}"
    echo "$REASON"
fi

# Show app info if available
APP_ID=$(echo "$RESPONSE" | jq -r '.details.app_info.app_id // "null"')
if [ "$APP_ID" != "null" ]; then
    echo -e "\n${YELLOW}App Information:${NC}"
    echo "App ID: $APP_ID"
    echo "Instance ID: $(echo "$RESPONSE" | jq -r '.details.app_info.instance_id')"
    echo "Compose Hash: $(echo "$RESPONSE" | jq -r '.details.app_info.compose_hash')"
fi

# Show report data
REPORT_DATA=$(echo "$RESPONSE" | jq -r '.details.report_data // "null"')
if [ "$REPORT_DATA" != "null" ]; then
    echo -e "\n${YELLOW}Report Data:${NC}"
    echo "$REPORT_DATA"
fi

echo -e "\n${YELLOW}Server Logs:${NC}"
echo "============"
tail -10 "$LOG_FILE"

echo -e "\n${YELLOW}Test completed!${NC}"
if [ "$IS_VALID" = "true" ]; then
    echo -e "${GREEN}✓ Verification PASSED${NC}"
    exit 0
else
    echo -e "${RED}✗ Verification FAILED${NC}"
    exit 1
fi
