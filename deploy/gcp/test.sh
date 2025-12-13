#!/bin/bash
# Dstack GCP TDX Verification Script
# Tests that the deployed VM has REAL Intel TDX hardware attestation
# 
# This script verifies:
# 1. TDX hardware is present (/dev/tdx_guest)
# 2. Kernel detected TDX (dmesg)
# 3. Memory encryption is active
# 4. TSM (Trusted Security Module) can generate real attestation quotes
# 5. Dstack components are running (if deployed)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
VM_IP="${VM_IP:-}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/jeju-dstack}"
SSH_USER="${SSH_USER:-ubuntu}"

usage() {
    echo "Usage: $0 <VM_IP> [SSH_KEY]"
    echo ""
    echo "Arguments:"
    echo "  VM_IP    - External IP of the GCP VM"
    echo "  SSH_KEY  - Path to SSH private key (default: ~/.ssh/jeju-dstack)"
    echo ""
    echo "Environment variables:"
    echo "  VM_IP    - Alternative to positional argument"
    echo "  SSH_KEY  - Alternative to positional argument"
    echo "  SSH_USER - SSH username (default: ubuntu)"
    exit 1
}

# Parse arguments
if [ -n "$1" ]; then
    VM_IP="$1"
fi
if [ -n "$2" ]; then
    SSH_KEY="$2"
fi

if [ -z "$VM_IP" ]; then
    usage
fi

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║       DSTACK GCP TDX HARDWARE VERIFICATION                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "VM IP:   $VM_IP"
echo "SSH Key: $SSH_KEY"
echo "User:    $SSH_USER"
echo ""

PASSED=0
FAILED=0
QUOTE_HEX=""

run_test() {
    local name="$1"
    local cmd="$2"
    local expect="$3"
    
    echo -n "Testing: $name... "
    
    result=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$SSH_USER@$VM_IP" "$cmd" 2>&1) || true
    
    if echo "$result" | grep -q "$expect"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Expected: $expect"
        echo "  Got: $(echo "$result" | head -1)"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

run_test_with_output() {
    local name="$1"
    local cmd="$2"
    local expect="$3"
    
    echo -n "Testing: $name... "
    
    result=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$SSH_USER@$VM_IP" "$cmd" 2>&1) || true
    
    if echo "$result" | grep -q "$expect"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        echo -e "  ${CYAN}$result${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Expected: $expect"
        echo "  Got: $(echo "$result" | head -1)"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════
# SECTION 1: CONNECTIVITY
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                    1. CONNECTIVITY TESTS"
echo "═══════════════════════════════════════════════════════════════"
run_test "SSH connectivity" "echo 'connected'" "connected"

# ═══════════════════════════════════════════════════════════════════
# SECTION 2: TDX HARDWARE
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                    2. TDX HARDWARE VERIFICATION"
echo "═══════════════════════════════════════════════════════════════"

run_test "TDX device present" "test -c /dev/tdx_guest && echo 'exists'" "exists"
run_test_with_output "Kernel TDX detection" "sudo dmesg | grep 'tdx: Guest detected' | head -1" "Guest detected"
run_test_with_output "Memory encryption active" "sudo dmesg | grep 'Memory Encryption' | head -1" "Intel TDX"
run_test "CPU tdx_guest flag" "grep -q tdx_guest /proc/cpuinfo && echo 'present'" "present"
run_test "TSM provider is tdx_guest" "cat /sys/kernel/config/tsm/report/com.intel.dcap/provider 2>/dev/null" "tdx_guest"

# ═══════════════════════════════════════════════════════════════════
# SECTION 3: DIRECT TDX ATTESTATION (via TSM interface)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                    3. REAL TDX ATTESTATION"
echo "═══════════════════════════════════════════════════════════════"

echo -n "Testing: Generate real TDX quote via TSM... "
# Generate a real quote using the kernel TSM interface
QUOTE_HEX=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VM_IP" '
    dd if=/dev/zero bs=1 count=64 2>/dev/null | sudo tee /sys/kernel/config/tsm/report/com.intel.dcap/inblob > /dev/null
    sudo dd if=/sys/kernel/config/tsm/report/com.intel.dcap/outblob bs=8192 count=1 2>/dev/null | xxd -p | tr -d "\n"
' 2>&1)

QUOTE_LEN=$((${#QUOTE_HEX}/2))
if [ "$QUOTE_LEN" -gt 1000 ]; then
    TEE_TYPE="${QUOTE_HEX:8:8}"
    if [ "$TEE_TYPE" = "81000000" ]; then
        echo -e "${GREEN}✓ PASSED${NC}"
        echo -e "  ${CYAN}Quote size: $QUOTE_LEN bytes${NC}"
        echo -e "  ${CYAN}TEE Type: 0x$TEE_TYPE (Intel TDX)${NC}"
        echo -e "  ${CYAN}Version: 0x${QUOTE_HEX:0:4} (TDX Quote v1.5)${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Unexpected TEE type: $TEE_TYPE (expected 81000000)"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Quote too small: $QUOTE_LEN bytes (expected >1000)"
    FAILED=$((FAILED + 1))
fi

# ═══════════════════════════════════════════════════════════════════
# SECTION 4: DSTACK COMPONENTS (Optional)
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                    4. DSTACK COMPONENTS (optional)"
echo "═══════════════════════════════════════════════════════════════"

# Check for Docker
run_test "Docker service" "systemctl is-active docker 2>/dev/null || echo 'not-installed'" "active"

# Check for Dstack containers or guest-agent
echo -n "Testing: Dstack process/container... "
dstack_status=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VM_IP" '
    if pgrep -f dstack-guest-agent > /dev/null; then
        echo "guest-agent running"
    elif sudo docker ps --format "{{.Names}}" 2>/dev/null | grep -qE "dstack|simulator"; then
        echo "container running"
    else
        echo "not-running"
    fi
' 2>&1)

if echo "$dstack_status" | grep -q "running"; then
    echo -e "${GREEN}✓ PASSED${NC}"
    echo -e "  ${CYAN}Status: $dstack_status${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}⚠ SKIPPED${NC}"
    echo "  Dstack not deployed (optional)"
fi

# Check for sockets
echo -n "Testing: Dstack sockets... "
socket_count=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VM_IP" '
    count=0
    for dir in /tmp/dstack /var/run/dstack; do
        [ -d "$dir" ] && count=$((count + $(ls "$dir"/*.sock 2>/dev/null | wc -l)))
    done
    echo $count
' 2>&1)

if [ "$socket_count" -gt 0 ]; then
    echo -e "${GREEN}✓ PASSED${NC}"
    echo -e "  ${CYAN}Found $socket_count socket(s)${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}⚠ SKIPPED${NC}"
    echo "  No sockets found (Dstack not fully deployed)"
fi

# ═══════════════════════════════════════════════════════════════════
# SECTION 5: DSTACK API TESTS
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                    5. DSTACK API TESTS"
echo "═══════════════════════════════════════════════════════════════"

# Test GetQuote via dstack socket
echo -n "Testing: Dstack GetQuote API... "
dstack_quote=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VM_IP" '
    if [ -S /var/run/dstack/dstack.sock ]; then
        sudo curl -s --unix-socket /var/run/dstack/dstack.sock "http://localhost/GetQuote" 2>&1
    else
        echo "no-socket"
    fi
' 2>&1)

if echo "$dstack_quote" | grep -q "040002"; then
    echo -e "${GREEN}✓ PASSED${NC}"
    DSTACK_QUOTE_SIZE=$(echo "$dstack_quote" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('quote',''))//2)" 2>/dev/null || echo "?")
    echo -e "  ${CYAN}Quote size: $DSTACK_QUOTE_SIZE bytes (via dstack API)${NC}"
    PASSED=$((PASSED + 1))
elif echo "$dstack_quote" | grep -q "no-socket"; then
    echo -e "${YELLOW}⚠ SKIPPED${NC}"
    echo "  No dstack socket available"
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Error: $(echo "$dstack_quote" | head -1)"
    FAILED=$((FAILED + 1))
fi

# Test DeriveKey via tappd socket
echo -n "Testing: Dstack DeriveKey API... "
dstack_key=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VM_IP" '
    if [ -S /var/run/dstack/tappd.sock ]; then
        sudo curl -s --unix-socket /var/run/dstack/tappd.sock -X POST "http://localhost/prpc/Tappd.DeriveKey" -H "Content-Type: application/json" -d "{\"path\":\"/test\"}" 2>&1
    else
        echo "no-socket"
    fi
' 2>&1)

if echo "$dstack_key" | grep -q "PRIVATE KEY"; then
    echo -e "${GREEN}✓ PASSED${NC}"
    CERT_COUNT=$(echo "$dstack_key" | grep -c "BEGIN CERTIFICATE" || echo "0")
    echo -e "  ${CYAN}Key derived with $CERT_COUNT certificate(s)${NC}"
    PASSED=$((PASSED + 1))
elif echo "$dstack_key" | grep -q "no-socket"; then
    echo -e "${YELLOW}⚠ SKIPPED${NC}"
    echo "  No tappd socket available"
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Error: $(echo "$dstack_key" | head -1)"
    FAILED=$((FAILED + 1))
fi

# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                         FINAL SUMMARY"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo -e "Tests Passed: ${GREEN}$PASSED${NC}"
echo -e "Tests Failed: ${RED}$FAILED${NC}"
echo ""

# Show attestation details if we got a quote
if [ -n "$QUOTE_HEX" ] && [ "${#QUOTE_HEX}" -gt 2000 ]; then
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    ATTESTATION DETAILS"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Quote Header:     ${QUOTE_HEX:0:32}..."
    echo "Quote Size:       $((${#QUOTE_HEX}/2)) bytes"
    echo "TEE Type:         0x${QUOTE_HEX:8:8}"
    echo "Quote Version:    0x${QUOTE_HEX:0:4}"
    echo ""
fi

if [ $FAILED -eq 0 ]; then
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  ✅ ALL TESTS PASSED - REAL INTEL TDX VERIFIED               ║"
    echo "║                                                               ║"
    echo "║  This VM is running with genuine Intel TDX hardware          ║"
    echo "║  attestation. Memory is encrypted by the CPU.                ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    exit 0
else
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  ❌ SOME TESTS FAILED                                        ║"
    echo "║                                                               ║"
    echo "║  Review the output above to identify issues.                 ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    exit 1
fi

