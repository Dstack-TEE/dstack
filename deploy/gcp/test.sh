#!/bin/bash
# Dstack GCP TDX Verification
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

VM_IP="${1:-$VM_IP}"
SSH_KEY="${2:-${SSH_KEY:-$HOME/.ssh/id_rsa}}"
SSH_USER="${SSH_USER:-ubuntu}"

[ -z "$VM_IP" ] && { echo "Usage: $0 <VM_IP> [SSH_KEY]"; exit 1; }

SSH_CMD="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 $SSH_USER@$VM_IP"

PASSED=0
FAILED=0

run_test() {
    local name="$1" cmd="$2" expect="$3" show_output="${4:-false}"
    echo -n "Testing: $name... "
    result=$($SSH_CMD "$cmd" 2>&1) || true
    if echo "$result" | grep -q "$expect"; then
        echo -e "${GREEN}PASS${NC}"
        [ "$show_output" = "true" ] && echo -e "  ${CYAN}$result${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC}"
        FAILED=$((FAILED + 1))
    fi
}

echo "VM: $VM_IP | Key: $SSH_KEY"
echo ""

# Connectivity
run_test "SSH" "echo ok" "ok"

# TDX Hardware
echo ""
echo "=== TDX Hardware ==="
run_test "TDX device" "test -c /dev/tdx_guest && echo exists" "exists"
run_test "Kernel TDX" "sudo dmesg | grep -m1 'tdx: Guest'" "Guest detected" true
run_test "Memory encryption" "sudo dmesg | grep -m1 'Memory Encryption'" "Intel TDX" true
run_test "CPU flag" "grep -q tdx_guest /proc/cpuinfo && echo yes" "yes"
run_test "TSM provider" "cat /sys/kernel/config/tsm/report/com.intel.dcap/provider 2>/dev/null" "tdx_guest"

# TSM Quote
echo ""
echo "=== TDX Attestation ==="
echo -n "Testing: TSM quote... "
QUOTE=$($SSH_CMD 'dd if=/dev/zero bs=1 count=64 2>/dev/null | sudo tee /sys/kernel/config/tsm/report/com.intel.dcap/inblob >/dev/null; sudo dd if=/sys/kernel/config/tsm/report/com.intel.dcap/outblob bs=8192 count=1 2>/dev/null | xxd -p | tr -d "\n"' 2>&1)
QLEN=$((${#QUOTE}/2))
if [ "$QLEN" -gt 1000 ] && [ "${QUOTE:8:8}" = "81000000" ]; then
    echo -e "${GREEN}PASS${NC} ($QLEN bytes, TEE=0x${QUOTE:8:8})"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
fi

# Dstack (optional)
echo ""
echo "=== Dstack APIs ==="
run_test "Docker" "systemctl is-active docker 2>/dev/null" "active"

echo -n "Testing: guest-agent... "
status=$($SSH_CMD 'pgrep -f dstack-guest-agent >/dev/null && echo running || echo stopped' 2>&1)
if [ "$status" = "running" ]; then
    echo -e "${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}SKIP${NC}"
fi

echo -n "Testing: GetQuote API... "
quote=$($SSH_CMD '[ -S /var/run/dstack/dstack.sock ] && sudo curl -s --unix-socket /var/run/dstack/dstack.sock "http://localhost/GetQuote" || echo no-socket' 2>&1)
if echo "$quote" | grep -q "040002"; then
    size=$(echo "$quote" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('quote',''))//2)" 2>/dev/null)
    echo -e "${GREEN}PASS${NC} ($size bytes)"
    PASSED=$((PASSED + 1))
elif echo "$quote" | grep -q "no-socket"; then
    echo -e "${YELLOW}SKIP${NC}"
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
fi

echo -n "Testing: DeriveKey API... "
key=$($SSH_CMD '[ -S /var/run/dstack/tappd.sock ] && sudo curl -s --unix-socket /var/run/dstack/tappd.sock -X POST "http://localhost/prpc/Tappd.DeriveKey" -H "Content-Type: application/json" -d "{\"path\":\"/test\"}" || echo no-socket' 2>&1)
if echo "$key" | grep -q "PRIVATE KEY"; then
    echo -e "${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
elif echo "$key" | grep -q "no-socket"; then
    echo -e "${YELLOW}SKIP${NC}"
else
    echo -e "${RED}FAIL${NC}"
    FAILED=$((FAILED + 1))
fi

# Summary
echo ""
echo "=== Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC} ==="
[ $FAILED -eq 0 ] && echo -e "${GREEN}Intel TDX verified${NC}" || exit 1
