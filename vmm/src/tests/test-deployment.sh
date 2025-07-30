#!/bin/bash

# Test script for vmm-cli.py deployment functionality
# Tests the complete compose + deploy workflow with local VMM instance

set -e # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
VMM_URL="http://127.0.0.1:12000"
VMM_CLI="/home/kvin/sdc/home/meta-dstack/dstack/vmm/src/vmm-cli.py"
TEST_DIR="/tmp/vmm-cli-deployment-test"

# Test counter
TESTS_PASSED=0
TESTS_TOTAL=0

# VM IDs for cleanup
DEPLOYED_VMS=()

# Helper functions
print_test() {
    echo -e "${YELLOW}[TEST $((++TESTS_TOTAL))] $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((TESTS_PASSED++))
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

cleanup() {
    echo -e "${YELLOW}Cleaning up test resources...${NC}"
    
    # Clean up any deployed VMs
    for vm_id in "${DEPLOYED_VMS[@]}"; do
        echo "Cleaning up VM: $vm_id"
        python3 "$VMM_CLI" --url "$VMM_URL" stop "$vm_id" --force 2>/dev/null || true
        python3 "$VMM_CLI" --url "$VMM_URL" remove "$vm_id" 2>/dev/null || true
    done
    
    # Clean up test files
    rm -rf "$TEST_DIR"
}

setup() {
    echo -e "${YELLOW}Setting up test environment...${NC}"
    mkdir -p "$TEST_DIR"
    
    # Create test docker-compose.yml
    cat > "$TEST_DIR/docker-compose.yml" << 'EOF'
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
    environment:
      - NGINX_HOST=localhost
      - NGINX_PORT=80
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
EOF

    # Create test environment file
    cat > "$TEST_DIR/test.env" << 'EOF'
API_KEY=test-deployment-key
DEBUG=true
ENVIRONMENT=test
EOF
}

# Test functions
test_server_connectivity() {
    print_test "VMM server connectivity"
    
    if python3 "$VMM_CLI" --url "$VMM_URL" lsvm > /dev/null 2>&1; then
        print_success "Server connectivity test passed"
        return 0
    else
        print_error "Server connectivity test failed - VMM server not accessible at $VMM_URL"
        return 1
    fi
}

test_list_images() {
    print_test "List available images"
    
    local output
    output=$(python3 "$VMM_CLI" --url "$VMM_URL" lsimage 2>/dev/null)
    
    if [[ $? -eq 0 ]] && [[ -n "$output" ]]; then
        print_success "List images test passed - found available images"
        return 0
    else
        print_error "List images test failed - no images available or command failed"
        return 1
    fi
}

test_compose_creation() {
    print_test "App compose file creation"
    
    if python3 "$VMM_CLI" --url "$VMM_URL" compose \
        --name "test-deployment-app" \
        --docker-compose "$TEST_DIR/docker-compose.yml" \
        --env-file "$TEST_DIR/test.env" \
        --output "$TEST_DIR/app-compose.json" > /dev/null 2>&1; then
        
        if [[ -f "$TEST_DIR/app-compose.json" ]] && \
           jq -e '.name == "test-deployment-app"' "$TEST_DIR/app-compose.json" > /dev/null; then
            print_success "Compose creation test passed"
            return 0
        else
            print_error "Compose creation test failed - invalid output file"
            return 1
        fi
    else
        print_error "Compose creation test failed - command execution failed"
        return 1
    fi
}

test_deployment() {
    print_test "VM deployment"
    
    # Get available image
    local image
    image=$(python3 "$VMM_CLI" --url "$VMM_URL" lsimage 2>/dev/null | grep "dstack" | head -1 | awk -F'│' '{print $2}' | xargs)
    
    if [[ -z "$image" ]]; then
        print_error "Deployment test failed - no suitable image found"
        return 1
    fi
    
    local output
    output=$(python3 "$VMM_CLI" --url "$VMM_URL" deploy \
        --name "test-deployment-vm" \
        --image "$image" \
        --compose "$TEST_DIR/app-compose.json" \
        --vcpu 1 \
        --memory 2G \
        --disk 20G 2>&1)
    
    if [[ $? -eq 0 ]]; then
        # Extract VM ID from output
        local vm_id
        vm_id=$(echo "$output" | grep "Created VM with ID:" | awk '{print $NF}')
        
        if [[ -n "$vm_id" ]]; then
            DEPLOYED_VMS+=("$vm_id")
            print_success "Deployment test passed - VM created with ID: $vm_id"
            return 0
        else
            print_error "Deployment test failed - could not extract VM ID"
            return 1
        fi
    else
        print_error "Deployment test failed - command execution failed"
        echo "$output"
        return 1
    fi
}

test_vm_listing_with_gpus() {
    print_test "VM listing with GPU information"
    
    local output
    output=$(python3 "$VMM_CLI" --url "$VMM_URL" lsvm -v 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$output" | grep -q "GPUs" && echo "$output" | grep -q "test-deployment-vm"; then
        print_success "VM listing with GPU info test passed"
        return 0
    else
        print_error "VM listing with GPU info test failed"
        return 1
    fi
}

test_vm_logs() {
    print_test "VM logs retrieval"
    
    if [[ ${#DEPLOYED_VMS[@]} -eq 0 ]]; then
        print_error "VM logs test skipped - no deployed VMs"
        return 1
    fi
    
    local vm_id="${DEPLOYED_VMS[0]}"
    
    # Wait a moment for VM to start
    sleep 3
    
    if python3 "$VMM_CLI" --url "$VMM_URL" logs "$vm_id" -n 5 > /dev/null 2>&1; then
        print_success "VM logs test passed"
        return 0
    else
        print_error "VM logs test failed"
        return 1
    fi
}

test_vm_lifecycle() {
    print_test "VM lifecycle management (stop/start)"
    
    if [[ ${#DEPLOYED_VMS[@]} -eq 0 ]]; then
        print_error "VM lifecycle test skipped - no deployed VMs"
        return 1
    fi
    
    local vm_id="${DEPLOYED_VMS[0]}"
    
    # Try to stop the VM (gracefully first, then force if needed)
    if python3 "$VMM_CLI" --url "$VMM_URL" stop "$vm_id" 2>/dev/null || \
       python3 "$VMM_CLI" --url "$VMM_URL" stop "$vm_id" --force 2>/dev/null; then
        
        # Try to start it again
        if python3 "$VMM_CLI" --url "$VMM_URL" start "$vm_id" 2>/dev/null; then
            print_success "VM lifecycle test passed"
            return 0
        else
            print_error "VM lifecycle test failed - could not restart VM"
            return 1
        fi
    else
        print_error "VM lifecycle test failed - could not stop VM"
        return 1
    fi
}

# Main test execution
main() {
    echo -e "${YELLOW}=== VMM-CLI Deployment Test Suite ===${NC}"
    echo "Testing against VMM server: $VMM_URL"
    echo ""
    
    # Check dependencies
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}Error: jq is required for JSON testing but not installed${NC}"
        exit 1
    fi
    
    if [[ ! -f "$VMM_CLI" ]]; then
        echo -e "${RED}Error: VMM CLI not found at $VMM_CLI${NC}"
        exit 1
    fi
    
    # Setup test environment
    trap cleanup EXIT
    setup
    
    # Run tests (continue even if some fail)
    test_server_connectivity || { echo "Skipping remaining tests due to connectivity issues"; exit 1; }
    test_list_images || true
    test_compose_creation || true
    test_deployment || true
    test_vm_listing_with_gpus || true
    test_vm_logs || true
    test_vm_lifecycle || true
    
    # Results summary
    echo ""
    echo -e "${YELLOW}=== Test Results ===${NC}"
    if [[ $TESTS_PASSED -eq $TESTS_TOTAL ]]; then
        echo -e "${GREEN}All tests passed! ($TESTS_PASSED/$TESTS_TOTAL)${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed. ($TESTS_PASSED/$TESTS_TOTAL passed)${NC}"
        exit 1
    fi
}

# Run main function
main "$@"