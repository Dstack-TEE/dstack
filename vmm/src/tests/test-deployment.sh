#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Test script for vmm-cli.py deployment functionality
# Tests the complete compose + deploy workflow with local VMM instance

set -e # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
export DSTACK_VMM_URL=${DSTACK_VMM_URL:-http://localhost:12000}
VMM_CLI=${VMM_CLI:-../vmm-cli.py}
TEST_DIR=$(mktemp -d)

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

        # Stop the VM first
        if "$VMM_CLI" stop "$vm_id" --force 2>/dev/null; then
            echo "Forcefully stopped VM $vm_id"
        else
            echo "Failed to stop VM $vm_id (may already be stopped)"
        fi

        # Wait a moment for the stop to complete
        sleep 1

        # Remove the VM
        if "$VMM_CLI" remove "$vm_id" 2>/dev/null; then
            echo "Removed VM $vm_id"
        else
            echo "Failed to remove VM $vm_id"
        fi
    done

    # Clean up test files
    rm -rf "$TEST_DIR"
}

setup() {
    echo -e "${YELLOW}Setting up test environment...${NC}"
    mkdir -p "$TEST_DIR"

    # Create test docker-compose.yml
    cat >"$TEST_DIR/docker-compose.yml" <<'EOF'
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
    environment:
      - NGINX_HOST=localhost
      - NGINX_PORT=80
      - UTF8_STR=你好
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
EOF

    # Create test environment file
    cat >"$TEST_DIR/test.env" <<'EOF'
API_KEY=test-deployment-key
DEBUG=true
ENVIRONMENT=test
EOF

    # Create test user config file
    cat >"$TEST_DIR/user-config.json" <<'EOF'
{
  "timezone": "UTC",
  "locale": "en_US.UTF-8",
  "custom_settings": {
    "debug_mode": false,
    "log_level": "INFO",
    "test_mode": true
  },
  "deployment_info": {
    "deployed_by": "vmm-cli-test",
    "deployment_time": "2025-01-01T00:00:00Z"
  }
}
EOF
}

# Test functions
test_server_connectivity() {
    print_test "VMM server connectivity"

    if "$VMM_CLI" lsvm >/dev/null 2>&1; then
        print_success "Server connectivity test passed"
        return 0
    else
        print_error "Server connectivity test failed - VMM server not accessible at $DSTACK_VMM_URL"
        return 1
    fi
}

test_list_images() {
    print_test "List available images"

    local output
    output=$("$VMM_CLI" lsimage 2>/dev/null)

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

    local output
    output=$("$VMM_CLI" compose \
        --name "test-deployment-app" \
        --docker-compose "$TEST_DIR/docker-compose.yml" \
        --env-file "$TEST_DIR/test.env" \
        --output "$TEST_DIR/app-compose.json" 2>&1)

    if [[ $? -eq 0 ]]; then
        if [[ -f "$TEST_DIR/app-compose.json" ]] &&
            jq -e '.name == "test-deployment-app"' "$TEST_DIR/app-compose.json" >/dev/null; then

            # Extract and store the compose hash for later verification
            local compose_hash
            compose_hash=$(echo "$output" | grep "Compose hash:" | awk '{print $NF}')
            if [[ -n "$compose_hash" ]]; then
                echo "$compose_hash" >"$TEST_DIR/compose-hash.txt"
                echo "Captured compose hash: $compose_hash"
            fi

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

test_compose_hash_verification() {
    print_test "Compose hash verification"

    # Check if we have a captured compose hash from the compose creation test
    if [[ ! -f "$TEST_DIR/compose-hash.txt" ]]; then
        print_error "Compose hash verification test failed - no compose hash captured from previous test"
        return 1
    fi

    local expected_hash
    expected_hash=$(cat "$TEST_DIR/compose-hash.txt")

    if [[ -z "$expected_hash" ]]; then
        print_error "Compose hash verification test failed - empty compose hash"
        return 1
    fi

    # Get available image for deployment
    local image
    image=$("$VMM_CLI" lsimage --json 2>/dev/null | jq -r '.[0].name // empty')

    if [[ -z "$image" ]]; then
        print_error "Compose hash verification test failed - no suitable image found"
        return 1
    fi

    # Deploy a VM to get logs with compose hash
    local output
    output=$("$VMM_CLI" deploy \
        --name "test-compose-hash-vm" \
        --image "$image" \
        --compose "$TEST_DIR/app-compose.json" \
        --vcpu 1 \
        --memory 1G \
        --disk 10G 2>&1)

    if [[ $? -eq 0 ]]; then
        # Extract VM ID from output
        local vm_id
        vm_id=$(echo "$output" | grep "Created VM with ID:" | awk '{print $NF}')

        if [[ -n "$vm_id" ]]; then
            DEPLOYED_VMS+=("$vm_id")

            # Stream VM logs and wait for compose_hash to appear (with 1-minute timeout)
            echo "Waiting for compose_hash to appear in VM logs (timeout: 60s)..."
            local timeout=60
            local elapsed=0
            local found_hash=false

            while [[ $elapsed -lt $timeout ]] && [[ "$found_hash" == "false" ]]; do
                local vm_logs
                vm_logs=$("$VMM_CLI" logs -n 200 "$vm_id" 2>/dev/null)
                if [[ -n "$vm_logs" ]]; then
                    # Check if compose_hash appears in the logs
                    if echo "$vm_logs" | grep -q "\"compose_hash\": \"$expected_hash\""; then
                        print_success "Compose hash verification test passed - hash matches between CLI and VM logs"
                        echo "Expected hash: $expected_hash"
                        echo "Hash found in VM logs: ✓ (after ${elapsed}s)"
                        return 0
                    elif echo "$vm_logs" | grep -q "compose_hash"; then
                        # Found compose_hash but not the expected one - show what we found
                        local found_compose_hash
                        found_compose_hash=$(echo "$vm_logs" | grep -o '"compose_hash": "[^"]*"' | head -1)
                        print_error "Compose hash verification test failed - hash mismatch"
                        echo "Expected hash: $expected_hash"
                        echo "Found in logs: $found_compose_hash"
                        return 1
                    fi
                fi

                sleep 2
                elapsed=$((elapsed + 2))
                echo -n "."
            done

            echo ""

            # Timeout reached - get final logs for debugging
            local final_logs
            final_logs=$("$VMM_CLI" logs -n 500 "$vm_id" 2>/dev/null)

            if [[ -n "$final_logs" ]]; then
                print_error "Compose hash verification test failed - timeout waiting for compose_hash"
                echo "Expected hash: $expected_hash"
                echo "Timeout: ${timeout}s elapsed"
                echo "VM logs containing 'compose_hash': $(echo "$final_logs" | grep -n compose_hash || echo 'None found')"
                echo "VM logs containing 'Measurement Report': $(echo "$final_logs" | grep -n 'Measurement Report' || echo 'None found')"
                echo "VM logs containing 'app_id': $(echo "$final_logs" | grep -n 'app_id' || echo 'None found')"
                echo "DEBUG: Last 1000 chars of VM logs:"
                echo "$final_logs" | tail -c 1000
            else
                print_error "Compose hash verification test failed - could not retrieve VM logs after timeout"
            fi

            return 1
        else
            print_error "Compose hash verification test failed - could not extract VM ID"
            return 1
        fi
    else
        print_error "Compose hash verification test failed - VM deployment failed"
        echo "$output"
        return 1
    fi
}

test_deployment() {
    print_test "VM deployment"

    # Get available image
    local image
    image=$("$VMM_CLI" lsimage --json 2>/dev/null | jq -r '.[0].name // empty')

    if [[ -z "$image" ]]; then
        print_error "Deployment test failed - no suitable image found"
        return 1
    fi

    local output
    output=$("$VMM_CLI" deploy \
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

    # Test JSON output functionality
    local json_output
    json_output=$("$VMM_CLI" lsvm --json 2>/dev/null)

    if [[ $? -eq 0 ]] && echo "$json_output" | jq -e '.[] | select(.name == "test-deployment-vm")' >/dev/null 2>&1; then
        # Verify JSON structure contains expected fields
        local vm_data
        vm_data=$(echo "$json_output" | jq -r '.[] | select(.name == "test-deployment-vm")')

        if echo "$vm_data" | jq -e '.id and .name and .status and .configuration' >/dev/null 2>&1; then
            print_success "VM listing with JSON output test passed - found test VM with proper structure"
            return 0
        else
            print_error "VM listing test failed - JSON structure incomplete"
            return 1
        fi
    else
        print_error "VM listing test failed - could not retrieve VM data via JSON"
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

    if "$VMM_CLI" logs "$vm_id" -n 5 >/dev/null 2>&1; then
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
    if "$VMM_CLI" stop "$vm_id" 2>/dev/null ||
        "$VMM_CLI" stop "$vm_id" --force 2>/dev/null; then

        # Try to start it again
        if "$VMM_CLI" start "$vm_id" 2>/dev/null; then
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

test_stopped_vm_deployment() {
    print_test "VM deployment with --stopped flag"

    # Get available image
    local image
    image=$("$VMM_CLI" lsimage --json 2>/dev/null | jq -r '.[0].name // empty')

    if [[ -z "$image" ]]; then
        print_error "Stopped VM deployment test failed - no suitable image found"
        return 1
    fi

    local output
    output=$("$VMM_CLI" deploy \
        --name "test-stopped-vm" \
        --image "$image" \
        --compose "$TEST_DIR/app-compose.json" \
        --vcpu 1 \
        --memory 2G \
        --disk 20G \
        --stopped 2>&1)

    if [[ $? -eq 0 ]]; then
        # Extract VM ID from output
        local vm_id
        vm_id=$(echo "$output" | grep "Created VM with ID:" | awk '{print $NF}')

        if [[ -n "$vm_id" ]]; then
            DEPLOYED_VMS+=("$vm_id")

            # Wait a moment and check VM status - should be stopped
            sleep 2
            local status
            status=$("$VMM_CLI" lsvm --json 2>/dev/null | jq -r ".[] | select(.id == \"$vm_id\") | .status")

            if [[ "$status" == "stopped" ]] || [[ "$status" == "exited" ]]; then
                print_success "Stopped VM deployment test passed - VM created in stopped state with ID: $vm_id"
                return 0
            else
                print_error "Stopped VM deployment test failed - VM not in stopped state (status: $status)"
                return 1
            fi
        else
            print_error "Stopped VM deployment test failed - could not extract VM ID"
            return 1
        fi
    else
        print_error "Stopped VM deployment test failed - command execution failed"
        echo "$output"
        return 1
    fi
}

test_user_config_deployment() {
    print_test "VM deployment with --user-config flag"

    # Get available image
    local image
    image=$("$VMM_CLI" lsimage --json 2>/dev/null | jq -r '.[0].name // empty')

    if [[ -z "$image" ]]; then
        print_error "User config deployment test failed - no suitable image found"
        return 1
    fi

    local output
    output=$("$VMM_CLI" deploy \
        --name "test-userconfig-vm" \
        --image "$image" \
        --compose "$TEST_DIR/app-compose.json" \
        --vcpu 1 \
        --memory 2G \
        --disk 20G \
        --user-config "$TEST_DIR/user-config.json" 2>&1)

    if [[ $? -eq 0 ]]; then
        # Extract VM ID from output
        local vm_id
        vm_id=$(echo "$output" | grep "Created VM with ID:" | awk '{print $NF}')

        if [[ -n "$vm_id" ]]; then
            DEPLOYED_VMS+=("$vm_id")

            # Wait a moment for VM to be fully initialized
            sleep 2

            # Verify that the user config was actually passed to the backend
            local vm_user_config
            vm_user_config=$("$VMM_CLI" lsvm --json 2>/dev/null | jq -r ".[] | select(.id == \"$vm_id\") | .configuration.user_config")

            if [[ -n "$vm_user_config" ]] && [[ "$vm_user_config" != "null" ]] && [[ "$vm_user_config" != "" ]]; then
                # Check if the user config contains expected content
                local expected_content="timezone"
                if echo "$vm_user_config" | grep -q "$expected_content"; then
                    print_success "User config deployment test passed - VM created with user config, ID: $vm_id"
                    echo "User config content verified: $(echo "$vm_user_config" | jq -c . 2>/dev/null || echo "$vm_user_config")"
                    return 0
                else
                    print_error "User config deployment test failed - user config content doesn't match expected format"
                    echo "Received user config: $vm_user_config"
                    return 1
                fi
            else
                print_error "User config deployment test failed - no user config found in VM configuration"
                echo "VM user_config field: '$vm_user_config'"
                return 1
            fi
        else
            print_error "User config deployment test failed - could not extract VM ID"
            return 1
        fi
    else
        print_error "User config deployment test failed - command execution failed"
        echo "$output"
        return 1
    fi
}

# Main test execution
main() {
    echo -e "${YELLOW}=== VMM-CLI Deployment Test Suite ===${NC}"
    echo "Testing against VMM server: $DSTACK_VMM_URL"
    echo ""

    # Check dependencies
    if ! command -v jq &>/dev/null; then
        echo -e "${RED}Error: jq is required for JSON testing but not installed${NC}"
        exit 1
    fi

    # Setup test environment
    trap cleanup EXIT
    setup

    # Run tests (continue even if some fail)
    test_server_connectivity || {
        echo "Skipping remaining tests due to connectivity issues"
        exit 1
    }
    test_list_images || true
    test_compose_creation || true
    test_compose_hash_verification || true
    test_deployment || true
    test_vm_listing_with_gpus || true
    test_vm_logs || true
    test_vm_lifecycle || true
    test_stopped_vm_deployment || true
    test_user_config_deployment || true

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
