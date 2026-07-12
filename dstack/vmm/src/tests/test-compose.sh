#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Test script for vmm-cli.py compose subcommand
# Tests the refactored create_app_compose method that accepts args directly

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test directory
TEST_DIR="/tmp/vmm-cli-compose-test"
VMM_CLI="/home/kvin/sdc/home/meta-dstack/dstack/vmm/src/vmm-cli.py"

# Test counter
TESTS_PASSED=0
TESTS_TOTAL=0

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
    echo -e "${YELLOW}Cleaning up test files...${NC}"
    rm -rf "$TEST_DIR"
}

setup() {
    echo -e "${YELLOW}Setting up test environment...${NC}"
    mkdir -p "$TEST_DIR"
    
    # Create test docker-compose.yml
    cat > "$TEST_DIR/docker-compose.yml" << 'EOF'
version: '3'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
    environment:
      - NODE_ENV=production
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
EOF

    # Create test environment file
    cat > "$TEST_DIR/test.env" << 'EOF'
API_KEY=test123
DEBUG=true
PORT=8080
DATABASE_URL=postgresql://user:pass@localhost/db
EOF

    # Create test prelaunch script
    cat > "$TEST_DIR/prelaunch.sh" << 'EOF'
#!/bin/bash
echo "Starting application..."
echo "Checking dependencies..."
sleep 2
echo "Application ready!"
EOF
}

# Test functions
test_basic_compose() {
    print_test "Basic compose functionality with minimal parameters"
    
    if python3 "$VMM_CLI" compose \
        --name test-basic \
        --docker-compose "$TEST_DIR/docker-compose.yml" \
        --output "$TEST_DIR/basic-output.json" > /dev/null 2>&1; then
        
        if [[ -f "$TEST_DIR/basic-output.json" ]]; then
            # Verify JSON structure
            if jq -e '.name == "test-basic"' "$TEST_DIR/basic-output.json" > /dev/null && \
               jq -e '.manifest_version == 2' "$TEST_DIR/basic-output.json" > /dev/null && \
               jq -e '.kms_enabled == false' "$TEST_DIR/basic-output.json" > /dev/null && \
               jq -e '.gateway_enabled == false' "$TEST_DIR/basic-output.json" > /dev/null; then
                print_success "Basic compose test passed - JSON structure correct"
                return 0
            else
                print_error "Basic compose test failed - JSON structure incorrect"
                return 1
            fi
        else
            print_error "Basic compose test failed - output file not created"
            return 1
        fi
    else
        print_error "Basic compose test failed - command execution failed"
        return 1
    fi
}

test_full_compose() {
    print_test "Full compose functionality with all optional parameters"
    
    if python3 "$VMM_CLI" compose \
        --name test-full \
        --docker-compose "$TEST_DIR/docker-compose.yml" \
        --prelaunch-script "$TEST_DIR/prelaunch.sh" \
        --env-file "$TEST_DIR/test.env" \
        --kms \
        --gateway \
        --local-key-provider \
        --key-provider-id my-test-provider \
        --public-logs \
        --public-sysinfo \
        --no-instance-id \
        --output "$TEST_DIR/full-output.json" > /dev/null 2>&1; then
        
        if [[ -f "$TEST_DIR/full-output.json" ]]; then
            # Verify all options are set correctly
            if jq -e '.name == "test-full"' "$TEST_DIR/full-output.json" > /dev/null && \
               jq -e '.kms_enabled == true' "$TEST_DIR/full-output.json" > /dev/null && \
               jq -e '.gateway_enabled == true' "$TEST_DIR/full-output.json" > /dev/null && \
               jq -e '.local_key_provider_enabled == true' "$TEST_DIR/full-output.json" > /dev/null && \
               jq -e '.key_provider_id == "my-test-provider"' "$TEST_DIR/full-output.json" > /dev/null && \
               jq -e '.public_logs == true' "$TEST_DIR/full-output.json" > /dev/null && \
               jq -e '.public_sysinfo == true' "$TEST_DIR/full-output.json" > /dev/null && \
               jq -e '.no_instance_id == true' "$TEST_DIR/full-output.json" > /dev/null && \
               jq -e '.allowed_envs | length == 4' "$TEST_DIR/full-output.json" > /dev/null && \
               jq -e '.pre_launch_script' "$TEST_DIR/full-output.json" > /dev/null; then
                print_success "Full compose test passed - all options set correctly"
            else
                print_error "Full compose test failed - options not set correctly"
                return 1
            fi
        else
            print_error "Full compose test failed - output file not created"
            return 1
        fi
    else
        print_error "Full compose test failed - command execution failed"
        return 1
    fi
}

test_env_parsing() {
    print_test "Environment variable parsing"
    
    python3 "$VMM_CLI" compose \
        --name test-env \
        --docker-compose "$TEST_DIR/docker-compose.yml" \
        --env-file "$TEST_DIR/test.env" \
        --output "$TEST_DIR/env-output.json" > /dev/null 2>&1
    
    # Check if all environment variables are in allowed_envs
    if jq -e '.allowed_envs | contains(["API_KEY", "DEBUG", "PORT", "DATABASE_URL"])' "$TEST_DIR/env-output.json" > /dev/null; then
        print_success "Environment parsing test passed - all env vars included"
    else
        print_error "Environment parsing test failed - env vars missing"
        return 1
    fi
}

test_docker_compose_embedding() {
    print_test "Docker compose file embedding"
    
    python3 "$VMM_CLI" compose \
        --name test-docker \
        --docker-compose "$TEST_DIR/docker-compose.yml" \
        --output "$TEST_DIR/docker-output.json" > /dev/null 2>&1
    
    # Check if docker-compose content is properly embedded
    if jq -e '.docker_compose_file | contains("nginx:latest")' "$TEST_DIR/docker-output.json" > /dev/null && \
       jq -e '.docker_compose_file | contains("redis:alpine")' "$TEST_DIR/docker-output.json" > /dev/null; then
        print_success "Docker compose embedding test passed - content properly embedded"
    else
        print_error "Docker compose embedding test failed - content not embedded correctly"
        return 1
    fi
}

test_prelaunch_script() {
    print_test "Prelaunch script embedding"
    
    python3 "$VMM_CLI" compose \
        --name test-prelaunch \
        --docker-compose "$TEST_DIR/docker-compose.yml" \
        --prelaunch-script "$TEST_DIR/prelaunch.sh" \
        --output "$TEST_DIR/prelaunch-output.json" > /dev/null 2>&1
    
    # Check if prelaunch script is properly embedded
    if jq -e '.pre_launch_script | contains("Starting application...")' "$TEST_DIR/prelaunch-output.json" > /dev/null && \
       jq -e '.pre_launch_script | contains("#!/bin/bash")' "$TEST_DIR/prelaunch-output.json" > /dev/null; then
        print_success "Prelaunch script test passed - script properly embedded"
    else
        print_error "Prelaunch script test failed - script not embedded correctly"
        return 1
    fi
}

test_error_handling() {
    print_test "Error handling for missing files"
    
    # Test missing docker-compose file
    if python3 "$VMM_CLI" compose \
        --name test-error \
        --docker-compose "$TEST_DIR/nonexistent.yml" \
        --output "$TEST_DIR/error-output.json" 2>/dev/null; then
        print_error "Error handling test failed - should have failed with missing file"
        return 1
    else
        print_success "Error handling test passed - correctly failed with missing docker-compose file"
    fi
}

test_help_command() {
    print_test "Help command functionality"
    
    if python3 "$VMM_CLI" compose --help > /dev/null 2>&1; then
        print_success "Help command test passed - help displayed correctly"
    else
        print_error "Help command test failed - help command failed"
        return 1
    fi
}

test_hash_generation() {
    print_test "Compose hash generation"
    
    # Create two identical compose files
    python3 "$VMM_CLI" compose \
        --name test-hash-1 \
        --docker-compose "$TEST_DIR/docker-compose.yml" \
        --output "$TEST_DIR/hash1-output.json" > "$TEST_DIR/hash1.log" 2>&1
    
    python3 "$VMM_CLI" compose \
        --name test-hash-1 \
        --docker-compose "$TEST_DIR/docker-compose.yml" \
        --output "$TEST_DIR/hash2-output.json" > "$TEST_DIR/hash2.log" 2>&1
    
    # Extract hashes from output
    HASH1=$(grep "Compose hash:" "$TEST_DIR/hash1.log" | cut -d' ' -f3)
    HASH2=$(grep "Compose hash:" "$TEST_DIR/hash2.log" | cut -d' ' -f3)
    
    if [[ "$HASH1" == "$HASH2" ]] && [[ -n "$HASH1" ]]; then
        print_success "Hash generation test passed - identical inputs produce identical hashes"
    else
        print_error "Hash generation test failed - hashes don't match or are empty"
        return 1
    fi
}

# Main test execution
main() {
    echo -e "${YELLOW}=== VMM-CLI Compose Subcommand Test Suite ===${NC}"
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
    test_help_command || true
    test_basic_compose || true
    test_full_compose || true
    test_env_parsing || true
    test_docker_compose_embedding || true
    test_prelaunch_script || true
    test_hash_generation || true
    test_error_handling || true
    
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