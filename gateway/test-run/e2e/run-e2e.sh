#!/bin/bash
# SPDX-FileCopyrightText: 2024-2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# E2E test runner for dstack-gateway
# Builds gateway and simulator images, then runs the test suite

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
SKIP_BUILD=false
SKIP_SIMULATOR_BUILD=false
KEEP_RUNNING=false
CLEAN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-simulator-build)
            SKIP_SIMULATOR_BUILD=true
            shift
            ;;
        --keep-running)
            KEEP_RUNNING=true
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-build           Skip building gateway image"
            echo "  --skip-simulator-build Skip building simulator"
            echo "  --keep-running         Keep containers running after test"
            echo "  --clean                Clean up containers and images"
            echo "  -h, --help             Show this help"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

cd "$SCRIPT_DIR"

# Clean up if requested
if $CLEAN; then
    log_info "Cleaning up..."
    docker compose down -v --remove-orphans 2>/dev/null || true
    docker rmi dstack-gateway:test dstack-simulator:test 2>/dev/null || true
    log_success "Cleanup complete"
    exit 0
fi

# Step 1: Build simulator if needed (musl static build)
if ! $SKIP_SIMULATOR_BUILD; then
    log_info "Building dstack-simulator (musl static)..."
    cd "$REPO_ROOT"
    cargo build --release -p dstack-guest-agent --target x86_64-unknown-linux-musl

    # Copy binary to simulator directory
    cp target/x86_64-unknown-linux-musl/release/dstack-guest-agent sdk/simulator/
    ln -sf dstack-guest-agent sdk/simulator/dstack-simulator
    log_success "Simulator built: sdk/simulator/dstack-simulator"
fi

# Create minimal simulator docker image (alpine for musl)
log_info "Creating simulator docker image..."
cat > /tmp/Dockerfile.simulator << 'EOF'
FROM alpine:latest
RUN apk add --no-cache curl ca-certificates
WORKDIR /app
EOF
docker build -t dstack-simulator:test -f /tmp/Dockerfile.simulator .
rm /tmp/Dockerfile.simulator
log_success "Simulator image created: dstack-simulator:test"

# Step 2: Build gateway if needed (musl static build)
if ! $SKIP_BUILD; then
    log_info "Building dstack-gateway (musl static)..."
    cd "$REPO_ROOT"
    cargo build --release -p dstack-gateway --target x86_64-unknown-linux-musl

    # Copy binary to e2e directory
    cp target/x86_64-unknown-linux-musl/release/dstack-gateway "$SCRIPT_DIR/"
    log_success "Gateway built: $SCRIPT_DIR/dstack-gateway"
fi

# Step 3: Create gateway docker image (alpine for musl)
log_info "Creating gateway docker image..."
cd "$SCRIPT_DIR"

cat > Dockerfile.gateway << 'EOF'
FROM alpine:latest

RUN apk add --no-cache \
    wireguard-tools \
    iproute2 \
    curl \
    ca-certificates

COPY dstack-gateway /usr/local/bin/dstack-gateway

RUN chmod +x /usr/local/bin/dstack-gateway

ENTRYPOINT ["/usr/local/bin/dstack-gateway", "-c", "/etc/gateway/gateway.toml"]
EOF

docker build -t dstack-gateway:test -f Dockerfile.gateway .
rm Dockerfile.gateway
log_success "Gateway image created: dstack-gateway:test"

# Step 4: Generate certificates if not exist
if [ ! -f "certs/gateway.crt" ]; then
    log_info "Generating test certificates..."
    ./setup.sh
    log_success "Certificates generated"
fi

# Step 5: Run docker compose
log_info "Starting e2e test environment..."
docker compose down -v --remove-orphans 2>/dev/null || true

export GATEWAY_IMAGE=dstack-gateway:test
export SIMULATOR_IMAGE=dstack-simulator:test

docker compose up -d mock-cf-dns-api pebble dstack-simulator
log_info "Waiting for mock services to be healthy..."
sleep 5

docker compose up -d gateway-1 gateway-2 gateway-3
log_info "Waiting for gateway cluster to be healthy..."
sleep 10

# Step 6: Run tests
log_info "Running tests..."
docker compose run --rm test-runner
TEST_EXIT_CODE=$?

# Step 7: Cleanup
if ! $KEEP_RUNNING; then
    log_info "Stopping containers..."
    docker compose down -v --remove-orphans
fi

if [ $TEST_EXIT_CODE -eq 0 ]; then
    log_success "All tests passed!"
else
    log_error "Tests failed with exit code: $TEST_EXIT_CODE"
fi

exit $TEST_EXIT_CODE
