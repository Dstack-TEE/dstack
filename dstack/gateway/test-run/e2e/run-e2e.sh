#!/bin/bash
# SPDX-FileCopyrightText: 2024-2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# E2E test runner for dstack-gateway
# Builds gateway image, then runs the test suite using real TDX endpoint

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TEST_RUN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# The attestation fixture is its own long-lived project: one simulator, one
# collateral service, one seed. Both suites reference its network and volumes
# rather than each building a copy, so the seed that signs quotes and the seed
# that derives the verifying roots cannot drift apart.
#
# Defined here, above the EXIT trap that calls it -- a cleanup handler naming a
# function defined later fails on exactly the error paths it exists for.
fixture_compose() {
    docker compose -p dstack-fixture -f "$TEST_RUN_DIR/attestation/fixture.yml" "$@"
}

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
KEEP_RUNNING=false
CLEAN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
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
        down)
            cd "$SCRIPT_DIR"
            log_info "Stopping containers..."
            docker compose down -v --remove-orphans 2>/dev/null || true
            log_success "Containers stopped"
            exit 0
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS|COMMAND]"
            echo ""
            echo "Commands:"
            echo "  down                   Stop all containers"
            echo ""
            echo "Options:"
            echo "  --skip-build           Skip building gateway image"
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

# Cleanup function
# Two runs share one compose project, one set of container names and one work
# directory, so a second run tears down what the first is using. The damage does
# not look like a collision -- it looks like flaky tests, because state vanishes
# mid-run. Refuse to start instead.
# Locked on the directory, not on a file inside it. Deleting a lock FILE does
# not release the lock, it detaches it: the holder keeps its inode while the
# next run creates a fresh one and flocks that successfully. Three runs of the
# cluster suite overlapped exactly that way -- each wiping the others' state,
# with the failures reading as flaky sync rather than as a collision -- because
# a "clean up before rerunning" step had removed the lock file by name.
exec 9<"$SCRIPT_DIR"
if ! flock -n 9; then
    log_error "another run of this suite is already in progress ($SCRIPT_DIR)"
    exit 1
fi

# Probed BEFORE the trap is installed, not next to the `up` that follows it: any
# failure in between would otherwise run cleanup with the variable unset, take
# the `:-0` default, and tear down a fixture another suite was using.
FIXTURE_WAS_UP=$(fixture_compose ps -q 2>/dev/null | wc -l)

# shellcheck disable=SC2317  # the body runs from the EXIT trap installed below
cleanup() {
    if ! $KEEP_RUNNING; then
        log_info "Stopping containers..."
        docker compose down -v --remove-orphans 2>/dev/null || true
        # Only if this run started it. The fixture is meant to outlive a single
        # suite; tearing down one this run found already up is what made the
        # next run fail with "network dstack-attestation declared as external,
        # but could not be found".
        if [ "${FIXTURE_WAS_UP:-0}" -eq 0 ]; then
            fixture_compose down -v --remove-orphans 2>/dev/null || true
        fi
    fi
}

# Trap to ensure cleanup on exit/interrupt
trap cleanup EXIT

# Clean up if requested
if $CLEAN; then
    log_info "Cleaning up..."
    docker compose down -v --remove-orphans 2>/dev/null || true
    docker rmi dstack-gateway:test 2>/dev/null || true
    log_success "Cleanup complete"
    exit 0
fi

# Stop any running containers first (to release file handles)
log_info "Stopping any existing containers..."
docker compose down -v --remove-orphans 2>/dev/null || true

# Step 1: Build gateway if needed (musl static build)
if ! $SKIP_BUILD; then
    log_info "Building dstack-gateway (musl static)..."
    cd "$REPO_ROOT"
    cargo build --release -p dstack-gateway --target x86_64-unknown-linux-musl

    # Copy binary to e2e directory
    cp target/x86_64-unknown-linux-musl/release/dstack-gateway "$SCRIPT_DIR/"
    log_success "Gateway built: $SCRIPT_DIR/dstack-gateway"
fi

# Step 2: Create gateway docker image (alpine for musl)
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

RUN chmod +x /usr/local/bin/dstack-gateway && \
    mkdir -p /etc/gateway/certs /var/lib/gateway

ENTRYPOINT ["/usr/local/bin/dstack-gateway", "-c", "/etc/gateway/gateway.toml"]
EOF

docker build -t dstack-gateway:test -f Dockerfile.gateway .
rm Dockerfile.gateway
log_success "Gateway image created: dstack-gateway:test"

# Step 3: Run docker compose
log_info "Starting e2e test environment..."

export GATEWAY_IMAGE=dstack-gateway:test

# Build the mock rather than trusting whatever carries its tag. `image:` plus
# `build:` means compose reuses a local tag if one exists, and this tag is
# shared with the full-stack suite, so a stale copy from an older checkout
# would be picked up silently -- and a mock that does not answer TCP fails
# every challenge now that Pebble actually validates them.
# Build every image rather than trusting whatever carries its tag. `image:` plus
# `build:` means compose reuses a local tag if one exists, and these tags are
# shared with other suites and other checkouts, so a stale copy would be picked
# up silently -- a mock that does not answer TCP fails every challenge now that
# Pebble validates them, and a stale simulator issues certificates from an older
# cert-client, which is the code path the cluster's app_id pinning depends on.
log_info "Building the mock services and the guest agent simulator..."
docker compose build
fixture_compose build

log_info "Starting the attestation fixture..."
fixture_compose up -d --wait

docker compose up -d mock-cf-dns-api pebble
log_info "Waiting for mock services to be healthy..."
sleep 5

docker compose up -d gateway-1 gateway-2 gateway-3
log_info "Waiting for gateway cluster to be healthy..."
sleep 10

# Step 4: Run tests
log_info "Running tests..."
# `set -e` is on, so a plain call would abort the script the moment the suite
# fails and the report below would be unreachable -- the failure still exits
# non-zero, but silently. Capture the status instead of inheriting it.
TEST_EXIT_CODE=0
docker compose run --rm test-runner || TEST_EXIT_CODE=$?

# Step 5: Report result (cleanup handled by trap)
if [ $TEST_EXIT_CODE -eq 0 ]; then
    log_success "All tests passed!"
else
    log_error "Tests failed with exit code: $TEST_EXIT_CODE"
fi

exit $TEST_EXIT_CODE
