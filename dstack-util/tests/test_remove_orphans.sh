#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

# Test script for remove-orphans command (both online and offline modes)
# Uses real docker compose to create containers for accurate testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DSTACK_UTIL="$PROJECT_ROOT/target/release/dstack-util"
TEST_DIR=$(mktemp -d)
DOCKER_ROOT="/var/lib/docker"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Project name for tests
PROJECT_NAME="test-orphan-$$"

cleanup() {
	echo -e "${YELLOW}Cleaning up...${NC}"
	rm -rf "$TEST_DIR"
	# Clean up test containers
	docker compose -f "$TEST_DIR/docker-compose.yaml" down -v 2>/dev/null || true
	docker rm -f "${PROJECT_NAME}-old" 2>/dev/null || true
}

trap cleanup EXIT

echo -e "${YELLOW}=== Test remove-orphans commands ===${NC}"
echo "Test directory: $TEST_DIR"
echo "Project root: $PROJECT_ROOT"
echo "Project name: $PROJECT_NAME"

# Check if Docker is available
if ! docker info >/dev/null 2>&1; then
	echo -e "${RED}ERROR: Docker daemon not available${NC}"
	exit 1
fi

# Build dstack-util in release mode
echo -e "\n${YELLOW}Building dstack-util...${NC}"
cargo build --release --package dstack-util --manifest-path "$PROJECT_ROOT/Cargo.toml"

if [ ! -f "$DSTACK_UTIL" ]; then
	echo -e "${RED}ERROR: dstack-util binary not found at $DSTACK_UTIL${NC}"
	exit 1
fi

# ============================================
# Setup: Create containers using docker compose
# ============================================
echo -e "\n${YELLOW}=== Setup: Creating test containers with docker compose ===${NC}"

# Create compose file with web, db, and old-service
cat >"$TEST_DIR/docker-compose-full.yaml" <<EOF
name: ${PROJECT_NAME}
services:
  web:
    image: alpine:latest
    command: sleep infinity
  db:
    image: alpine:latest
    command: sleep infinity
  old-service:
    image: alpine:latest
    command: sleep infinity
EOF

# Start all containers
echo "Starting all containers (web, db, old-service)..."
docker compose -f "$TEST_DIR/docker-compose-full.yaml" up -d

# Wait for containers to be created
sleep 2

# Verify containers exist
echo "Containers created:"
docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" --format "table {{.Names}}\t{{.Status}}"

# Stop docker daemon to test offline mode
echo -e "\n${YELLOW}Stopping Docker daemon for offline test...${NC}"
sudo systemctl stop docker

# Wait for docker to stop
sleep 2

# ============================================
# Test 1: Offline mode with real Docker data
# ============================================
echo -e "\n${YELLOW}=== Test 1: Offline mode (remove-orphans --no-dockerd) ===${NC}"

# Create compose file with only web and db (old-service removed)
cat >"$TEST_DIR/docker-compose.yaml" <<EOF
name: ${PROJECT_NAME}
services:
  web:
    image: alpine:latest
    command: sleep infinity
  db:
    image: alpine:latest
    command: sleep infinity
EOF

# Test dry-run mode
echo -e "\n${YELLOW}Testing offline dry-run mode...${NC}"
OUTPUT=$(sudo "$DSTACK_UTIL" remove-orphans --no-dockerd -f "$TEST_DIR/docker-compose.yaml" -d "$DOCKER_ROOT" -n 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "would remove orphaned container old-service"; then
	echo -e "${GREEN}✓ Dry-run correctly identified orphaned container${NC}"
else
	echo -e "${RED}✗ Dry-run failed to identify orphaned container${NC}"
	sudo systemctl start docker
	exit 1
fi

# Test actual removal
echo -e "\n${YELLOW}Testing offline actual removal...${NC}"
OUTPUT=$(sudo "$DSTACK_UTIL" remove-orphans --no-dockerd -f "$TEST_DIR/docker-compose.yaml" -d "$DOCKER_ROOT" 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "removing orphaned container old-service"; then
	echo -e "${GREEN}✓ Removal correctly identified orphaned container${NC}"
else
	echo -e "${RED}✗ Removal failed to identify orphaned container${NC}"
	sudo systemctl start docker
	exit 1
fi

# ============================================
# Restart Docker and verify
# ============================================
echo -e "\n${YELLOW}Restarting Docker daemon...${NC}"
sudo systemctl start docker

# Wait for docker to start
sleep 3

# Verify old-service container is gone
echo -e "\n${YELLOW}Verifying results after Docker restart...${NC}"
echo "Remaining containers:"
docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" --format "table {{.Names}}\t{{.Status}}"

if docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" --format "{{.Names}}" | grep -q "old-service"; then
	echo -e "${RED}✗ old-service container still exists${NC}"
	exit 1
else
	echo -e "${GREEN}✓ old-service container was removed${NC}"
fi

# Verify web and db containers still exist
if docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" --format "{{.Names}}" | grep -q "web"; then
	echo -e "${GREEN}✓ web container still exists${NC}"
else
	echo -e "${RED}✗ web container was incorrectly removed${NC}"
	exit 1
fi

if docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" --format "{{.Names}}" | grep -q "db"; then
	echo -e "${GREEN}✓ db container still exists${NC}"
else
	echo -e "${RED}✗ db container was incorrectly removed${NC}"
	exit 1
fi

# ============================================
# Test 2: Online mode (with Docker daemon)
# ============================================
echo -e "\n${YELLOW}=== Test 2: Online mode (remove-orphans) ===${NC}"

# Create another orphan container using docker run
echo "Creating orphan container for online test..."
docker run -d --name "${PROJECT_NAME}-old" \
	--label "com.docker.compose.project=${PROJECT_NAME}" \
	--label "com.docker.compose.service=another-old-service" \
	alpine:latest sleep infinity

echo "Containers before online removal:"
docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" --format "table {{.Names}}\t{{.Status}}"

# Test dry-run
echo -e "\n${YELLOW}Testing online dry-run mode...${NC}"
OUTPUT=$("$DSTACK_UTIL" remove-orphans -f "$TEST_DIR/docker-compose.yaml" -n 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "would remove orphaned container another-old-service"; then
	echo -e "${GREEN}✓ Online dry-run correctly identified orphaned container${NC}"
else
	echo -e "${RED}✗ Online dry-run failed to identify orphaned container${NC}"
	exit 1
fi

# Verify orphan still exists after dry-run
if docker ps -a --format "{{.Names}}" | grep -q "${PROJECT_NAME}-old"; then
	echo -e "${GREEN}✓ Online dry-run did not remove container${NC}"
else
	echo -e "${RED}✗ Online dry-run incorrectly removed container${NC}"
	exit 1
fi

# Test actual removal
echo -e "\n${YELLOW}Testing online actual removal...${NC}"
OUTPUT=$("$DSTACK_UTIL" remove-orphans -f "$TEST_DIR/docker-compose.yaml" 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "removing orphaned container another-old-service"; then
	echo -e "${GREEN}✓ Online removal correctly identified orphaned container${NC}"
else
	echo -e "${RED}✗ Online removal failed to identify orphaned container${NC}"
	exit 1
fi

# Verify orphan was removed
if ! docker ps -a --format "{{.Names}}" | grep -q "${PROJECT_NAME}-old"; then
	echo -e "${GREEN}✓ Orphaned container was removed${NC}"
else
	echo -e "${RED}✗ Orphaned container was NOT removed${NC}"
	exit 1
fi

# Verify other containers still exist
echo "Containers after online removal:"
docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" --format "table {{.Names}}\t{{.Status}}"

# Final cleanup
echo -e "\n${YELLOW}Final cleanup...${NC}"
docker compose -f "$TEST_DIR/docker-compose.yaml" down -v 2>/dev/null || true

echo -e "\n${GREEN}=== All tests passed! ===${NC}"
