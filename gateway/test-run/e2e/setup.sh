#!/bin/bash
# SPDX-FileCopyrightText: 2024-2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Setup script for E2E test environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Generate self-signed certificates for RPC TLS
generate_certs() {
    local certs_dir="$SCRIPT_DIR/certs"

    if [[ -f "$certs_dir/gateway-rpc.cert" ]]; then
        log_info "Certificates already exist, skipping generation"
        return 0
    fi

    log_info "Generating self-signed certificates for RPC TLS..."
    mkdir -p "$certs_dir"

    # Generate CA key and certificate
    openssl genrsa -out "$certs_dir/gateway-ca.key" 4096
    openssl req -x509 -new -nodes \
        -key "$certs_dir/gateway-ca.key" \
        -sha256 -days 3650 \
        -out "$certs_dir/gateway-ca.cert" \
        -subj "/CN=Gateway Test CA/O=Test/C=US"

    # Generate server key
    openssl genrsa -out "$certs_dir/gateway-rpc.key" 2048

    # Generate server CSR with SANs
    cat > "$certs_dir/server.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = gateway.test.local

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = gateway.test.local
DNS.2 = gateway-1
DNS.3 = gateway-2
DNS.4 = gateway-3
DNS.5 = localhost
IP.1 = 127.0.0.1
IP.2 = 172.30.0.21
IP.3 = 172.30.0.22
IP.4 = 172.30.0.23
EOF

    openssl req -new \
        -key "$certs_dir/gateway-rpc.key" \
        -out "$certs_dir/gateway-rpc.csr" \
        -config "$certs_dir/server.cnf"

    # Sign the certificate
    openssl x509 -req \
        -in "$certs_dir/gateway-rpc.csr" \
        -CA "$certs_dir/gateway-ca.cert" \
        -CAkey "$certs_dir/gateway-ca.key" \
        -CAcreateserial \
        -out "$certs_dir/gateway-rpc.cert" \
        -days 365 \
        -sha256 \
        -extensions v3_req \
        -extfile "$certs_dir/server.cnf"

    # Clean up
    rm -f "$certs_dir/gateway-rpc.csr" "$certs_dir/server.cnf" "$certs_dir/gateway-ca.srl"

    log_info "Certificates generated in $certs_dir"
}

# Build simulator (musl static)
build_simulator() {
    local repo_dir="$SCRIPT_DIR/../../.."

    if [[ -n "$SKIP_SIMULATOR_BUILD" ]]; then
        log_info "Skipping simulator build (SKIP_SIMULATOR_BUILD is set)"
        return 0
    fi

    log_info "Building dstack-simulator (musl static)..."
    cd "$repo_dir"
    cargo build --release -p dstack-guest-agent --target x86_64-unknown-linux-musl

    # Copy binary to simulator directory
    cp target/x86_64-unknown-linux-musl/release/dstack-guest-agent sdk/simulator/
    ln -sf dstack-guest-agent sdk/simulator/dstack-simulator

    log_info "Simulator built: sdk/simulator/dstack-simulator"

    # Create simulator docker image (alpine for musl)
    log_info "Building simulator Docker image..."
    cat > /tmp/Dockerfile.simulator << 'EOF'
FROM alpine:latest
RUN apk add --no-cache curl ca-certificates
WORKDIR /app
EOF
    docker build -t dstack-simulator:test -f /tmp/Dockerfile.simulator .
    rm /tmp/Dockerfile.simulator

    log_info "Simulator Docker image built: dstack-simulator:test"
}

# Build gateway Docker image (musl static)
build_gateway_image() {
    local repo_dir="$SCRIPT_DIR/../../.."

    if [[ -n "$SKIP_BUILD" ]]; then
        log_info "Skipping gateway build (SKIP_BUILD is set)"
        return 0
    fi

    log_info "Building dstack-gateway (musl static)..."
    cd "$repo_dir"
    cargo build --release -p dstack-gateway --target x86_64-unknown-linux-musl

    log_info "Building Docker image..."

    # Create a minimal Dockerfile for testing (alpine for musl)
    cat > "$SCRIPT_DIR/Dockerfile.gateway" << 'EOF'
FROM alpine:latest

RUN apk add --no-cache \
    ca-certificates \
    curl \
    iproute2 \
    wireguard-tools

COPY dstack-gateway /usr/local/bin/dstack-gateway

RUN chmod +x /usr/local/bin/dstack-gateway

WORKDIR /etc/gateway

ENTRYPOINT ["/usr/local/bin/dstack-gateway", "-c", "/etc/gateway/gateway.toml"]
EOF

    cp "$repo_dir/target/x86_64-unknown-linux-musl/release/dstack-gateway" "$SCRIPT_DIR/"
    docker build -t dstack-gateway:test -f "$SCRIPT_DIR/Dockerfile.gateway" "$SCRIPT_DIR"
    rm -f "$SCRIPT_DIR/dstack-gateway" "$SCRIPT_DIR/Dockerfile.gateway"

    log_info "Gateway Docker image built: dstack-gateway:test"
}

# Main
main() {
    log_info "Setting up E2E test environment..."

    generate_certs
    build_simulator
    build_gateway_image

    log_info ""
    log_info "Setup complete! Run the tests with:"
    log_info "  ./run-e2e.sh"
    log_info ""
    log_info "Or run individual services:"
    log_info "  docker compose up -d mock-cf-dns-api pebble dstack-simulator"
    log_info "  docker compose up gateway-1 gateway-2 gateway-3"
    log_info ""
    log_info "View mock CF DNS API: http://localhost:18080"
    log_info "View Pebble mgmt:     https://localhost:15000"
    log_info "View Simulator:       http://localhost:18090"
}

main "$@"
