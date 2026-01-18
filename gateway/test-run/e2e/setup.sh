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

# Build gateway Docker image
build_gateway_image() {
    local gateway_dir="$SCRIPT_DIR/../../.."

    if [[ -n "$SKIP_BUILD" ]]; then
        log_info "Skipping gateway build (SKIP_BUILD is set)"
        return 0
    fi

    log_info "Building dstack-gateway..."
    cd "$gateway_dir"
    cargo build --release -p dstack-gateway

    log_info "Building Docker image..."

    # Create a minimal Dockerfile for testing
    cat > "$SCRIPT_DIR/Dockerfile.gateway" << 'EOF'
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    iproute2 \
    wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY dstack-gateway /usr/local/bin/dstack-gateway

RUN chmod +x /usr/local/bin/dstack-gateway

WORKDIR /etc/gateway

ENTRYPOINT ["/usr/local/bin/dstack-gateway", "-c", "/etc/gateway/gateway.toml"]
EOF

    cp "$gateway_dir/target/release/dstack-gateway" "$SCRIPT_DIR/"
    docker build -t dstack-gateway:test -f "$SCRIPT_DIR/Dockerfile.gateway" "$SCRIPT_DIR"
    rm -f "$SCRIPT_DIR/dstack-gateway" "$SCRIPT_DIR/Dockerfile.gateway"

    log_info "Gateway Docker image built: dstack-gateway:test"
}

# Main
main() {
    log_info "Setting up E2E test environment..."

    generate_certs
    build_gateway_image

    log_info ""
    log_info "Setup complete! Run the tests with:"
    log_info "  docker compose up --abort-on-container-exit"
    log_info ""
    log_info "Or run individual services:"
    log_info "  docker compose up -d mock-cf-dns-api pebble"
    log_info "  docker compose up gateway-1 gateway-2 gateway-3"
    log_info ""
    log_info "View mock CF DNS API: http://localhost:18080"
    log_info "View Pebble mgmt:     https://localhost:15000"
}

main "$@"
