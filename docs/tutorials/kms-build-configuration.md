---
title: "KMS Build & Configuration"
description: "Build and configure the dstack Key Management Service"
section: "KMS Deployment"
stepNumber: 2
totalSteps: 3
lastUpdated: 2026-01-09
prerequisites:
  - contract-deployment
  - guest-image-setup
tags:
  - dstack
  - kms
  - cargo
  - build
  - configuration
difficulty: "advanced"
estimatedTime: "25 minutes"
---

# KMS Build & Configuration

This tutorial guides you through building and configuring the dstack Key Management Service (KMS). The KMS is a critical component that manages cryptographic keys for TEE applications.

## Prerequisites

Before starting, ensure you have:

- Completed [Contract Deployment](/tutorial/contract-deployment) with deployed KMS contract
- Completed [TDX & SGX Verification](/tutorial/tdx-sgx-verification) - **SGX must be verified before KMS deployment**
- Completed [Rust Toolchain Installation](/tutorial/rust-toolchain-installation)
- dstack repository cloned to ~/dstack

> **Important:** The KMS uses a `local_key_provider` that requires SGX to generate TDX attestation quotes. Without SGX properly configured (including Auto MP Registration in BIOS), KMS cannot bootstrap and will fail to generate cryptographic proofs of its TDX environment.


## What Gets Built

The dstack KMS provides:

| Component | Purpose |
|-----------|---------|
| **dstack-kms** | Main KMS binary - generates and stores cryptographic keys |
| **auth-eth** | Node.js service - verifies app permissions via smart contract |
| **kms.toml** | Configuration file for KMS settings |
| **auth-eth.env** | Environment file with Ethereum RPC credentials |
| **Docker image** | Containerized KMS for deployment in a CVM |
| **docker-compose.yml** | Deployment manifest for VMM |

> **Note:** KMS runs inside a Confidential Virtual Machine (CVM) to enable TDX attestation. The Docker image packages KMS for CVM deployment.

---

## Manual Build

> **Note:** The previous tutorial ([Contract Deployment](/tutorial/contract-deployment)) was run on your **local machine**. The remaining tutorials are run on your **TDX server**. SSH back in before continuing:
> ```bash
> ssh ubuntu@YOUR_SERVER_IP
> ```

If you prefer to build manually, follow these steps.

### Step 1: Build the KMS Binary

Build the KMS service using Cargo in release mode.

### Navigate to repository root

```bash
cd ~/dstack
```

### Build KMS in release mode

```bash
cargo build --release -p dstack-kms
```

This compilation will:
- Download and compile KMS dependencies
- Build the KMS binary with optimizations

### Verify the build

```bash
ls -lh ~/dstack/target/release/dstack-kms
```

Expected output (typically 20-30MB):
```
-rwxrwxr-x 1 ubuntu ubuntu 25M Nov 20 10:30 /home/ubuntu/dstack/target/release/dstack-kms
```

### Test the binary

```bash
~/dstack/target/release/dstack-kms --help
```

This displays available command-line options.

## Step 2: Install KMS to System Path

Install the KMS binary to a system-wide location.

### Copy to /usr/local/bin

```bash
sudo cp ~/dstack/target/release/dstack-kms /usr/local/bin/dstack-kms
sudo chmod 755 /usr/local/bin/dstack-kms
```

### Verify installation

```bash
which dstack-kms
dstack-kms --help
```

## Step 3: Create Configuration Directories

Create the directory structure for KMS configuration and certificates.

### Create directories

```bash
# Configuration directory
sudo mkdir -p /etc/kms

# Certificate directory
sudo mkdir -p /etc/kms/certs

# Runtime directories
sudo mkdir -p /var/run/kms
sudo mkdir -p /var/log/kms

# Set permissions
sudo chown -R $USER:$USER /etc/kms
sudo chown -R $USER:$USER /var/run/kms
sudo chown -R $USER:$USER /var/log/kms
```

### Verify directory structure

```bash
ls -la /etc/kms
```

You should see:
```
total 12
drwxr-xr-x 3 ubuntu ubuntu 4096 Nov 20 10:35 .
drwxr-xr-x 3 root   root   4096 Nov 20 10:35 ..
drwxr-xr-x 2 ubuntu ubuntu 4096 Nov 20 10:35 certs
```

## Step 4: Create KMS Configuration

Create the main KMS configuration file.

### Create kms.toml

```bash
cat > /etc/kms/kms.toml << 'EOF'
# dstack KMS Configuration
# See: https://github.com/Dstack-TEE/dstack

[default]
workers = 8
max_blocking = 64
ident = "DStack KMS"
temp_dir = "/tmp"
keep_alive = 10
log_level = "info"

# RPC Server Configuration
[rpc]
address = "0.0.0.0"
port = 9100

# TLS Certificate Configuration for RPC
[rpc.tls]
key = "/etc/kms/certs/rpc.key"
certs = "/etc/kms/certs/rpc.crt"

# Mutual TLS (mTLS) Configuration
[rpc.tls.mutual]
ca_certs = "/etc/kms/certs/tmp-ca.crt"
mandatory = false

# Core KMS Configuration
[core]
cert_dir = "/etc/kms/certs"
subject_postfix = ".dstack"
# Intel PCCS URL for TDX quote verification
pccs_url = "https://pccs.phala.network/sgx/certification/v4"

# Authentication API Configuration
# Uses webhook to query Ethereum contract via auth-eth service
[core.auth_api]
type = "webhook"

[core.auth_api.webhook]
url = "http://127.0.0.1:9200"

# Onboarding Configuration
[core.onboard]
enabled = true
auto_bootstrap_domain = ""
address = "0.0.0.0"
port = 9100
EOF
```

### Configuration explained

| Section | Key | Description |
|---------|-----|-------------|
| `[default]` | `workers` | Number of worker threads (default: 8) |
| `[default]` | `log_level` | Logging level: debug, info, warn, error |
| `[rpc]` | `address` | RPC server bind address |
| `[rpc]` | `port` | RPC server port (9100) |
| `[core]` | `cert_dir` | Directory for certificates |
| `[core]` | `pccs_url` | Local PCCS via host bridge (`10.0.2.2`) for quote verification |
| `[core.auth_api]` | `url` | Auth-eth webhook service URL |
| `[core.onboard]` | `enabled` | Enable bootstrap/onboard mode |

## Step 5: Build Auth-ETH Service

The KMS requires the auth-eth service to query the Ethereum contract for authorization.

### Install Node.js

The auth-eth service requires Node.js. Install Node.js 20.x from NodeSource:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

Verify the installation:

```bash
node --version
npm --version
```

You should see Node.js v20.x and npm v10.x (or later).

### Navigate to auth-eth directory

```bash
cd ~/dstack/kms/auth-eth
```

### Install dependencies

```bash
npm install
```

### Build TypeScript

```bash
npx tsc --project tsconfig.json
```

### Verify build

```bash
ls -la dist/src/
```

You should see `main.js` and other compiled files.

## Step 6: Create Auth-ETH Configuration

Create environment configuration for the auth-eth service.

### Get contract address from deployment

The contract address was created during [Contract Deployment](/tutorial/contract-deployment), which ran on your **local machine**. You need to transfer this address to your server.

**Option A: Read from saved secrets**

If you saved the contract address in the previous tutorial:

```bash
KMS_CONTRACT_ADDRESS=$(cat ~/.dstack/secrets/kms-contract-address)
echo "Contract address: $KMS_CONTRACT_ADDRESS"
```

**Option B: Check Etherscan**

If you've lost the address, find it on [Sepolia Etherscan](https://sepolia.etherscan.io/) by searching for your wallet address and looking at recent contract deployments.

### Create environment file

```bash
cat > /etc/kms/auth-eth.env << EOF
# Auth-ETH Service Configuration

# Server settings
HOST=127.0.0.1
PORT=9200

# Ethereum RPC endpoint (Sepolia testnet)
ETH_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com

# KMS Authorization Contract Address
KMS_CONTRACT_ADDR=$KMS_CONTRACT_ADDRESS
EOF
```

### Secure the file

```bash
chmod 600 /etc/kms/auth-eth.env
```

### Verify configuration

```bash
cat /etc/kms/auth-eth.env
```

## Step 7: Create Docker Image for CVM Deployment

KMS runs inside a Confidential Virtual Machine (CVM) to enable TDX attestation. We need to create a Docker image that packages KMS and auth-eth together.

### Create deployment directory

```bash
mkdir -p ~/kms-deployment
cd ~/kms-deployment
```

### Create QCNL Configuration

The CVM needs to know how to reach a PCCS for attestation. We use Phala Network's public PCCS:

```bash
cat > sgx_default_qcnl.conf << 'EOF'
{
  "pccs_url": "https://pccs.phala.network/sgx/certification/v4/",
  "use_secure_cert": false,
  "retry_times": 6,
  "retry_delay": 10
}
EOF
```

### Create .dockerignore

Exclude `node_modules` from the build context to avoid transferring hundreds of megabytes:

```bash
cat > .dockerignore << 'EOF'
auth-eth/node_modules
EOF
```

### Create Dockerfile

The Dockerfile bakes all configuration into the image for reliable CVM deployment:

```bash
cat > Dockerfile << 'EOF'
# KMS Docker Image for CVM Deployment
# Extract dstack-acpi-tables and QEMU BIOS files from the official builder image.
# These are required for OS image verification (computing expected TDX measurements).
FROM dstacktee/dstack-kms@sha256:11ac59f524a22462ccd2152219b0bec48a28ceb734e32500152d4abefab7a62a AS official

FROM ubuntu:24.04

# Install runtime dependencies
# libglib2.0-0t64, libpixman-1-0, and libslirp0 are required by dstack-acpi-tables (QEMU binary)
RUN apt-get update && \
    apt-get install -y ca-certificates curl libglib2.0-0t64 libpixman-1-0 libslirp0 && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js 20.x for auth-eth
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /etc/kms/certs /etc/kms/images /var/run/kms /var/log/kms

# Copy dstack-acpi-tables from official image (needed for OS image verification)
COPY --from=official /usr/local/bin/dstack-acpi-tables /usr/local/bin/dstack-acpi-tables
COPY --from=official /usr/local/share/qemu /usr/local/share/qemu

# Copy KMS binary
COPY dstack-kms /usr/local/bin/dstack-kms
RUN chmod 755 /usr/local/bin/dstack-kms

# Copy configuration files (baked into image)
COPY kms.toml /etc/kms/kms.toml
COPY auth-eth.env /etc/kms/auth-eth.env
COPY sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf

# Copy auth-eth service and install dependencies
COPY auth-eth /opt/auth-eth
RUN cd /opt/auth-eth && npm install --production

# Copy startup script
COPY start-kms.sh /usr/local/bin/start-kms.sh
RUN chmod 755 /usr/local/bin/start-kms.sh

EXPOSE 9100

ENTRYPOINT ["/usr/local/bin/start-kms.sh"]
EOF
```

### Create startup script

The startup script runs both KMS and auth-eth services:

```bash
cat > start-kms.sh << 'EOF'
#!/bin/bash
set -e

# Start auth-eth in background
cd /opt/auth-eth
node dist/src/main.js &
AUTH_ETH_PID=$!

# Wait for auth-eth to be ready
sleep 2

# Start KMS (foreground)
exec /usr/local/bin/dstack-kms --config /etc/kms/kms.toml
EOF
```

### Create CVM-specific kms.toml

The KMS config for CVM deployment enables TDX attestation:

```bash
cat > kms.toml << 'EOF'
# dstack KMS Configuration (CVM Deployment)

[default]
workers = 8
max_blocking = 64
ident = "DStack KMS"
temp_dir = "/tmp"
keep_alive = 10
log_level = "info"

# RPC Server Configuration
[rpc]
address = "0.0.0.0"
port = 9100

# TLS Certificate Configuration for RPC
[rpc.tls]
key = "/etc/kms/certs/rpc.key"
certs = "/etc/kms/certs/rpc.crt"

# Mutual TLS (mTLS) Configuration
[rpc.tls.mutual]
ca_certs = "/etc/kms/certs/tmp-ca.crt"
mandatory = false

# Core KMS Configuration
[core]
cert_dir = "/etc/kms/certs"
subject_postfix = ".dstack"
pccs_url = "https://pccs.phala.network/sgx/certification/v4"

# OS Image Verification
# KMS downloads OS images to compute expected TDX measurements
[core.image]
verify = true
cache_dir = "/etc/kms/images"
download_url = "https://download.dstack.org/os-images/mr_{OS_IMAGE_HASH}.tar.gz"
download_timeout = "2m"

# Authentication API Configuration
[core.auth_api]
type = "webhook"

[core.auth_api.webhook]
url = "http://127.0.0.1:9200"

# Onboarding Configuration
[core.onboard]
enabled = true
# Empty domain = manual bootstrap mode (ensures bootstrap-info.json is written)
auto_bootstrap_domain = ""
# Enable TDX quotes - works because KMS runs in CVM
address = "0.0.0.0"
port = 9100
EOF
```

> **Why empty `auto_bootstrap_domain`?** With an empty domain, KMS starts in "onboard mode" — a plain HTTP server that waits for you to trigger bootstrap via an RPC call. This ensures `bootstrap-info.json` is written to disk, which is required for on-chain KMS registration. You'll provide the domain during the bootstrap step in [KMS CVM Deployment](/tutorial/kms-cvm-deployment).

### Copy build artifacts and configuration

```bash
# Copy KMS binary
cp ~/dstack/target/release/dstack-kms .

# Copy auth-eth service
cp -r ~/dstack/kms/auth-eth auth-eth

# Copy auth-eth environment config
cp /etc/kms/auth-eth.env .
```

### Build Docker image

```bash
docker build -t dstack-kms:latest .
```

### Verify image was created

```bash
docker images dstack-kms
```

Expected output:
```
REPOSITORY    TAG       IMAGE ID       CREATED          SIZE
dstack-kms    latest    abc123def456   10 seconds ago   ~300MB
```

### Push to local registry

Tag and push the image to your local Docker registry so CVMs can pull it during boot. Push directly to `localhost:5000` (HAProxy only handles read access for CVM pulls):

```bash
# Tag for local registry (push via localhost, pull via HAProxy domain)
docker tag dstack-kms:latest localhost:5000/dstack-kms:latest
docker tag dstack-kms:latest localhost:5000/dstack-kms:fixed

# Push both tags
docker push localhost:5000/dstack-kms:latest
docker push localhost:5000/dstack-kms:fixed
```

Verify the image is in the registry (via HAProxy):

```bash
curl -sk https://registry.yourdomain.com/v2/dstack-kms/tags/list
```

Expected output:
```json
{"name":"dstack-kms","tags":["fixed","latest"]}
```

## Step 8: Create docker-compose.yml

Create the deployment manifest for VMM deployment.

### Create docker-compose.yml

```bash
cat > docker-compose.yml << 'EOF'
# KMS Deployment Manifest for dstack CVM
# Deploy via VMM web interface at http://localhost:9080

services:
  kms:
    image: dstack-kms:latest
    ports:
      - "9100:9100"
    volumes:
      # Mount config file from local directory
      - ./kms.toml:/etc/kms/kms.toml:ro
      - ./auth-eth.env:/etc/kms/auth-eth.env:ro
      # Named volume for persistent certificates
      - kms-certs:/etc/kms/certs
    environment:
      - RUST_LOG=info
    restart: unless-stopped

volumes:
  kms-certs:
    # Certificates persist across container restarts
EOF
```

### Verify deployment files

```bash
ls -la ~/kms-deployment/
```

You should have:
- `Dockerfile` - Container build definition
- `dstack-kms` - KMS binary
- `auth-eth/` - Auth-eth service directory
- `start-kms.sh` - Startup script
- `docker-compose.yml` - Deployment manifest
- `kms.toml` - KMS configuration
- `auth-eth.env` - Auth-eth environment
- `sgx_default_qcnl.conf` - QCNL configuration for CVM PCCS access

## Step 9: Verify Configuration

### Check KMS configuration syntax

The KMS loads configuration using the Rocket framework's Figment library:

```bash
# Validate TOML syntax
cat /etc/kms/kms.toml | python3 -c "import sys, tomllib; tomllib.load(sys.stdin.buffer); print('Valid TOML')"
```

### Check auth-eth configuration

```bash
# Source and verify environment
source /etc/kms/auth-eth.env
echo "ETH_RPC_URL: ${ETH_RPC_URL:0:30}..."
echo "KMS_CONTRACT_ADDR: $KMS_CONTRACT_ADDR"
```

### Test RPC connectivity

```bash
source /etc/kms/auth-eth.env
curl -s -X POST "$ETH_RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | \
  jq .
```

Expected output shows the current block number.

### Verify contract exists

```bash
source /etc/kms/auth-eth.env
curl -s -X POST "$ETH_RPC_URL" \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getCode\",\"params\":[\"$KMS_CONTRACT_ADDR\",\"latest\"],\"id\":1}" | \
  jq -r 'if .result != "0x" then "✓ Contract found" else "✗ Contract not found" end'
```

---

## Architecture Overview

### Component Interaction

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│   TEE App   │────►│     KMS     │────►│   Auth-ETH   │
└─────────────┘     └─────────────┘     └──────────────┘
       │                   │                    │
       │                   │                    ▼
       │                   │            ┌──────────────┐
       │                   │            │   Ethereum   │
       │                   │            │   (Sepolia)  │
       │                   │            └──────────────┘
       │                   │                    │
       │                   ▼                    │
       │            ┌─────────────┐             │
       └───────────►│    VMM      │◄────────────┘
                    └─────────────┘
```

### Data Flow

1. **TEE App** requests key from **KMS**
2. **KMS** calls **Auth-ETH** webhook to verify authorization
3. **Auth-ETH** queries **Ethereum** smart contract
4. If authorized, **KMS** returns key to app
5. **VMM** orchestrates the overall TEE environment

## Troubleshooting

For detailed solutions, see the [KMS Deployment Troubleshooting Guide](/tutorial/troubleshooting-kms-deployment#kms-build--configuration-issues):

- [Build fails with missing dependencies](/tutorial/troubleshooting-kms-deployment#build-fails-with-missing-dependencies)
- [Configuration file not found](/tutorial/troubleshooting-kms-deployment#configuration-file-not-found)
- [Auth-eth npm install fails](/tutorial/troubleshooting-kms-deployment#auth-eth-npm-install-fails)
- [Invalid TOML syntax](/tutorial/troubleshooting-kms-deployment#invalid-toml-syntax)
- [RPC connection failed](/tutorial/troubleshooting-kms-deployment#rpc-connection-failed)
- [Contract address not set](/tutorial/troubleshooting-kms-deployment#contract-address-not-set)

## Next Steps

With KMS built and containerized, proceed to CVM deployment:

- [KMS CVM Deployment](/tutorial/kms-cvm-deployment) - Deploy KMS as a Confidential VM

## Additional Resources

- [dstack GitHub Repository](https://github.com/Dstack-TEE/dstack)
- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [Rocket Framework](https://rocket.rs/)
- [Figment Configuration](https://docs.rs/figment/)
