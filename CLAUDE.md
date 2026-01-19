# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

dstack is a developer-friendly, security-first framwwork for deploying containerized applications into Intel TDX (Trust Domain Extensions) Trusted Execution Environments (TEEs). The system provides end-to-end security through hardware-rooted attestation, automated key management, and zero-trust networking.

## Architecture

dstack consists of several core components that interact to provide TEE-based container deployment:

### Core Components

- **`dstack-vmm`** (`vmm/`): Virtual Machine Manager that runs on bare-metal TDX hosts. Orchestrates CVM lifecycle, manages QEMU processes, allocates resources, parses docker-compose files, and provides a web UI (port 9080) for deployment.

- **`dstack-kms`** (`kms/`): Key Management System that handles cryptographic key provisioning after TDX quote verification. Derives keys deterministically per application identity and enforces authorization policies defined in smart contracts on Ethereum.

- **`dstack-gateway`** (`gateway/`): Reverse proxy providing zero-trust network access. Handles TLS termination, automated ACME certificate provisioning, and traffic routing via ingress mapping rules.

- **`dstack-guest-agent`** (`guest-agent/`): Runs inside each CVM to provide runtime services including Docker Compose lifecycle management, TDX quote generation, key provisioning from KMS, and log aggregation. Exposes API via Unix socket at `/var/run/dstack.sock`.

### Communication Protocols

- **RA-TLS**: Remote Attestation TLS used for all inter-CVM communication, embedding TDX quotes in X.509 certificates for mutual authentication
- **`prpc`**: Protocol Buffers-based RPC framework used across all service APIs
- **`vsock`**: Host-guest communication channel for metadata and configuration
- **Unix Domain Sockets**: Used for local management (e.g., `vmm.sock`)

### Additional Components

- **`certbot`** (`certbot/`): Automated ACME DNS-01 certificate management
- **`ct_monitor`** (`ct_monitor/`): Certificate Transparency log monitoring
- **`verifier`** (`verifier/`): TDX quote verification service using `dcap-qvl`
- **`supervisor`** (`supervisor/`): Process supervision inside CVMs
- **SDKs** (`sdk/`): Client SDKs in Rust, Python, Go, and JavaScript for interacting with guest-agent APIs

## Build Commands

### Rust Components

```bash
# Build all components
cargo build --release

# Build specific components
cargo build --release -p dstack-vmm
cargo build --release -p dstack-kms
cargo build --release -p dstack-gateway
cargo build --release -p dstack-guest-agent

# Check code
cargo check --all-features

# Format code
cargo fmt --all

# Lint with Clippy
cargo clippy -- -D warnings --allow unused_variables
```

### Ethereum Smart Contracts (KMS Auth)

```bash
cd kms/auth-eth
npm install
npm run build          # Compile TypeScript
npm test              # Run tests
npm run test:coverage # Run tests with coverage

# Hardhat commands
npx hardhat compile
npx hardhat test
npx hardhat node  # Start local node
```

### Python SDK

```bash
cd sdk/python
make install  # Install dependencies
make test     # Run tests
```

## Test Commands

### Running All Tests

```bash
# Run all Rust tests (requires simulator)
./run-tests.sh
```

This script:
1. Builds the SDK simulator (`sdk/simulator/`)
2. Starts the simulator in background
3. Sets `DSTACK_SIMULATOR_ENDPOINT` and `TAPPD_SIMULATOR_ENDPOINT`
4. Runs `cargo test --all-features -- --show-output`

### Running Specific Tests

```bash
# Run tests for a specific package
cargo test -p dstack-kms --all-features

# Run a specific test
cargo test --all-features test_name

# Run tests with output
cargo test --all-features -- --show-output --test-threads=1
```

### Foundry Tests (Ethereum Contracts)

```bash
cd kms/auth-eth

# Run all Foundry tests
forge test

# Run with verbosity
forge test -vv

# Run specific test contract
forge test --match-contract UpgradesWithPluginTest -vv

# Clean build artifacts
forge clean
```

## Code Style Guidelines

### Logging and Error Messages

- **Never capitalize** the first letter of log messages and error messages
- Example: `log::info!("starting server on port {}", port);`
- Example: `anyhow::bail!("failed to connect to server");`

This rule is enforced in `.cursorrules`.

## Key Security Concepts

### Attestation Flow

1. **Quote Generation**: Applications request TDX quotes via `getQuote()` with reportData (up to 64 bytes)
2. **Quote Verification**: `dstack-verifier` validates quotes using `dcap-qvl`, verifies OS image hash, and replays RTMRs from event logs
3. **RTMR Replay**: Compute Runtime Measurement Register values by applying SHA384 hashing to event log entries

### Key Management

- **Deterministic Keys**: `getKey(path, purpose)` derives secp256k1 keys using HKDF, with signature chains proving TEE origin
- **TLS Keys**: `getTlsKey()` generates fresh X.509 certificates with optional RA-TLS support
- **Environment Encryption**: Client-side encryption using X25519 ECDH + AES-256-GCM, decrypted only in TEE

### Smart Contract Integration

- **DstackKms**: Main KMS contract managing OS image whitelist and app registration
- **DstackApp**: Per-app authorization contract controlling device IDs and compose hash whitelist
- Deployed on Ethereum-compatible networks (Phala Network)

## Development Workflow

### Local Development Setup

1. Build meta-dstack artifacts (see README.md section "Build and Run")
2. Download or build guest OS image
3. Run components in separate terminals:
   - KMS: `./dstack-kms -c kms.toml`
   - Gateway: `sudo ./dstack-gateway -c gateway.toml`
   - VMM: `./dstack-vmm -c vmm.toml`

### Deploying Apps

- Via Web UI: `http://localhost:9080` (or configured port)
- Via CLI: `./vmm-cli.py` (see `docs/vmm-cli-user-guide.md`)
- Requires:
  1. On-chain app registration (`npx hardhat kms:create-app`)
  2. Adding compose hash to whitelist (`npx hardhat app:add-hash`)
  3. Deploying via VMM with App ID

### Accessing Deployed Apps

Ingress mapping pattern: `<id>[-[<port>][s|g]].<base_domain>`
- Default: TLS termination to TCP
- `s` suffix: TLS passthrough
- `g` suffix: HTTP/2 with TLS termination (gRPC)

## Important Files

- `Cargo.toml`: Workspace configuration with all Rust crates
- `vmm.toml`: VMM configuration (CID pool, port mapping, KMS/gateway URLs)
- `kms.toml`: KMS configuration (contract addresses, RPC endpoints)
- `gateway.toml`: Gateway configuration (domain, certificates, WireGuard)
- `docker-compose.yaml`: App deployment format (normalized to `.app-compose.json`)

## Common Tasks

### Adding a New Rust Crate

1. Create crate directory and `Cargo.toml`
2. Add to workspace members in root `Cargo.toml`
3. Add workspace dependency if it will be used by other crates

### Modifying RPC APIs

RPC definitions use `prpc` framework with Protocol Buffers:
- Define `.proto` files in `*/rpc/proto/`
- Use `prpc-build` in `build.rs` to generate Rust code
- Implement service traits in main crate

### Working with TDX Quotes

- Low-level bindings: `tdx-attest-sys/` (FFI to libtdx-attest)
- High-level API: `tdx-attest/`
- Verification: `verifier/` using `dcap-qvl`
- Event log parsing: `cc-eventlog/`

## Documentation

- Main README: `README.md`
- Deployment guide: `docs/deployment.md`
- VMM CLI guide: `docs/vmm-cli-user-guide.md`
- Security guide: `docs/security-guide/security-guide.md`
- Design decisions: `docs/design-and-hardening-decisions.md`

When need more detailed info, try to use deepwiki mcp.

## Agent Resources

The `.agent/` directory contains AI assistant resources:
- `WRITING_GUIDE.md` — Documentation and README writing guidelines (messaging, style, audiences)
- `GPU_TEE_DEPLOYMENT.md` — GPU deployment to Phala Cloud (instance types, docker-compose config, debugging)
