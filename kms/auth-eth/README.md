# dstack KMS Auth-ETH

A Foundry-based smart contract project for dstack's Key Management System (KMS) authentication on Ethereum.

## Overview

This project contains upgradeable smart contracts for:
- **DstackKms**: Key Management System contract with app registration and validation
- **DstackApp**: Application-specific authentication contract with device and compose hash management

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) - For smart contract development and testing
- Node.js - For the bootAuth server and TypeScript development

## Setup

1. Install dependencies:
```bash
# Install Foundry dependencies
forge install

# Install Node.js dependencies for server
npm install
```

2. Build contracts and server:
```bash
# Build smart contracts
forge build

# Build TypeScript server
npm run build
```

## Testing

### Smart contract tests (Foundry)
```bash
forge test --ffi
```

### BootAuth server tests (Jest)
```bash
npm test
```

### Local integration testing
```bash
# Quick test workflow — spins up Anvil, deploys, runs Jest + Foundry against the live chain
npm run test:all

# Step-by-step workflow
npm run test:setup        # Start Anvil and deploy contracts
npm run test:run          # Run tests against deployed contracts
npm run test:cleanup      # Stop all test processes
```

## Contract Management

Use Foundry scripts for all contract operations instead of Cast commands:

### Deployment
```bash
# Deploy both contracts
forge script script/Deploy.s.sol:DeployScript --broadcast --rpc-url http://localhost:8545

# Deploy to other networks
forge script script/Deploy.s.sol:DeployScript --broadcast --rpc-url <RPC_URL> --private-key <PRIVATE_KEY>
```

### Management Operations
```bash
# Add KMS aggregated MR
KMS_CONTRACT_ADDR=0x... MR_AGGREGATED=0x1234... \
forge script script/Manage.s.sol:AddKmsAggregatedMr --broadcast --rpc-url $RPC_URL

# Deploy new app via factory
KMS_CONTRACT_ADDR=0x... APP_OWNER=0x... \
forge script script/Manage.s.sol:DeployApp --broadcast --rpc-url $RPC_URL
```

### Query Operations
```bash
# Get KMS settings
KMS_CONTRACT_ADDR=0x... \
forge script script/Query.s.sol:GetKmsSettings --rpc-url $RPC_URL

# Check if device is allowed
APP_CONTRACT_ADDR=0x... DEVICE_ID=0x1234... \
forge script script/Query.s.sol:CheckAppDevice --rpc-url $RPC_URL
```

### Safe Upgrades
```bash
# Upgrade KMS to V2
KMS_CONTRACT_ADDR=0x... \
forge script script/Upgrade.s.sol:UpgradeKmsToV2 --broadcast --rpc-url $RPC_URL --ffi
```

See `script/README.md` for complete documentation of all available scripts.

## BootAuth Server

The project includes a Fastify-based HTTP server for TEE boot validation:

### Endpoints
- **`GET /`** - Health check and contract information
- **`POST /bootAuth/app`** - Validate application boot information
- **`POST /bootAuth/kms`** - Validate KMS boot information

### Configuration
Set these environment variables:
- **`ETH_RPC_URL`** - Ethereum RPC endpoint (default: `http://localhost:8545`)
- **`KMS_CONTRACT_ADDR`** - Deployed DstackKms contract address
- **`PORT`** - Server port (default: `8000`)
- **`HOST`** - Server host (default: `127.0.0.1`)

### Running the Server
```bash
# Development mode
npm run dev

# Production mode
npm run build && npm start

# Test the server
npm test
```

## Static Analysis & Symbolic Verification (local only)

We run [Slither](https://github.com/crytic/slither) and
[Halmos](https://github.com/a16z/halmos) locally during development. They
are intentionally not part of CI — symbolic proofs are slow, sensitive to
solver versions, and most valuable as an interactive design check rather
than a gate.

```bash
pipx install slither-analyzer halmos
slither .
halmos --contract DstackAppSymbolicTest
halmos --contract DstackKmsSymbolicTest
```

Configuration lives in `slither.config.json` and `foundry.toml`.
See `docs/formal-verification.md` for the verification roadmap, what each
symbolic property proves, and the deeper-verification plan for a future
audit-firm engagement.

## Additional Commands

```bash
# Format code
forge fmt

# Gas snapshots
forge snapshot

# Start local node
anvil
```

Documentation: https://book.getfoundry.sh/
