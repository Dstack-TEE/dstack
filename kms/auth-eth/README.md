# Dstack KMS Auth-ETH

A Foundry-based smart contract project for Dstack's Key Management System (KMS) authentication on Ethereum.

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

The project uses Foundry for testing with proper separation between core functionality and upgrade testing.

### Core Functionality Tests

Test the basic features of the contracts without upgrade-related functionality:

```bash
# Test DstackApp core functionality (11 tests)
forge test --ffi --match-path "test/DstackApp.t.sol"

# Test DstackKms core functionality (16 tests)  
forge test --ffi --match-path "test/DstackKms.t.sol"

# Run both core functionality test suites
forge test --ffi --match-path "test/DstackApp.t.sol" && forge test --ffi --match-path "test/DstackKms.t.sol"
```

### Upgrade Tests

Test upgrade functionality and contract migration scenarios using OpenZeppelin Foundry Upgrades plugin:

```bash
# Test comprehensive upgrade scenarios with plugin
forge test --ffi --match-path "test/UpgradesWithPlugin.t.sol"
```

### Run All Tests

```bash
# Run all tests (36 tests total)
forge test --ffi

# Or run specific test suites
forge test --ffi --match-path "test/DstackApp.t.sol" && \
forge test --ffi --match-path "test/DstackKms.t.sol" && \
forge test --ffi --match-path "test/UpgradesWithPlugin.t.sol"
```

### Local Integration Testing

The project includes automated scripts for testing against a local Anvil blockchain:

```bash
# Quick test workflow
npm run test:all          # Sets up chain, deploys contracts, runs all tests
npm run test:all:foundry  # Also includes Foundry tests

# Step-by-step workflow
npm run test:setup        # Start Anvil and deploy contracts
npm run test:run          # Run tests against deployed contracts
npm run test:cleanup      # Stop all test processes

# Available NPM scripts for testing
npm test                  # Run Jest unit tests
npm run test:foundry      # Run Foundry tests with FFI
```

### Test Coverage Summary

- ✅ **DstackApp.t.sol**: 11/11 tests PASS - Core app functionality
- ✅ **DstackKms.t.sol**: 16/16 tests PASS - Core KMS functionality  
- ✅ **UpgradesWithPlugin.t.sol**: 9/9 tests PASS - Comprehensive upgrade scenarios

**Total: 36/36 tests PASSING (100% success rate)**

## Important Notes

- **FFI Flag Required**: Tests use the `--ffi` flag because they rely on the OpenZeppelin Foundry Upgrades plugin
- **Clean Builds**: If you encounter OpenZeppelin validation errors, run `forge clean && forge build` before testing
- **Test Organization**: Basic functionality tests use OpenZeppelin plugin for deployment (production-like) but don't test upgrading. All upgrade testing is isolated in dedicated test files.

## Contract Deployment

The contracts are designed to be deployed as UUPS proxies. The project includes deployment scripts:

```bash
# Deploy to local Anvil
forge script script/Deploy.s.sol:DeployScript --broadcast --rpc-url http://localhost:8545

# Deploy to other networks
forge script script/Deploy.s.sol:DeployScript --broadcast --rpc-url <RPC_URL> --private-key <PRIVATE_KEY>
```

Available deployment scripts:
- `DeployScript` - Deploys both DstackKms and DstackApp
- `DeployKmsOnly` - Deploys only DstackKms (requires APP_IMPLEMENTATION env var)
- `DeployAppOnly` - Deploys only DstackApp implementation

## BootAuth Server

The project includes a Fastify-based HTTP server that provides TEE boot validation services:

### Server Endpoints:
- **`GET /`** - Health check and contract information
- **`POST /bootAuth/app`** - Validate application boot information
- **`POST /bootAuth/kms`** - Validate KMS boot information

### Configuration:
Set these environment variables:
- **`ETH_RPC_URL`** - Ethereum RPC endpoint (default: `http://localhost:8545`)
- **`KMS_CONTRACT_ADDR`** - Deployed DstackKms contract address
- **`PORT`** - Server port (default: `8000`)
- **`HOST`** - Server host (default: `127.0.0.1`)

### Running the Server:
```bash
# Development mode
npm run dev

# Production mode
npm run build && npm start

# Test the server
npm test
```

## Migration Status

This project has been successfully migrated from Hardhat to Foundry while maintaining:
- Complete test coverage of core functionality
- Proper separation between basic functionality and upgrade testing  
- Production-like deployment patterns using OpenZeppelin upgrades
- All essential contract features and security properties

---

## Foundry Reference

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:
- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

### Additional Foundry Commands

```bash
# Format code
forge fmt

# Gas snapshots
forge snapshot

# Start local node
anvil

# Deploy contracts
forge script script/Deploy.s.sol --rpc-url <your_rpc_url> --private-key <your_private_key>

# Help
forge --help
anvil --help
cast --help
```

Documentation: https://book.getfoundry.sh/
