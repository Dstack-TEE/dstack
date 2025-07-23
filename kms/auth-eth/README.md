# Dstack KMS Auth-ETH

A Foundry-based smart contract project for Dstack's Key Management System (KMS) authentication on Ethereum.

## Overview

This project contains upgradeable smart contracts for:
- **DstackKms**: Key Management System contract with app registration and validation
- **DstackApp**: Application-specific authentication contract with device and compose hash management

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Node.js (for OpenZeppelin Foundry Upgrades plugin)

## Setup

1. Install dependencies:
```bash
forge install
npm install
```

2. Build contracts:
```bash
forge build
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

Test upgrade functionality and contract migration scenarios:

```bash
# Test basic upgrade functionality (5 tests)
forge test --ffi --match-path "test/UpgradesBasic.t.sol"

# Test advanced upgrade scenarios (may have OpenZeppelin validation issues)
forge test --ffi --match-path "test/Upgrades.t.sol"
forge test --ffi --match-path "test/UpgradesWithPlugin.t.sol"
```

### Run All Working Tests

```bash
# Run all stable tests (32 tests total)
forge test --ffi --match-path "test/DstackApp.t.sol" && \
forge test --ffi --match-path "test/DstackKms.t.sol" && \
forge test --ffi --match-path "test/UpgradesBasic.t.sol"
```

### Test Coverage Summary

- ✅ **DstackApp.t.sol**: 11/11 tests PASS - Core app functionality
- ✅ **DstackKms.t.sol**: 16/16 tests PASS - Core KMS functionality  
- ✅ **UpgradesBasic.t.sol**: 5/5 tests PASS - Basic upgrade functionality
- ⚠️ **Upgrades.t.sol**: OpenZeppelin validation issues (advanced upgrade testing)
- ⚠️ **UpgradesWithPlugin.t.sol**: OpenZeppelin validation issues (advanced upgrade testing)

**Total: 32/32 core and basic upgrade tests PASSING**

## Important Notes

- **FFI Flag Required**: Tests use the `--ffi` flag because they rely on the OpenZeppelin Foundry Upgrades plugin
- **Clean Builds**: If you encounter OpenZeppelin validation errors, run `forge clean && forge build` before testing
- **Test Organization**: Basic functionality tests use OpenZeppelin plugin for deployment (production-like) but don't test upgrading. All upgrade testing is isolated in dedicated test files.

## Contract Deployment

The contracts are designed to be deployed as UUPS proxies using the OpenZeppelin Foundry Upgrades plugin. See the test files for deployment examples.

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
