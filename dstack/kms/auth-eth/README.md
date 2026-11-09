# dstack KMS Auth-ETH

A Foundry-based smart contract project for dstack's Key Management System (KMS) authentication on Ethereum.

This directory holds the contracts, their tests and the deployment and management
scripts. The KMS reads these contracts through the
[`auth-eth-bun`](../auth-eth-bun/) webhook server, which serves the `/bootAuth/*`,
`/authorizeKms` and `/authorizeApp` endpoints.

## Overview

This project contains upgradeable smart contracts for:
- **DstackKms**: Key Management System contract with app registration and validation
- **DstackApp**: Application-specific authentication contract with device and compose hash management

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) - For smart contract development and testing
- Node.js/npm - Only for `@openzeppelin/upgrades-core`, which the upgrade-safety tests call through `--ffi`

## Upgrade order

Upgrade the `DstackKms` contract before deploying the new auth backend or KMS.
An empty root epoch registry is supported on the upgraded contract; there is no
fallback for legacy contracts. Old KMS instances that omit the root epoch can
receive app authorization only while no epoch is registered or epoch 0 is current,
subject to the existing authorization policy.

## Setup

```bash
# Fetch the Foundry dependencies (git submodules under lib/)
git submodule update --init --recursive lib/forge-std \
  lib/openzeppelin-contracts-upgradeable lib/openzeppelin-foundry-upgrades

# Install the OpenZeppelin upgrade-safety validator used by `forge test --ffi`
npm install --no-save --package-lock=false @openzeppelin/upgrades-core@^1.37.0

# Build the contracts
forge build
```

## Testing

```bash
# Run `forge clean` first: stale build-info files make the upgrade validator
# report the same contract twice.
forge clean
forge test --ffi
```

## Local chain

To try the contracts together with the webhook server, deploy them to a local
Anvil node and point [`auth-eth-bun`](../auth-eth-bun/) at the proxy:

```bash
# Terminal 1: local node
anvil

# Terminal 2: deploy with Anvil's first prefunded account; the output prints
# "DstackKms proxy deployed to: 0x..."
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  forge script script/Deploy.s.sol:DeployScript --broadcast --rpc-url http://127.0.0.1:8545

# Terminal 3: webhook server. Anvil finalizes 64 blocks behind its head, so read
# at the latest block.
cd ../auth-eth-bun
bun install
ETH_RPC_URL=http://127.0.0.1:8545 ETH_BLOCK_TAG=latest KMS_CONTRACT_ADDR=0x... PORT=8000 \
  bun index.ts
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
halmos --contract DstackAppEpochSymbolicTest
halmos --contract DstackKmsSymbolicTest
halmos --contract DstackKmsEpochSymbolicTest
```

Forge 1.8 enables `dynamic_test_linking` by default, which compiles `new` in
tests to `vm.deployCode`, a cheat code Halmos 0.3.3 does not support. Disable
it for Halmos runs with `FOUNDRY_DYNAMIC_TEST_LINKING=false`.

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


### Epoch-scoped material approvals

Material approvals use exact root/app epoch rows; neither older nor newer rows
are implicitly authorized. Existing add/remove methods change every root row from
the current epoch through the latest registered one, and the current and next
app rows. The `*AtEpoch` methods and optional
`ROOT_EPOCH` / `APP_EPOCH` variables on single-material management scripts select
an explicit row. Original bool mappings and events remain epoch-zero views after
upgrading; epoch-specific getters/events describe the new rows. KMS keyring
handover separately checks its highest exported root epoch, which authorizes the
whole keyring. See [epoch-scoped allowlists](../../../docs/app-key-epochs.md#epoch-scoped-allowlists)
for migration, upgrade order and compatibility.
