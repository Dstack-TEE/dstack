# On-Chain Governance

This guide covers setting up on-chain governance for dstack using smart contracts on Ethereum.

## Overview

On-chain governance adds:
- **Smart contract-based authorization**: App registration and whitelisting managed by smart contracts
- **Decentralized trust**: No single operator controls keys
- **Transparent policies**: Anyone can verify authorization rules on-chain

## Prerequisites

- Production dstack deployment with KMS and Gateway as CVMs (see [Deployment Guide](./deployment.md))
- Ethereum wallet with funds on Sepolia testnet (or your target network)
- Node.js and npm installed

## Deploy DstackKms Contract

```bash
cd dstack/kms/auth-eth
npm install
npx hardhat compile
PRIVATE_KEY=<your-key> npx hardhat kms:deploy --with-app-impl --network sepolia
```

Note the deployed contract address.

## Configure KMS for On-Chain Auth

Update KMS to use webhook auth mode pointing to your auth-api service.

> **TODO:** Document auth-api service deployment and KMS webhook configuration.

## Whitelist OS Image

```bash
cd dstack/kms/auth-eth
npm install
npx hardhat kms:add-image --network sepolia 0x<os-image-hash>
```

The `os_image_hash` is in the `digest.txt` file from the image build.

## Register Gateway App

```bash
npx hardhat kms:create-app --network sepolia --allow-any-device
```

Note the App ID from the output.

Set it as the gateway app:

```bash
npx hardhat kms:set-gateway --network sepolia <app-id>
```

Add the compose hash to the whitelist:

```bash
npx hardhat app:add-hash --network sepolia --app-id <app-id> <compose-hash>
```

## Register Apps On-Chain

For each app you want to deploy:

### Create App

```bash
npx hardhat kms:create-app --network sepolia --allow-any-device
```

### Add Compose Hash

```bash
npx hardhat app:add-hash --network sepolia --app-id <app-id> <compose-hash>
```

### Deploy via VMM

Use the App ID when deploying through the VMM dashboard or CLI.

## Smart Contract Reference

### DstackKms (Main Contract)

The central governance contract that manages OS image whitelisting, app registration, and KMS authorization.

| Function | Description |
|----------|-------------|
| `addOsImageHash(bytes32)` | Whitelist an OS image hash |
| `removeOsImageHash(bytes32)` | Remove an OS image from whitelist |
| `setGatewayAppId(string)` | Set the trusted Gateway app ID |
| `registerApp(address)` | Register an app contract |
| `deployAndRegisterApp(...)` | Deploy and register app in one transaction |
| `isAppAllowed(AppBootInfo)` | Check if an app is allowed to boot |
| `isKmsAllowed(AppBootInfo)` | Check if KMS is allowed to boot |

### DstackApp (Per-App Contract)

Each app has its own contract controlling which compose hashes and devices are allowed.

| Function | Description |
|----------|-------------|
| `addComposeHash(bytes32)` | Whitelist a compose hash |
| `removeComposeHash(bytes32)` | Remove a compose hash from whitelist |
| `addDevice(bytes32)` | Whitelist a device ID |
| `removeDevice(bytes32)` | Remove a device from whitelist |
| `setAllowAnyDevice(bool)` | Allow any device to run this app |
| `isAppAllowed(AppBootInfo)` | Check if app can boot with given config |
| `disableUpgrades()` | Permanently disable contract upgrades |

### AppBootInfo Structure

Both `isAppAllowed` and `isKmsAllowed` take an `AppBootInfo` struct:

```solidity
struct AppBootInfo {
    address appId;        // Unique app identifier (contract address)
    bytes32 composeHash;  // Hash of docker-compose configuration
    address instanceId;   // Unique instance identifier
    bytes32 deviceId;     // Hardware device identifier
    bytes32 mrAggregated; // Aggregated measurement register
    bytes32 mrSystem;     // System measurement register
    bytes32 osImageHash;  // OS image hash
    string tcbStatus;     // TCB status (e.g., "UpToDate")
    string[] advisoryIds; // Security advisory IDs
}
```

Source: [`kms/auth-eth/contracts/`](../kms/auth-eth/contracts/)

## See Also

- [Deployment Guide](./deployment.md) - Setting up dstack infrastructure
- [Security Guide](./security.md) - Security best practices
