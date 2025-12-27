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
- Alchemy API key (for Sepolia) - get one at https://www.alchemy.com/

## Deploy DstackKms Contract

```bash
cd dstack/kms/auth-eth
npm install
npx hardhat compile
PRIVATE_KEY=<your-key> ALCHEMY_API_KEY=<your-key> npx hardhat kms:deploy --with-app-impl --network sepolia
```

The command will prompt for confirmation. Sample output:

```
✅ DstackApp implementation deployed to: 0x5FbDB2315678afecb367f032d93F642f64180aa3
DstackKms Proxy deployed to: 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
Implementation deployed to: 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
```

Note the proxy address (e.g., `0x9fE4...`).

Set environment variables for subsequent commands:

```bash
export KMS_CONTRACT_ADDRESS="<DstackKms-proxy-address>"
export PRIVATE_KEY="<your-private-key>"
export ALCHEMY_API_KEY="<your-alchemy-key>"
```

## Configure KMS for On-Chain Auth

The KMS CVM includes an auth-api service that connects to your DstackKms contract. Configure it via environment variables in the KMS CVM:

```bash
KMS_CONTRACT_ADDR=<your-dstack-kms-contract-address>
ETH_RPC_URL=<ethereum-rpc-endpoint>
```

Note: The auth-api uses `KMS_CONTRACT_ADDR`, while Hardhat tasks use `KMS_CONTRACT_ADDRESS`.

The auth-api validates boot requests against the smart contract. See [Deployment Guide](./deployment.md#2-deploy-kms-as-cvm) for complete setup instructions.

## Whitelist OS Image

```bash
npx hardhat kms:add-image --network sepolia 0x<os-image-hash>
```

Output: `Image added successfully`

The `os_image_hash` is in the `digest.txt` file from the guest OS image build (see [Building Guest Images](./deployment.md#building-guest-images)).

## Register Gateway App

```bash
npx hardhat kms:create-app --network sepolia --allow-any-device
```

Sample output:

```
✅ App deployed and registered successfully!
Proxy Address (App Id): 0x75537828f2ce51be7289709686A69CbFDbB714F1
```

Note the App ID (Proxy Address) from the output.

Set it as the gateway app:

```bash
npx hardhat kms:set-gateway --network sepolia <app-id>
```

Output: `Gateway App ID set successfully`

Add the gateway's compose hash to the whitelist. To compute the compose hash:

```bash
sha256sum /path/to/gateway-compose.json | awk '{print "0x"$1}'
```

Then add it:

```bash
npx hardhat app:add-hash --network sepolia --app-id <app-id> <compose-hash>
```

Output: `Compose hash added successfully`

## Register Apps On-Chain

For each app you want to deploy:

### Create App

```bash
npx hardhat kms:create-app --network sepolia --allow-any-device
```

Note the App ID from the output.

### Add Compose Hash

Compute your app's compose hash:

```bash
sha256sum /path/to/your-app-compose.json | awk '{print "0x"$1}'
```

Then add it:

```bash
npx hardhat app:add-hash --network sepolia --app-id <app-id> <compose-hash>
```

### Deploy via VMM

Use the App ID when deploying through the VMM dashboard or [VMM CLI](./vmm-cli-user-guide.md).

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
