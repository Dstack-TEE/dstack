# On-Chain Governance

This guide covers setting up on-chain governance for dstack using smart contracts on Ethereum or NEAR Protocol.

## Overview

On-chain governance adds:
- **Smart contract-based authorization**: App registration and whitelisting managed by smart contracts
- **Decentralized trust**: No single operator controls keys
- **Transparent policies**: Anyone can verify authorization rules on-chain

dstack supports two blockchain platforms for on-chain governance:
- **Ethereum**: Using Solidity smart contracts (see [Ethereum Auth](#ethereum-auth) section)
- **NEAR Protocol**: Using Rust smart contracts (see [NEAR Auth](#near-auth) section)

## Prerequisites

- Production dstack deployment with KMS and Gateway as CVMs (see [Deployment Guide](./deployment.md))

**For Ethereum:**
- Ethereum wallet with funds on Sepolia testnet (or your target network)
- Node.js and npm installed
- Alchemy API key (for Sepolia) - get one at https://www.alchemy.com/

**For NEAR:**
- NEAR account with funds on testnet or mainnet
- Bun runtime (or Node.js) installed
- NEAR RPC endpoint access (default: `https://free.rpc.fastnear.com`)

## Ethereum Auth

### Deploy DstackKms Contract

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

### Configure KMS for On-Chain Auth

The KMS CVM includes an auth-api service that connects to your DstackKms contract. Configure it via environment variables in the KMS CVM:

```bash
KMS_CONTRACT_ADDR=<your-dstack-kms-contract-address>
ETH_RPC_URL=<ethereum-rpc-endpoint>
```

Note: The auth-api uses `KMS_CONTRACT_ADDR`, while Hardhat tasks use `KMS_CONTRACT_ADDRESS`.

The auth-api validates boot requests against the smart contract. See [Deployment Guide](./deployment.md#2-deploy-kms-as-cvm) for complete setup instructions.

### Whitelist OS Image

```bash
npx hardhat kms:add-image --network sepolia 0x<os-image-hash>
```

Output: `Image added successfully`

The `os_image_hash` is in the `digest.txt` file from the guest OS image build (see [Building Guest Images](./deployment.md#building-guest-images)).

### Register Gateway App

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

### Register Apps On-Chain

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

### Ethereum Smart Contract Reference

#### DstackKms (Main Contract)

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

#### DstackApp (Per-App Contract)

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

#### AppBootInfo Structure

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

## NEAR Auth

### Deploy NEAR KMS Contract

The NEAR KMS contract must be deployed to a NEAR account. You can deploy it using NEAR CLI or the deployment scripts in the `near-kms` repository.

**Prerequisites:**
- NEAR account with sufficient balance (for contract deployment and storage)
- NEAR CLI installed and configured
- MPC contract ID (for key derivation)

**Deploy the contract:**

```bash
cd near-kms/contracts/kms
near deploy --wasmFile res/near_dstack_kms.wasm \
  --accountId <your-kms-account-id> \
  --initFunction new \
  --initArgs '{"owner_id": "<owner-account-id>", "mpc_contract_id": "<mpc-contract-id>", "mpc_domain_id": 2}'
```

Note the KMS contract account ID (e.g., `kms.dstack.testnet`).

Set environment variables for subsequent commands:

```bash
export KMS_CONTRACT_ID="<kms-contract-account-id>"
export NEAR_ACCOUNT_ID="<your-near-account-id>"
export NEAR_PRIVATE_KEY="ed25519:<your-private-key>"
export NEAR_NETWORK_ID="testnet"  # or "mainnet"
export NEAR_RPC_URL="https://free.rpc.fastnear.com"  # optional, auto-detected if not set
```

### Configure KMS for NEAR Auth

The KMS CVM can be configured to use NEAR contracts in two ways:

**Option 1: Direct NEAR integration (recommended)**

Configure via TOML config file:

```toml
[core.auth_api]
type = "near"

[core.auth_api.near]
url = "http://auth-near:3000"  # Optional: auth-near webhook service URL
rpc_url = "https://free.rpc.fastnear.com"
network_id = "testnet"
contract_id = "<kms-contract-account-id>"
mpc_contract_id = "<mpc-contract-id>"  # Optional: for MPC key derivation
mpc_domain_id = 2  # Optional: default is 2
```

**Option 2: Via webhook service**

Deploy the `auth-near` webhook service and configure KMS to use it:

```toml
[core.auth_api]
type = "webhook"

[core.auth_api.webhook]
url = "http://auth-near:3000"
```

The `auth-near` service validates boot requests against NEAR smart contracts. See [auth-near README](../kms/auth-near/README.md) for complete setup instructions.

### Whitelist OS Image

Add an OS image hash to the KMS contract's allowed list:

```bash
cd dstack/kms/auth-near
bun install
bun cli.ts add-os-image 0x<os-image-hash>
```

Output: `✅ OS image hash added successfully`

The `os_image_hash` is in the `digest.txt` file from the guest OS image build (see [Building Guest Images](./deployment.md#building-guest-images)).

**Remove an OS image:**

```bash
bun cli.ts remove-os-image 0x<os-image-hash>
```

### Register Gateway App

Deploy and register a gateway app contract:

```bash
bun cli.ts deploy <app-id> <owner-id> \
  --allow-any-device \
  --compose-hash 0x<compose-hash> \
  --deposit 30
```

Sample output:

```
✅ App contract deployed successfully!
   App Account: <app-id>.<kms-contract-id>
   Transaction: <transaction-hash>
```

Note the App Account ID (e.g., `gateway.kms.dstack.testnet`).

Set it as the gateway app:

```bash
near call <kms-contract-id> set_gateway_app_id \
  '{"app_id": "<app-account-id>"}' \
  --accountId <your-account-id> \
  --deposit 1
```

Output: `Gateway App ID set successfully`

**Add compose hash to gateway:**

```bash
bun cli.ts add-hash <app-account-id> 0x<compose-hash>
```

### Register Apps On-Chain

For each app you want to deploy:

#### Create App

Deploy and register an app contract:

```bash
bun cli.ts deploy <app-id> <owner-id> \
  --allow-any-device \
  --compose-hash 0x<compose-hash> \
  --deposit 30
```

Note the App Account ID from the output (format: `<app-id>.<kms-contract-id>`).

#### Add Compose Hash

Compute your app's compose hash:

```bash
sha256sum /path/to/your-app-compose.json | awk '{print "0x"$1}'
```

Then add it:

```bash
bun cli.ts add-hash <app-account-id> 0x<compose-hash>
```

#### Add Device ID (Optional)

If not using `--allow-any-device`, add specific device IDs:

```bash
near call <app-account-id> add_device \
  '{"device_id": "0x<device-id>"}' \
  --accountId <your-account-id> \
  --deposit 1
```

#### Deploy via VMM

Use the App Account ID when deploying through the VMM dashboard or [VMM CLI](./vmm-cli-user-guide.md).

### NEAR Smart Contract Reference

#### KMS Contract (Main Contract)

The central governance contract that manages OS image whitelisting, app registration, and KMS authorization.

| Function | Description |
|----------|-------------|
| `new(owner_id, mpc_contract_id, mpc_domain_id)` | Initialize the KMS contract |
| `add_os_image_hash(os_image_hash)` | Whitelist an OS image hash |
| `remove_os_image_hash(os_image_hash)` | Remove an OS image from whitelist |
| `add_kms_aggregated_mr(mr_aggregated)` | Whitelist an aggregated MR for KMS |
| `remove_kms_aggregated_mr(mr_aggregated)` | Remove an aggregated MR from whitelist |
| `add_kms_device(device_id)` | Whitelist a device ID for KMS |
| `remove_kms_device(device_id)` | Remove a device ID from whitelist |
| `add_kms_compose_hash(compose_hash)` | Whitelist a compose hash for KMS |
| `remove_kms_compose_hash(compose_hash)` | Remove a compose hash from whitelist |
| `set_gateway_app_id(app_id)` | Set the trusted Gateway app ID |
| `register_app(app_id, owner_id, ...)` | Deploy and register an app contract |
| `is_app_registered(app_id)` | Check if an app is registered |
| `is_kms_allowed(AppBootInfo)` | Check if KMS is allowed to boot |
| `request_kms_root_key(...)` | Request KMS root key from MPC network |

#### App Contract (Per-App Contract)

Each app has its own contract controlling which compose hashes and devices are allowed.

| Function | Description |
|----------|-------------|
| `new(owner_id, kms_contract_id, ...)` | Initialize the app contract |
| `add_compose_hash(compose_hash)` | Whitelist a compose hash |
| `remove_compose_hash(compose_hash)` | Remove a compose hash from whitelist |
| `add_device(device_id)` | Whitelist a device ID |
| `remove_device(device_id)` | Remove a device from whitelist |
| `set_allow_any_device(allow)` | Allow any device to run this app |
| `is_app_allowed(AppBootInfo)` | Check if app can boot with given config |
| `disable_upgrades()` | Permanently disable contract upgrades |

#### AppBootInfo Structure

Both `is_app_allowed` and `is_kms_allowed` take an `AppBootInfo` struct:

```rust
pub struct AppBootInfo {
    pub app_id: AccountId,        // Unique app identifier (account ID)
    pub compose_hash: String,     // Hash of docker-compose configuration
    pub instance_id: AccountId,    // Unique instance identifier
    pub device_id: String,         // Hardware device identifier
    pub mr_aggregated: String,     // Aggregated measurement register
    pub mr_system: String,         // System measurement register
    pub os_image_hash: String,     // OS image hash
    pub tcb_status: String,        // TCB status (e.g., "UpToDate")
    pub advisory_ids: Vec<String>, // Security advisory IDs
}
```

Source: [`near-kms/contracts/kms/`](../../near-kms/contracts/kms/)

### NEAR CLI Commands Reference

The `auth-near` package provides CLI commands for managing NEAR contracts:

**App Management:**
```bash
# Deploy app contract
bun cli.ts deploy <app-id> <owner-id> [options]

# Add compose hash
bun cli.ts add-hash <app-account-id> <compose-hash>

# Remove compose hash
bun cli.ts remove-hash <app-account-id> <compose-hash>
```

**KMS Configuration:**
```bash
# Add OS image hash
bun cli.ts add-os-image <os_image_hash>

# Remove OS image hash
bun cli.ts remove-os-image <os_image_hash>

# Add KMS device ID
bun cli.ts add-device <device_id>

# Remove KMS device ID
bun cli.ts remove-device <device_id>

# Add KMS aggregated MR
bun cli.ts add-mr <mr_aggregated>

# Remove KMS aggregated MR
bun cli.ts remove-mr <mr_aggregated>
```

See [auth-near README](../kms/auth-near/README.md) for detailed CLI documentation.

## See Also

- [Deployment Guide](./deployment.md) - Setting up dstack infrastructure
- [Security Best Practices](./security/security-best-practices.md)
