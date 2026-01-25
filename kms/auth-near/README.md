# dstack auth-near

A NEAR Protocol backend for dstack KMS webhook authorization. Validates boot requests against NEAR smart contracts.

## Overview

This module provides on-chain governance authentication for dstack KMS using NEAR Protocol smart contracts. It's similar to `auth-eth` but uses NEAR's contract system instead of Ethereum.

## Features

- **NEAR Contract Integration**: Calls `is_kms_allowed()` and `is_app_allowed()` view methods on NEAR contracts
- **Multi-Contract Support**: Validates both KMS and App contracts
- **Account ID Handling**: Converts hex addresses to NEAR AccountId format
- **Compatible API**: Same HTTP endpoints as `auth-eth` for seamless integration

## Prerequisites

- Bun runtime (or Node.js with appropriate setup)
- NEAR RPC endpoint access
- Deployed NEAR KMS contract
- Deployed NEAR App contracts (for app validation)

## Installation

```bash
bun install
```

## Configuration

Set the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `NEAR_RPC_URL` | NEAR RPC endpoint | `https://free.rpc.fastnear.com` |
| `NEAR_NETWORK_ID` | NEAR network ID (`mainnet`, `testnet`, `betanet`) | `mainnet` |
| `KMS_CONTRACT_ID` | NEAR account ID of the KMS contract | (required) |
| `PORT` | Server port | `3000` |

## Usage

### Start the server

```bash
bun run start
```

Or in development mode with auto-reload:

```bash
bun run dev
```

### Endpoints

#### GET /

Health check and info endpoint. Returns contract information.

**Response:**
```json
{
  "status": "ok",
  "kmsContractAddr": "kms.dstack.near",
  "gatewayAppId": "gateway.dstack.near",
  "chainId": "mainnet",
  "appAuthImplementation": "",
  "appImplementation": ""
}
```

#### POST /bootAuth/app

App boot authorization.

**Request:** JSON body matching `BootInfo` schema:
```json
{
  "mrAggregated": "hex_string",
  "osImageHash": "hex_string",
  "appId": "hex_string",
  "composeHash": "hex_string",
  "instanceId": "hex_string",
  "deviceId": "hex_string",
  "tcbStatus": "UpToDate",
  "advisoryIds": [],
  "mrSystem": "hex_string"
}
```

**Response:**
```json
{
  "isAllowed": true,
  "reason": "",
  "gatewayAppId": "gateway.dstack.near"
}
```

#### POST /bootAuth/kms

KMS boot authorization.

**Request:** Same as `/bootAuth/app`

**Response:** Same as `/bootAuth/app`

## Integration with dstack-kms

Configure KMS to use webhook auth pointing to this server:

```toml
[core.auth_api]
type = "webhook"

[core.auth_api.webhook]
url = "http://auth-near:3000"
```

Or use the new NEAR-specific config:

```toml
[core.auth_api]
type = "near"

[core.auth_api.near]
rpc_url = "https://free.rpc.fastnear.com"
network_id = "mainnet"
contract_id = "kms.dstack.near"
```

## Differences from auth-eth

| Aspect | auth-eth | auth-near |
|--------|----------|-----------|
| Blockchain | Ethereum/Base | NEAR Protocol |
| SDK | viem | near-api-js |
| Address Format | 20-byte hex (0x...) | AccountId (string) |
| Contract Calls | `readContract()` | `viewFunction()` |
| Network Config | Chain ID (number) | Network ID (string) |

## CLI Commands

The `auth-near` package includes CLI commands for deploying app contracts and managing compose hashes, similar to Hardhat tasks in `auth-eth`.

### Environment Variables

For CLI commands, you need to set:

| Variable | Description | Required |
|----------|-------------|----------|
| `NEAR_ACCOUNT_ID` | NEAR account ID for signing transactions | Yes |
| `NEAR_PRIVATE_KEY` | NEAR account private key (ed25519:...) | Yes |
| `KMS_CONTRACT_ID` | NEAR account ID of the KMS contract | Yes (for deploy) |
| `NEAR_NETWORK_ID` | Network ID (`testnet`, `mainnet`) | No (default: `testnet`) |
| `NEAR_RPC_URL` | NEAR RPC endpoint | No (auto-detected) |

### Deploy App Contract

Deploy a new app contract via the KMS contract's `register_app` function:

```bash
bun run app:deploy <app_id> <owner_id> [options]
```

**Example:**
```bash
export NEAR_ACCOUNT_ID=owner.testnet
export NEAR_PRIVATE_KEY=ed25519:...
export KMS_CONTRACT_ID=kms.testnet
export NEAR_NETWORK_ID=testnet

bun run app:deploy myapp owner.testnet \
  --allow-any-device \
  --compose-hash 0x1234...
```

**Options:**
- `--disable-upgrades` - Disable contract upgrades
- `--allow-any-device` - Allow any device to boot this app
- `--device-id <id>` - Initial device ID to allow
- `--compose-hash <hash>` - Initial compose hash to allow (hex string)
- `--deposit <near>` - Deposit amount in NEAR (default: 30 NEAR)

**Note:** The app contract will be deployed as a subaccount: `{app_id}.{kms_contract_id}`

### Add Compose Hash

Add a compose hash to an existing app contract:

```bash
bun run app:add-hash <app_account_id> <compose_hash>
```

**Example:**
```bash
export NEAR_ACCOUNT_ID=owner.testnet
export NEAR_PRIVATE_KEY=ed25519:...

bun run app:add-hash myapp.kms.testnet 0xabcd1234...
```

**Note:** The `app_account_id` should be the full account ID (e.g., `myapp.kms.testnet`), not just the app ID.

### Remove Compose Hash

Remove a compose hash from an app contract:

```bash
bun run app:remove-hash <app_account_id> <compose_hash>
```

**Example:**
```bash
bun run app:remove-hash myapp.kms.testnet 0xabcd1234...
```

### Add OS Image Hash

Add an OS image hash to the KMS contract's allowed list:

```bash
bun cli.ts add-os-image <os_image_hash>
```

**Example:**
```bash
export NEAR_ACCOUNT_ID=owner.testnet
export NEAR_PRIVATE_KEY=ed25519:...
export KMS_CONTRACT_ID=kms.testnet

bun cli.ts add-os-image 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

**Note:** The hash can be provided with or without the `0x` prefix. The CLI will automatically strip it if present.

### Remove OS Image Hash

Remove an OS image hash from the KMS contract:

```bash
bun cli.ts remove-os-image <os_image_hash>
```

**Example:**
```bash
bun cli.ts remove-os-image 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

### Add KMS Device ID

Add a device ID to the KMS contract's allowed device list:

```bash
bun cli.ts add-device <device_id>
```

**Example:**
```bash
export NEAR_ACCOUNT_ID=owner.testnet
export NEAR_PRIVATE_KEY=ed25519:...
export KMS_CONTRACT_ID=kms.testnet

bun cli.ts add-device 0xdevice1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

**Note:** Device IDs are typically hex strings. The `0x` prefix is optional.

### Remove KMS Device ID

Remove a device ID from the KMS contract:

```bash
bun cli.ts remove-device <device_id>
```

**Example:**
```bash
bun cli.ts remove-device 0xdevice1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

### Add KMS Aggregated MR

Add an aggregated MR (measurement) to the KMS contract's allowed list:

```bash
bun cli.ts add-mr <mr_aggregated>
```

**Example:**
```bash
export NEAR_ACCOUNT_ID=owner.testnet
export NEAR_PRIVATE_KEY=ed25519:...
export KMS_CONTRACT_ID=kms.testnet

bun cli.ts add-mr 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

**Note:** Aggregated MRs are hex strings representing TEE measurements. The `0x` prefix is optional.

### Remove KMS Aggregated MR

Remove an aggregated MR from the KMS contract:

```bash
bun cli.ts remove-mr <mr_aggregated>
```

**Example:**
```bash
bun cli.ts remove-mr 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

### Direct CLI Usage

You can also use the CLI directly with all available commands:

```bash
# App management
bun cli.ts deploy <app_id> <owner_id> [options]
bun cli.ts add-hash <app_account_id> <compose_hash>
bun cli.ts remove-hash <app_account_id> <compose_hash>

# KMS configuration
bun cli.ts add-os-image <os_image_hash>
bun cli.ts remove-os-image <os_image_hash>
bun cli.ts add-device <device_id>
bun cli.ts remove-device <device_id>
bun cli.ts add-mr <mr_aggregated>
bun cli.ts remove-mr <mr_aggregated>
```

**Note:** All KMS configuration commands require the `KMS_CONTRACT_ID` environment variable to be set.

## Development

### Running Tests

```bash
bun run test
```

### Linting

```bash
bun run lint
```

## See Also

- [auth-eth](../auth-eth/) - Ethereum-based auth server
- [auth-simple](../auth-simple/) - Config-based auth server
- [auth-mock](../auth-mock/) - Development/testing auth server (always allows)


