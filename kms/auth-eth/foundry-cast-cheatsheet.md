# Foundry Cast Cheatsheet

This document provides Foundry Cast equivalents for all Hardhat tasks defined in `hardhat.config.ts`. Replace the placeholder values and modify as needed.

## Setup Variables

```bash
# Contract addresses - set these to your deployed addresses
export KMS_CONTRACT_ADDRESS="0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"  # Your deployed KMS proxy
export APP_AUTH_ADDRESS="YOUR_APP_AUTH_ADDRESS"  # Specific DstackApp instance address
export PRIVATE_KEY="your_private_key_here"
export RPC_URL="http://kms2.phatfn.xyz:8545"  # or your network RPC URL
export DEPLOYER_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # Your deployer address

# Alternative: Create an alias for shorter commands
alias mycast="cast --private-key $PRIVATE_KEY --rpc-url $RPC_URL"
```

## Contract Deployment & Upgrade

### Initial Setup (One-time)

#### Option 1: Complete Setup (Recommended)

```bash
# Deploy DstackApp implementation and DstackKms with implementation set in one command
npx hardhat kms:deploy --with-app-impl --network test
# This automatically:
# 1. Deploys DstackApp implementation
# 2. Deploys DstackKms UUPS proxy with DstackApp implementation set during initialization
# 3. Ready for factory app deployments immediately!
```

#### Option 2: Step-by-step Setup

```bash
# 1. Deploy DstackApp implementation first (equivalent to app:deploy-impl)
npx hardhat app:deploy-impl --network test
# Note the implementation address: 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0

# 2. Deploy DstackKms UUPS proxy with DstackApp implementation set during initialization
npx hardhat kms:deploy --network test --app-implementation 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
```

#### Option 3: Legacy Setup (Manual)

```bash
# 1. Deploy DstackKms UUPS proxy without DstackApp implementation
npx hardhat kms:deploy --network test

# 2. Deploy DstackApp implementation separately
npx hardhat app:deploy-impl --network test

# 3. Set DstackApp implementation in KMS manually (equivalent to kms:set-app-implementation)
cast send $KMS_CONTRACT_ADDRESS "setAppImplementation(address)" \
  "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

### Proxy Verification (UUPS Specific)

```bash
# ✅ CORRECT: Check UUPS proxy implementation address via storage slot
cast storage $KMS_CONTRACT_ADDRESS 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC_URL
# Returns: 0x0000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa3

# ✅ CORRECT: Verify implementation supports UUPS (call on implementation address)
cast call 0x5FbDB2315678afecb367f032d93F642f64180aa3 "proxiableUUID()" --rpc-url $RPC_URL
# Should return: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

# ❌ INCORRECT: These don't work with ERC1967 proxy
# cast call $KMS_CONTRACT_ADDRESS "implementation()" --rpc-url $RPC_URL
# cast call $KMS_CONTRACT_ADDRESS "proxiableUUID()" --rpc-url $RPC_URL
```

### Upgrade Operations

```bash
# Deploy new DstackKms implementation (equivalent to kms:deploy-impl)
npx hardhat kms:deploy-impl --network test
# Output: ✅ DstackKms implementation deployed to: NEW_IMPL_ADDRESS

# Upgrade the proxy to new implementation (equivalent to kms:upgrade)
cast send $KMS_CONTRACT_ADDRESS "upgradeTo(address)" "NEW_IMPL_ADDRESS" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL --gas-limit 500000

# Note: Existing KMS proxy deployments can be upgraded in-place using the steps above.
# This release only adds optional app boot TCB checks in DstackApp and keeps the KMS
# storage layout unchanged, so no initializer is required for the KMS upgrade.

# Verify upgrade success
cast storage $KMS_CONTRACT_ADDRESS 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC_URL
# Should show the new implementation address

# Test new functionality (if added)
cast call $KMS_CONTRACT_ADDRESS "owner()" --rpc-url $RPC_URL
```

## KMS Contract Operations

### Basic KMS Information

```bash
# info:kms - Get current KMS information
cast call $KMS_CONTRACT_ADDRESS "kmsInfo()" --rpc-url $RPC_URL
# To decode: cast abi-decode "kmsInfo()((bytes,bytes,bytes,bytes))" RETURN_DATA

# info:gateway - Get current Gateway App ID  
cast call $KMS_CONTRACT_ADDRESS "gatewayAppId()" --rpc-url $RPC_URL
# To decode: cast abi-decode "gatewayAppId()(string)" RETURN_DATA

# Get DstackApp implementation address for factory deployment
cast call $KMS_CONTRACT_ADDRESS "appImplementation()" --rpc-url $RPC_URL
# To decode: cast abi-decode "appImplementation()(address)" RETURN_DATA
# Should return: 0x0000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e0

# Get contract owner
cast call $KMS_CONTRACT_ADDRESS "owner()" --rpc-url $RPC_URL
# To decode: cast abi-decode "owner()(address)" RETURN_DATA
```

### KMS Configuration

```bash
# kms:set-gateway - Set the allowed Gateway App ID
cast send $KMS_CONTRACT_ADDRESS "setGatewayAppId(string)" "APP_ID_HERE" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# kms:set-info - Set KMS information (complex struct)
cast send $KMS_CONTRACT_ADDRESS "setKmsInfo((bytes,bytes,bytes,bytes))" \
  "(0xk256_pubkey,0xca_pubkey,0xquote,0xeventlog)" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# Set DstackApp implementation for factory deployment (owner only)
cast send $KMS_CONTRACT_ADDRESS "setAppImplementation(address)" \
  "APP_IMPL_ADDRESS" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

### KMS Aggregated MR Management

```bash
# kms:add - Add a KMS aggregated MR
cast send $KMS_CONTRACT_ADDRESS "addKmsAggregatedMr(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# kms:remove - Remove a KMS aggregated MR
cast send $KMS_CONTRACT_ADDRESS "removeKmsAggregatedMr(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

### OS Image Management

```bash
# kms:add-image - Add an OS image measurement
cast send $KMS_CONTRACT_ADDRESS "addOsImageHash(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# kms:remove-image - Remove an OS image measurement
cast send $KMS_CONTRACT_ADDRESS "removeOsImageHash(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

### KMS Device Management

```bash
# kms:add-device - Add a KMS device ID
cast send $KMS_CONTRACT_ADDRESS "addKmsDevice(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# kms:remove-device - Remove a KMS device ID
cast send $KMS_CONTRACT_ADDRESS "removeKmsDevice(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

## App Registration & Factory Deployment

### Factory Deployment (Recommended - Single Transaction)

```bash
# kms:create-app - Deploy and register DstackApp in single transaction
cast send $KMS_CONTRACT_ADDRESS "deployAndRegisterApp(address,bool,bool,bool,bytes32,bytes32)" \
  "$DEPLOYER_ADDRESS" false false true \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
# Parameters: (owner, disableUpgrades, requireTcbUpToDate, allowAnyDevice, initialDeviceId, initialComposeHash)
# Use 0x0000...0000 for empty device/hash values
# To decode return: cast abi-decode "deployAndRegisterApp(address,bool,bool,bool,bytes32,bytes32)(address,address)" RETURN_DATA

# Example with no initial data:
cast send $KMS_CONTRACT_ADDRESS "deployAndRegisterApp(address,bool,bool,bool,bytes32,bytes32)" \
  "$DEPLOYER_ADDRESS" false false true \
  "0x0000000000000000000000000000000000000000000000000000000000000000" \
  "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

### Traditional App Registration

```bash
# Register an existing DstackApp contract with KMS
cast send $KMS_CONTRACT_ADDRESS "registerApp(address)" \
  "$APP_AUTH_ADDRESS" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# Get next app ID
cast call $KMS_CONTRACT_ADDRESS "nextAppId()" --rpc-url $RPC_URL
# To decode: cast abi-decode "nextAppId()(address)" RETURN_DATA

# app:show-controller - Get DstackApp controller for an app
cast call $KMS_CONTRACT_ADDRESS "apps(address)" "APP_ID_HERE" --rpc-url $RPC_URL
# To decode: cast abi-decode "apps(address)((bool,address))" RETURN_DATA
```

### KMS Query Operations

```bash
# Check if aggregated MR is allowed
cast call $KMS_CONTRACT_ADDRESS "kmsAllowedAggregatedMrs(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --rpc-url $RPC_URL
# To decode: cast abi-decode "kmsAllowedAggregatedMrs(bytes32)(bool)" RETURN_DATA

# Check if KMS device is allowed
cast call $KMS_CONTRACT_ADDRESS "kmsAllowedDeviceIds(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --rpc-url $RPC_URL
# To decode: cast abi-decode "kmsAllowedDeviceIds(bytes32)(bool)" RETURN_DATA

# Check if OS image is allowed
cast call $KMS_CONTRACT_ADDRESS "allowedOsImages(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --rpc-url $RPC_URL
# To decode: cast abi-decode "allowedOsImages(bytes32)(bool)" RETURN_DATA

# Get next app sequence for a user
cast call $KMS_CONTRACT_ADDRESS "nextAppSequence(address)" "USER_ADDRESS_HERE" \
  --rpc-url $RPC_URL
# To decode: cast abi-decode "nextAppSequence(address)(uint256)" RETURN_DATA

# Check if KMS is allowed to boot
cast call $KMS_CONTRACT_ADDRESS "isKmsAllowed((address,bytes32,address,bytes32,bytes32,bytes32,bytes32,string,string[]))" \
  "(app_id,compose_hash,instance_id,device_id,mr_aggregated,mr_system,os_image_hash,tcb_status,[])" \
  --rpc-url $RPC_URL
# To decode: cast abi-decode "isKmsAllowed((address,bytes32,address,bytes32,bytes32,bytes32,bytes32,string,string[]))(bool,string)" RETURN_DATA

# Check if app is allowed to boot (via KMS)
cast call $KMS_CONTRACT_ADDRESS "isAppAllowed((address,bytes32,address,bytes32,bytes32,bytes32,bytes32,string,string[]))" \
  "(app_id,compose_hash,instance_id,device_id,mr_aggregated,mr_system,os_image_hash,tcb_status,[])" \
  --rpc-url $RPC_URL
# To decode: cast abi-decode "isAppAllowed((address,bytes32,address,bytes32,bytes32,bytes32,bytes32,string,string[]))(bool,string)" RETURN_DATA
```

## DstackApp Contract Operations

### Query Operations

```bash
# Get owner
cast call $APP_AUTH_ADDRESS "owner()" --rpc-url $RPC_URL
# To decode: cast abi-decode "owner()(address)" RETURN_DATA

# Get allowAnyDevice setting
cast call $APP_AUTH_ADDRESS "allowAnyDevice()" --rpc-url $RPC_URL
# To decode: cast abi-decode "allowAnyDevice()(bool)" RETURN_DATA

# Check if a device is allowed
cast call $APP_AUTH_ADDRESS "allowedDeviceIds(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --rpc-url $RPC_URL
# To decode: cast abi-decode "allowedDeviceIds(bytes32)(bool)" RETURN_DATA

# Check if a compose hash is allowed
cast call $APP_AUTH_ADDRESS "allowedComposeHashes(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --rpc-url $RPC_URL
# To decode: cast abi-decode "allowedComposeHashes(bytes32)(bool)" RETURN_DATA
```

### Compose Hash Management

```bash
# app:add-hash - Add a compose hash
cast send $APP_AUTH_ADDRESS "addComposeHash(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# app:remove-hash - Remove a compose hash
cast send $APP_AUTH_ADDRESS "removeComposeHash(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

### Device Management

```bash
# app:add-device - Add a device ID
cast send $APP_AUTH_ADDRESS "addDevice(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# app:remove-device - Remove a device ID
cast send $APP_AUTH_ADDRESS "removeDevice(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# app:set-allow-any-device - Set allowAnyDevice flag
cast send $APP_AUTH_ADDRESS "setAllowAnyDevice(bool)" true \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
cast send $APP_AUTH_ADDRESS "setAllowAnyDevice(bool)" false \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

### App Authorization Check

```bash
# Check if an app is allowed to boot (complex struct required)
# Note: This requires encoding the AppBootInfo struct
cast call $APP_AUTH_ADDRESS "isAppAllowed((address,bytes32,address,bytes32,bytes32,bytes32,bytes32,string,string[]))" \
  "(app_id,compose_hash,instance_id,device_id,mr_aggregated,mr_system,os_image_hash,tcb_status,[])" \
  --rpc-url $RPC_URL
# To decode: cast abi-decode "isAppAllowed((address,bytes32,address,bytes32,bytes32,bytes32,bytes32,string,string[]))(bool,string)" RETURN_DATA
```

### Upgrade Management

```bash
# DstackApp upgrade (if not disabled)
cast send $APP_AUTH_ADDRESS "upgradeTo(address)" "NEW_APP_IMPL_ADDRESS" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# Disable upgrades permanently
cast send $APP_AUTH_ADDRESS "disableUpgrades()" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

## Utility Commands

### Check Transaction Status

```bash
# Check transaction receipt
cast receipt TRANSACTION_HASH --rpc-url $RPC_URL

# Get transaction details
cast tx TRANSACTION_HASH --rpc-url $RPC_URL
```

### Encode/Decode Data

```bash
# Encode function call data
cast calldata "addComposeHash(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# Decode return data
cast --to-ascii RETURN_DATA
cast --to-dec RETURN_DATA

# Decode ABI-encoded return values (for complex types)
cast abi-decode "functionName()(returnType)" RETURN_DATA

# Examples from this contract:
# Decode KMS info struct
cast abi-decode "kmsInfo()((bytes,bytes,bytes,bytes))" RETURN_DATA

# Decode app config struct  
cast abi-decode "apps(address)((bool,address))" RETURN_DATA

# Decode boolean mappings
cast abi-decode "allowedDeviceIds(bytes32)(bool)" RETURN_DATA
cast abi-decode "allowedComposeHashes(bytes32)(bool)" RETURN_DATA
cast abi-decode "kmsAllowedAggregatedMrs(bytes32)(bool)" RETURN_DATA

# Decode isAppAllowed response
cast abi-decode "isAppAllowed((address,bytes32,address,bytes32,bytes32,bytes32,bytes32,string,string[]))(bool,string)" RETURN_DATA

# Decode factory deployment response
cast abi-decode "deployAndRegisterApp(address,bool,bool,bool,bytes32,bytes32)(address,address)" RETURN_DATA
```

### Get Contract Information

```bash
# Get contract code
cast code $CONTRACT_ADDRESS --rpc-url $RPC_URL

# Get storage slot
cast storage $CONTRACT_ADDRESS SLOT_NUMBER --rpc-url $RPC_URL

# Get nonce
cast nonce $DEPLOYER_ADDRESS --rpc-url $RPC_URL

# Get balance
cast balance $DEPLOYER_ADDRESS --rpc-url $RPC_URL
```

## Advanced Usage

### Using with Different Networks

```bash
# Phala Network
export RPC_URL="https://rpc.phala.network"

# Sepolia Testnet
export RPC_URL="https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY"

# Local development
export RPC_URL="http://127.0.0.1:8545"

# Custom test network
export RPC_URL="http://kms2.phatfn.xyz:8545"
```

### Batch Operations

```bash
# Execute multiple commands in sequence
cast send $APP_AUTH_ADDRESS "addDevice(bytes32)" "0x1111..." \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL && \
cast send $APP_AUTH_ADDRESS "addComposeHash(bytes32)" "0x2222..." \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

### Gas Estimation and Control

```bash
# Estimate gas for a transaction
cast estimate $APP_AUTH_ADDRESS "addDevice(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  --rpc-url $RPC_URL

# Send with custom gas limit
cast send $KMS_CONTRACT_ADDRESS "upgradeTo(address)" "NEW_IMPL_ADDRESS" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL --gas-limit 500000

# Send with custom gas price
cast send $APP_AUTH_ADDRESS "addDevice(bytes32)" "0x1234..." \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL --gas-price 2000000000
```

## Complete Deployment Workflow

### Production Deployment Process

#### Streamlined Deployment (Recommended)

```bash
# 1. Complete Setup (Deploy DstackApp implementation and KMS in one command)
npx hardhat kms:deploy --with-app-impl --network test
export KMS_CONTRACT_ADDRESS="DEPLOYED_PROXY_ADDRESS"

# 2. Configure KMS (add allowed MRs, devices, images)
cast send $KMS_CONTRACT_ADDRESS "addKmsAggregatedMr(bytes32)" "0x..." \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# 3. Users can now deploy apps via factory immediately!
cast send $KMS_CONTRACT_ADDRESS "deployAndRegisterApp(address,bool,bool,bool,bytes32,bytes32)" \
  "$USER_ADDRESS" false true "0x..." "0x..." \
  --private-key $USER_PRIVATE_KEY --rpc-url $RPC_URL
```

#### Traditional Deployment Process

```bash
# 1. Initial Setup (Deploy KMS with UUPS proxy)
npx hardhat kms:deploy --network test
export KMS_CONTRACT_ADDRESS="DEPLOYED_PROXY_ADDRESS"

# 2. Deploy DstackApp implementation
npx hardhat app:deploy-impl --network test
# Note the implementation address

# 3. Set DstackApp implementation in KMS
cast send $KMS_CONTRACT_ADDRESS "setAppImplementation(address)" \
  "APP_IMPL_ADDRESS" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# 4. Configure KMS (add allowed MRs, devices, images)
cast send $KMS_CONTRACT_ADDRESS "addKmsAggregatedMr(bytes32)" "0x..." \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# 5. Users can now deploy apps via factory
cast send $KMS_CONTRACT_ADDRESS "deployAndRegisterApp(address,bool,bool,bool,bytes32,bytes32)" \
  "$USER_ADDRESS" false true "0x..." "0x..." \
  --private-key $USER_PRIVATE_KEY --rpc-url $RPC_URL
```

### Upgrade Process

```bash
# 1. Deploy new DstackKms implementation
npx hardhat kms:deploy-impl --network test

# 2. Upgrade proxy (requires owner)
cast send $KMS_CONTRACT_ADDRESS "upgradeTo(address)" "NEW_IMPL_ADDRESS" \
  --private-key $PRIVATE_KEY --rpc-url $RPC_URL --gas-limit 500000

# 3. Verify upgrade
cast storage $KMS_CONTRACT_ADDRESS 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC_URL

# 4. Test new functionality
cast call $KMS_CONTRACT_ADDRESS "owner()" --rpc-url $RPC_URL
```

## Quick Reference

| Hardhat Task | Cast Equivalent | Notes |
|--------------|-----------------|-------|
| `kms:deploy` | Use hardhat (complex proxy deployment) | Creates UUPS proxy, optionally sets DstackApp impl |
| `kms:deploy --with-app-impl` | Use hardhat | **⭐ Recommended**: Deploys both DstackApp impl & KMS in one go |
| `kms:deploy-impl` | `npx hardhat kms:deploy-impl` | Deploys implementation only |
| `app:deploy-impl` | `npx hardhat app:deploy-impl` | Deploys DstackApp implementation |
| `kms:upgrade` | `cast send ... upgradeTo` | Upgrades proxy to new impl |
| `kms:add` | `cast send ... addKmsAggregatedMr` | Direct mapping |
| `app:add-hash` | `cast send ... addComposeHash` | Need DstackApp address |
| `info:kms` | `cast call ... kmsInfo` | Returns struct |
| `app:deploy` | Complex hardhat task | Multi-transaction deployment |
| `app:deploy-with-data` | Complex hardhat task | Use initializeWithData |
| `app:deploy-factory` | `cast send ... deployAndRegisterApp` | **Single transaction deployment** ⭐ |
| `kms:set-app-implementation` | `cast send ... setAppImplementation` | Manual setup (rarely needed now) |
| `kms:get-app-implementation` | `cast call ... appImplementation` | Query factory implementation |

## Important Notes

- **UUPS Proxy Verification**: Use storage slot queries, not direct function calls
- **Factory Deployment**: Recommended for new apps (single transaction)
- **Upgrade Safety**: Always verify implementation compatibility before upgrading
- **Gas Limits**: Upgrades and factory deployments may need higher gas limits
- **Error Handling**: Always check transaction receipts for success/failure status
- **Complex Structs**: Functions requiring structs need manual encoding

## Simplified Usage with Alias

After setting up the alias `alias mycast="cast --private-key $PRIVATE_KEY --rpc-url $RPC_URL"`, you can use shorter commands:

```bash
# Example: Get KMS info
mycast call $KMS_CONTRACT_ADDRESS "kmsInfo()"

# Example: Add device
mycast send $APP_AUTH_ADDRESS "addDevice(bytes32)" \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# Example: Factory deployment
mycast send $KMS_CONTRACT_ADDRESS "deployAndRegisterApp(address,bool,bool,bool,bytes32,bytes32)" \
  "$DEPLOYER_ADDRESS" false true \
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" \
  "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"

# Example: Verify proxy implementation
mycast storage $KMS_CONTRACT_ADDRESS 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

# Example: Upgrade contract
mycast send $KMS_CONTRACT_ADDRESS "upgradeTo(address)" "NEW_IMPL_ADDRESS" --gas-limit 500000
``` 
