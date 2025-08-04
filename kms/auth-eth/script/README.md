# Foundry Scripts

This directory contains Foundry scripts for deploying and managing dstack contracts.

## Deployment Scripts (`Deploy.s.sol`)

### DeployScript
Deploys both DstackKms and DstackApp implementation:
```bash
forge script script/Deploy.s.sol:DeployScript --broadcast --rpc-url $RPC_URL
```

### DeployKmsOnly
Deploys only DstackKms (requires APP_IMPLEMENTATION):
```bash
APP_IMPLEMENTATION=0x... forge script script/Deploy.s.sol:DeployKmsOnly --broadcast --rpc-url $RPC_URL
```

### DeployAppOnly
Deploys only DstackApp implementation:
```bash
forge script script/Deploy.s.sol:DeployAppOnly --broadcast --rpc-url $RPC_URL
```

## Management Scripts (`Manage.s.sol`)

Type-safe contract management scripts. Set the environment variables and run the scripts.

### KMS Management

#### Add KMS Aggregated MR
```bash
KMS_CONTRACT_ADDR=0x... MR_AGGREGATED=0x1234... \
forge script script/Manage.s.sol:AddKmsAggregatedMr --broadcast --rpc-url $RPC_URL
```

#### Add OS Image
```bash
KMS_CONTRACT_ADDR=0x... OS_IMAGE_HASH=0x1234... \
forge script script/Manage.s.sol:AddOsImage --broadcast --rpc-url $RPC_URL
```

#### Add KMS Device
```bash
KMS_CONTRACT_ADDR=0x... DEVICE_ID=0x1234... \
forge script script/Manage.s.sol:AddKmsDevice --broadcast --rpc-url $RPC_URL
```

#### Set Gateway App ID
```bash
KMS_CONTRACT_ADDR=0x... GATEWAY_APP_ID="my-gateway" \
forge script script/Manage.s.sol:SetGatewayAppId --broadcast --rpc-url $RPC_URL
```

#### Set KMS Info
```bash
KMS_CONTRACT_ADDR=0x... K256_PUBKEY=0x... CA_PUBKEY=0x... QUOTE=0x... EVENTLOG=0x... \
forge script script/Manage.s.sol:SetKmsInfo --broadcast --rpc-url $RPC_URL
```

#### Remove KMS Aggregated MR
```bash
KMS_CONTRACT_ADDR=0x... MR_AGGREGATED=0x1234... \
forge script script/Manage.s.sol:RemoveKmsAggregatedMr --broadcast --rpc-url $RPC_URL
```

#### Remove OS Image
```bash
KMS_CONTRACT_ADDR=0x... OS_IMAGE_HASH=0x1234... \
forge script script/Manage.s.sol:RemoveOsImage --broadcast --rpc-url $RPC_URL
```

#### Remove KMS Device
```bash
KMS_CONTRACT_ADDR=0x... DEVICE_ID=0x1234... \
forge script script/Manage.s.sol:RemoveKmsDevice --broadcast --rpc-url $RPC_URL
```

#### Set App Implementation
```bash
KMS_CONTRACT_ADDR=0x... APP_IMPLEMENTATION=0x... \
forge script script/Manage.s.sol:SetAppImplementation --broadcast --rpc-url $RPC_URL
```

#### Register Existing App
```bash
KMS_CONTRACT_ADDR=0x... APP_ADDRESS=0x... \
forge script script/Manage.s.sol:RegisterApp --broadcast --rpc-url $RPC_URL
```

#### Batch KMS Setup
Configure multiple settings at once:
```bash
KMS_CONTRACT_ADDR=0x... \
GATEWAY_APP_ID="my-gateway" \
MR_AGGREGATED_LIST=0x1111...,0x2222...,0x3333... \
OS_IMAGE_LIST=0xaaaa...,0xbbbb... \
DEVICE_LIST=0xcccc...,0xdddd... \
forge script script/Manage.s.sol:BatchKmsSetup --broadcast --rpc-url $RPC_URL
```

### App Management

#### Add Compose Hash
```bash
KMS_CONTRACT_ADDR=0x... APP_CONTRACT_ADDR=0x... COMPOSE_HASH=0x1234... \
forge script script/Manage.s.sol:AddComposeHash --broadcast --rpc-url $RPC_URL
```

#### Add Device
```bash
KMS_CONTRACT_ADDR=0x... APP_CONTRACT_ADDR=0x... DEVICE_ID=0x1234... \
forge script script/Manage.s.sol:AddDevice --broadcast --rpc-url $RPC_URL
```

#### Set Allow Any Device
```bash
KMS_CONTRACT_ADDR=0x... APP_CONTRACT_ADDR=0x... ALLOW_ANY_DEVICE=true \
forge script script/Manage.s.sol:SetAllowAnyDevice --broadcast --rpc-url $RPC_URL
```

#### Remove Compose Hash
```bash
KMS_CONTRACT_ADDR=0x... APP_CONTRACT_ADDR=0x... COMPOSE_HASH=0x1234... \
forge script script/Manage.s.sol:RemoveComposeHash --broadcast --rpc-url $RPC_URL
```

#### Remove Device
```bash
KMS_CONTRACT_ADDR=0x... APP_CONTRACT_ADDR=0x... DEVICE_ID=0x1234... \
forge script script/Manage.s.sol:RemoveDevice --broadcast --rpc-url $RPC_URL
```

#### Disable App Upgrades
```bash
KMS_CONTRACT_ADDR=0x... APP_CONTRACT_ADDR=0x... \
forge script script/Manage.s.sol:DisableAppUpgrades --broadcast --rpc-url $RPC_URL
```

### Factory Deployment

Deploy a new app via factory:
```bash
KMS_CONTRACT_ADDR=0x... \
APP_OWNER=0x... \
DISABLE_UPGRADES=false \
ALLOW_ANY_DEVICE=true \
INITIAL_DEVICE_ID=0x1234... \
INITIAL_COMPOSE_HASH=0x5678... \
forge script script/Manage.s.sol:DeployApp --broadcast --rpc-url $RPC_URL
```

## Query Scripts (`Query.s.sol`)

Query scripts provide read-only access to contract state without transactions.

### KMS Queries

#### Get All KMS Settings
```bash
KMS_CONTRACT_ADDR=0x... \
forge script script/Query.s.sol:GetKmsSettings --rpc-url $RPC_URL
```

#### Check KMS Aggregated MR
```bash
KMS_CONTRACT_ADDR=0x... MR_AGGREGATED=0x1234... \
forge script script/Query.s.sol:CheckKmsAggregatedMr --rpc-url $RPC_URL
```

#### Check KMS Device
```bash
KMS_CONTRACT_ADDR=0x... DEVICE_ID=0x1234... \
forge script script/Query.s.sol:CheckKmsDevice --rpc-url $RPC_URL
```

#### Check OS Image
```bash
KMS_CONTRACT_ADDR=0x... OS_IMAGE_HASH=0x1234... \
forge script script/Query.s.sol:CheckOsImage --rpc-url $RPC_URL
```

#### Check App Registration
```bash
KMS_CONTRACT_ADDR=0x... APP_ADDRESS=0x... \
forge script script/Query.s.sol:CheckAppRegistration --rpc-url $RPC_URL
```

#### Check KMS Boot Authorization
```bash
KMS_CONTRACT_ADDR=0x... \
APP_ID=0x... COMPOSE_HASH=0x... DEVICE_ID=0x... \
MR_AGGREGATED=0x... OS_IMAGE_HASH=0x... \
forge script script/Query.s.sol:CheckKmsAllowed --rpc-url $RPC_URL
```

#### Check App Boot Authorization
```bash
KMS_CONTRACT_ADDR=0x... \
APP_ID=0x... COMPOSE_HASH=0x... DEVICE_ID=0x... \
MR_AGGREGATED=0x... OS_IMAGE_HASH=0x... \
forge script script/Query.s.sol:CheckAppAllowed --rpc-url $RPC_URL
```

### App Queries

#### Get All App Settings
```bash
APP_CONTRACT_ADDR=0x... \
forge script script/Query.s.sol:GetAppSettings --rpc-url $RPC_URL
```

#### Check Compose Hash
```bash
APP_CONTRACT_ADDR=0x... COMPOSE_HASH=0x1234... \
forge script script/Query.s.sol:CheckComposeHash --rpc-url $RPC_URL
```

#### Check App Device
```bash
APP_CONTRACT_ADDR=0x... DEVICE_ID=0x1234... \
forge script script/Query.s.sol:CheckAppDevice --rpc-url $RPC_URL
```

### Storage Queries

#### Get Storage Slot Value
```bash
TARGET_ADDRESS=0x... STORAGE_SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc \
forge script script/Query.s.sol:GetStorageSlot --rpc-url $RPC_URL
```

## Upgrade Scripts (`Upgrade.s.sol`)

The upgrade scripts use OpenZeppelin's Foundry upgrades plugin for safe contract upgrades with validation.

### Safe Upgrades with Validation

#### Upgrade KMS to V2
```bash
KMS_CONTRACT_ADDR=0x... \
forge script script/Upgrade.s.sol:UpgradeKmsToV2 --broadcast --rpc-url $RPC_URL --ffi
```

#### Upgrade App to V2
```bash
APP_CONTRACT_ADDR=0x... \
forge script script/Upgrade.s.sol:UpgradeAppToV2 --broadcast --rpc-url $RPC_URL --ffi
```

### Important Notes on Upgrades

- **FFI Required**: Upgrade scripts require `--ffi` flag for the OpenZeppelin plugin
- **Validation**: The plugin automatically validates storage layout compatibility
- **Safety Checks**: Prevents common upgrade mistakes like storage collisions
- **V2 Contracts**: Upgrades use specific V2 contract implementations

## Environment Variables

### Required
- `KMS_CONTRACT_ADDR` - Address of deployed KMS proxy
- `APP_CONTRACT_ADDR` - Address of specific app (for app operations)
- `PRIVATE_KEY` - Private key for transactions

### Optional
- `RPC_URL` - RPC endpoint (default: http://localhost:8545)
- Various operation-specific variables (see examples above)

## Script Categories

### Management Scripts (`Manage.s.sol`)
- Write operations: Add/remove/set functions
- Factory deployment
- Batch operations

### Query Scripts (`Query.s.sol`)  
- Read-only operations: Check/get functions
- Storage inspection
- Boot authorization validation

### Upgrade Scripts (`Upgrade.s.sol`)
- Safe contract upgrades with validation
- Version-specific upgrade paths

### Deploy Scripts (`Deploy.s.sol`)
- Initial contract deployment
- Various deployment configurations

## Benefits

1. **Type Safety**: Solidity types prevent encoding errors
2. **Validation**: Built-in parameter validation
3. **Logging**: Clear console output
4. **Batch Operations**: Execute multiple transactions efficiently  
5. **Maintainability**: Easy to modify and extend

## Creating Custom Scripts

To create your own management script:

1. Extend `BaseScript` for common functionality
2. Implement the `run()` function
3. Use `vm.env*` functions to read parameters
4. Use `vm.startBroadcast()` / `vm.stopBroadcast()` for transactions
5. Add console.log statements for clarity

Example:
```solidity
contract MyCustomScript is BaseScript {
    function run() external {
        // Read parameters
        uint256 value = vm.envUint("MY_VALUE");
        
        // Execute transaction
        vm.startBroadcast();
        kms.someFunction(value);
        vm.stopBroadcast();
        
        // Log result
        console.log("Executed with value:", value);
    }
}
```

## Tips

- Use `--dry-run` to simulate without broadcasting
- Add `-vvvv` for detailed trace output
- Check gas usage with `--gas-report`
- Use `.env` files to manage environment variables