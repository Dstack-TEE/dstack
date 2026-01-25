// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { connect, keyStores, Near, Account, KeyPair, utils } from 'near-api-js';
import { parseNearAmount } from 'near-api-js/lib/utils/format';

// Helper function to load account from private key
async function getAccount(
  accountId: string,
  privateKey: string,
  networkId: string,
  rpcUrl: string
): Promise<Account> {
  const keyStore = new keyStores.InMemoryKeyStore();
  const keyPair = KeyPair.fromString(privateKey);
  keyStore.setKey(networkId, accountId, keyPair);

  const near = await connect({
    networkId,
    nodeUrl: rpcUrl,
    keyStore,
  });

  return await near.account(accountId);
}

// Helper function to get app account ID (subaccount of KMS)
function getAppAccountId(appId: string, kmsContractId: string): string {
  return `${appId}.${kmsContractId}`;
}

// Deploy app contract via KMS register_app
async function deployApp(
  kmsContractId: string,
  appId: string,
  ownerId: string,
  accountId: string,
  privateKey: string,
  networkId: string,
  rpcUrl: string,
  options: {
    disableUpgrades?: boolean;
    allowAnyDevice?: boolean;
    initialDeviceId?: string;
    initialComposeHash?: string;
    deposit?: string; // in NEAR
  } = {}
): Promise<string> {
  const account = await getAccount(accountId, privateKey, networkId, rpcUrl);
  const appAccountId = getAppAccountId(appId, kmsContractId);

  console.log(`Deploying app contract...`);
  console.log(`  KMS Contract: ${kmsContractId}`);
  console.log(`  App ID: ${appId}`);
  console.log(`  App Account: ${appAccountId}`);
  console.log(`  Owner: ${ownerId}`);

  const args: any = {
    app_id: appId,
    owner_id: ownerId,
    disable_upgrades: options.disableUpgrades ?? false,
    allow_any_device: options.allowAnyDevice ?? false,
  };

  if (options.initialDeviceId) {
    args.initial_device_id = options.initialDeviceId;
  } else {
    args.initial_device_id = null;
  }

  if (options.initialComposeHash) {
    args.initial_compose_hash = options.initialComposeHash;
  } else {
    args.initial_compose_hash = null;
  }

  const deposit = options.deposit
    ? parseNearAmount(options.deposit)
    : parseNearAmount('30'); // Default 30 NEAR for account creation + deployment

  if (!deposit) {
    throw new Error('Failed to parse deposit amount');
  }

  try {
    const result = await account.functionCall({
      contractId: kmsContractId,
      methodName: 'register_app',
      args,
      gas: BigInt('300000000000000'), // 300 TGas
      attachedDeposit: BigInt(deposit),
    });

    console.log(`✅ App contract deployed successfully!`);
    console.log(`   App Account: ${appAccountId}`);
    console.log(`   Transaction: ${result.transaction.hash}`);
    return appAccountId;
  } catch (error) {
    console.error('❌ Failed to deploy app contract:', error);
    throw error;
  }
}

// Add compose hash to app contract
async function addComposeHash(
  appAccountId: string,
  composeHash: string,
  accountId: string,
  privateKey: string,
  networkId: string,
  rpcUrl: string
): Promise<void> {
  const account = await getAccount(accountId, privateKey, networkId, rpcUrl);

  // Convert hex hash to string (remove 0x prefix if present)
  const hashString = composeHash.startsWith('0x') ? composeHash.slice(2) : composeHash;

  console.log(`Adding compose hash to app contract...`);
  console.log(`  App Account: ${appAccountId}`);
  console.log(`  Compose Hash: ${hashString}`);

  try {
    const result = await account.functionCall({
      contractId: appAccountId,
      methodName: 'add_compose_hash',
      args: { compose_hash: hashString },
      gas: BigInt('100000000000000'), // 100 TGas
      attachedDeposit: BigInt('1'), // 1 yoctoNEAR
    });

    console.log(`✅ Compose hash added successfully!`);
    console.log(`   Transaction: ${result.transaction.hash}`);
  } catch (error) {
    console.error('❌ Failed to add compose hash:', error);
    throw error;
  }
}

// Remove compose hash from app contract
async function removeComposeHash(
  appAccountId: string,
  composeHash: string,
  accountId: string,
  privateKey: string,
  networkId: string,
  rpcUrl: string
): Promise<void> {
  const account = await getAccount(accountId, privateKey, networkId, rpcUrl);

  // Convert hex hash to string (remove 0x prefix if present)
  const hashString = composeHash.startsWith('0x') ? composeHash.slice(2) : composeHash;

  console.log(`Removing compose hash from app contract...`);
  console.log(`  App Account: ${appAccountId}`);
  console.log(`  Compose Hash: ${hashString}`);

  try {
    const result = await account.functionCall({
      contractId: appAccountId,
      methodName: 'remove_compose_hash',
      args: { compose_hash: hashString },
      gas: BigInt('100000000000000'), // 100 TGas
      attachedDeposit: BigInt('1'), // 1 yoctoNEAR
    });

    console.log(`✅ Compose hash removed successfully!`);
    console.log(`   Transaction: ${result.transaction.hash}`);
  } catch (error) {
    console.error('❌ Failed to remove compose hash:', error);
    throw error;
  }
}

// Add OS image hash to KMS contract
async function addOsImageHash(
  kmsContractId: string,
  osImageHash: string,
  accountId: string,
  privateKey: string,
  networkId: string,
  rpcUrl: string
): Promise<void> {
  const account = await getAccount(accountId, privateKey, networkId, rpcUrl);

  // Convert hex hash to string (remove 0x prefix if present)
  const hashString = osImageHash.startsWith('0x') ? osImageHash.slice(2) : osImageHash;

  console.log(`Adding OS image hash to KMS contract...`);
  console.log(`  KMS Contract: ${kmsContractId}`);
  console.log(`  OS Image Hash: ${hashString}`);

  try {
    const result = await account.functionCall({
      contractId: kmsContractId,
      methodName: 'add_os_image_hash',
      args: { os_image_hash: hashString },
      gas: BigInt('100000000000000'), // 100 TGas
      attachedDeposit: BigInt('1'), // 1 yoctoNEAR
    });

    console.log(`✅ OS image hash added successfully!`);
    console.log(`   Transaction: ${result.transaction.hash}`);
  } catch (error) {
    console.error('❌ Failed to add OS image hash:', error);
    throw error;
  }
}

// Remove OS image hash from KMS contract
async function removeOsImageHash(
  kmsContractId: string,
  osImageHash: string,
  accountId: string,
  privateKey: string,
  networkId: string,
  rpcUrl: string
): Promise<void> {
  const account = await getAccount(accountId, privateKey, networkId, rpcUrl);

  // Convert hex hash to string (remove 0x prefix if present)
  const hashString = osImageHash.startsWith('0x') ? osImageHash.slice(2) : osImageHash;

  console.log(`Removing OS image hash from KMS contract...`);
  console.log(`  KMS Contract: ${kmsContractId}`);
  console.log(`  OS Image Hash: ${hashString}`);

  try {
    const result = await account.functionCall({
      contractId: kmsContractId,
      methodName: 'remove_os_image_hash',
      args: { os_image_hash: hashString },
      gas: BigInt('100000000000000'), // 100 TGas
      attachedDeposit: BigInt('1'), // 1 yoctoNEAR
    });

    console.log(`✅ OS image hash removed successfully!`);
    console.log(`   Transaction: ${result.transaction.hash}`);
  } catch (error) {
    console.error('❌ Failed to remove OS image hash:', error);
    throw error;
  }
}

// Add KMS device ID to KMS contract
async function addKmsDevice(
  kmsContractId: string,
  deviceId: string,
  accountId: string,
  privateKey: string,
  networkId: string,
  rpcUrl: string
): Promise<void> {
  const account = await getAccount(accountId, privateKey, networkId, rpcUrl);

  // Convert hex device ID to string (remove 0x prefix if present)
  const deviceIdString = deviceId.startsWith('0x') ? deviceId.slice(2) : deviceId;

  console.log(`Adding KMS device ID to KMS contract...`);
  console.log(`  KMS Contract: ${kmsContractId}`);
  console.log(`  Device ID: ${deviceIdString}`);

  try {
    const result = await account.functionCall({
      contractId: kmsContractId,
      methodName: 'add_kms_device',
      args: { device_id: deviceIdString },
      gas: BigInt('100000000000000'), // 100 TGas
      attachedDeposit: BigInt('1'), // 1 yoctoNEAR
    });

    console.log(`✅ KMS device ID added successfully!`);
    console.log(`   Transaction: ${result.transaction.hash}`);
  } catch (error) {
    console.error('❌ Failed to add KMS device ID:', error);
    throw error;
  }
}

// Remove KMS device ID from KMS contract
async function removeKmsDevice(
  kmsContractId: string,
  deviceId: string,
  accountId: string,
  privateKey: string,
  networkId: string,
  rpcUrl: string
): Promise<void> {
  const account = await getAccount(accountId, privateKey, networkId, rpcUrl);

  // Convert hex device ID to string (remove 0x prefix if present)
  const deviceIdString = deviceId.startsWith('0x') ? deviceId.slice(2) : deviceId;

  console.log(`Removing KMS device ID from KMS contract...`);
  console.log(`  KMS Contract: ${kmsContractId}`);
  console.log(`  Device ID: ${deviceIdString}`);

  try {
    const result = await account.functionCall({
      contractId: kmsContractId,
      methodName: 'remove_kms_device',
      args: { device_id: deviceIdString },
      gas: BigInt('100000000000000'), // 100 TGas
      attachedDeposit: BigInt('1'), // 1 yoctoNEAR
    });

    console.log(`✅ KMS device ID removed successfully!`);
    console.log(`   Transaction: ${result.transaction.hash}`);
  } catch (error) {
    console.error('❌ Failed to remove KMS device ID:', error);
    throw error;
  }
}

// Add KMS aggregated MR to KMS contract
async function addKmsAggregatedMr(
  kmsContractId: string,
  mrAggregated: string,
  accountId: string,
  privateKey: string,
  networkId: string,
  rpcUrl: string
): Promise<void> {
  const account = await getAccount(accountId, privateKey, networkId, rpcUrl);

  // Convert hex MR to string (remove 0x prefix if present)
  const mrString = mrAggregated.startsWith('0x') ? mrAggregated.slice(2) : mrAggregated;

  console.log(`Adding KMS aggregated MR to KMS contract...`);
  console.log(`  KMS Contract: ${kmsContractId}`);
  console.log(`  Aggregated MR: ${mrString}`);

  try {
    const result = await account.functionCall({
      contractId: kmsContractId,
      methodName: 'add_kms_aggregated_mr',
      args: { mr_aggregated: mrString },
      gas: BigInt('100000000000000'), // 100 TGas
      attachedDeposit: BigInt('1'), // 1 yoctoNEAR
    });

    console.log(`✅ KMS aggregated MR added successfully!`);
    console.log(`   Transaction: ${result.transaction.hash}`);
  } catch (error) {
    console.error('❌ Failed to add KMS aggregated MR:', error);
    throw error;
  }
}

// Remove KMS aggregated MR from KMS contract
async function removeKmsAggregatedMr(
  kmsContractId: string,
  mrAggregated: string,
  accountId: string,
  privateKey: string,
  networkId: string,
  rpcUrl: string
): Promise<void> {
  const account = await getAccount(accountId, privateKey, networkId, rpcUrl);

  // Convert hex MR to string (remove 0x prefix if present)
  const mrString = mrAggregated.startsWith('0x') ? mrAggregated.slice(2) : mrAggregated;

  console.log(`Removing KMS aggregated MR from KMS contract...`);
  console.log(`  KMS Contract: ${kmsContractId}`);
  console.log(`  Aggregated MR: ${mrString}`);

  try {
    const result = await account.functionCall({
      contractId: kmsContractId,
      methodName: 'remove_kms_aggregated_mr',
      args: { mr_aggregated: mrString },
      gas: BigInt('100000000000000'), // 100 TGas
      attachedDeposit: BigInt('1'), // 1 yoctoNEAR
    });

    console.log(`✅ KMS aggregated MR removed successfully!`);
    console.log(`   Transaction: ${result.transaction.hash}`);
  } catch (error) {
    console.error('❌ Failed to remove KMS aggregated MR:', error);
    throw error;
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  // Get environment variables
  const networkId = process.env.NEAR_NETWORK_ID || process.env.NEAR_ENV || 'testnet';
  const rpcUrl =
    process.env.NEAR_RPC_URL ||
    (networkId === 'mainnet' ? 'https://rpc.near.org' : 'https://rpc.testnet.near.org');
  const kmsContractId = process.env.KMS_CONTRACT_ID || '';
  const accountId = process.env.NEAR_ACCOUNT_ID || '';
  const privateKey = process.env.NEAR_PRIVATE_KEY || '';

  if (!accountId || !privateKey) {
    console.error('❌ NEAR_ACCOUNT_ID and NEAR_PRIVATE_KEY environment variables are required');
    process.exit(1);
  }

  if (command === 'deploy') {
    // Usage: bun cli.ts deploy <app_id> <owner_id> [options]
    if (args.length < 3) {
      console.error('Usage: bun cli.ts deploy <app_id> <owner_id> [--disable-upgrades] [--allow-any-device] [--device-id <id>] [--compose-hash <hash>] [--deposit <near>]');
      process.exit(1);
    }

    if (!kmsContractId) {
      console.error('❌ KMS_CONTRACT_ID environment variable is required for deployment');
      process.exit(1);
    }

    const appId = args[1];
    const ownerId = args[2];
    const options: any = {};

    // Parse options
    for (let i = 3; i < args.length; i++) {
      if (args[i] === '--disable-upgrades') {
        options.disableUpgrades = true;
      } else if (args[i] === '--allow-any-device') {
        options.allowAnyDevice = true;
      } else if (args[i] === '--device-id' && i + 1 < args.length) {
        options.initialDeviceId = args[++i];
      } else if (args[i] === '--compose-hash' && i + 1 < args.length) {
        options.initialComposeHash = args[++i];
      } else if (args[i] === '--deposit' && i + 1 < args.length) {
        options.deposit = args[++i];
      }
    }

    await deployApp(
      kmsContractId,
      appId,
      ownerId,
      accountId,
      privateKey,
      networkId,
      rpcUrl,
      options
    );
  } else if (command === 'add-hash') {
    // Usage: bun cli.ts add-hash <app_account_id> <compose_hash>
    if (args.length < 3) {
      console.error('Usage: bun cli.ts add-hash <app_account_id> <compose_hash>');
      console.error('  app_account_id: Full account ID (e.g., app-id.kms-contract.near)');
      console.error('  compose_hash: Hex string (with or without 0x prefix)');
      process.exit(1);
    }

    const appAccountId = args[1];
    const composeHash = args[2];

    await addComposeHash(appAccountId, composeHash, accountId, privateKey, networkId, rpcUrl);
  } else if (command === 'remove-hash') {
    // Usage: bun cli.ts remove-hash <app_account_id> <compose_hash>
    if (args.length < 3) {
      console.error('Usage: bun cli.ts remove-hash <app_account_id> <compose_hash>');
      process.exit(1);
    }

    const appAccountId = args[1];
    const composeHash = args[2];

    await removeComposeHash(appAccountId, composeHash, accountId, privateKey, networkId, rpcUrl);
  } else if (command === 'add-os-image') {
    // Usage: bun cli.ts add-os-image <os_image_hash>
    if (args.length < 2) {
      console.error('Usage: bun cli.ts add-os-image <os_image_hash>');
      console.error('  os_image_hash: Hex string (with or without 0x prefix)');
      process.exit(1);
    }

    if (!kmsContractId) {
      console.error('❌ KMS_CONTRACT_ID environment variable is required');
      process.exit(1);
    }

    const osImageHash = args[1];
    await addOsImageHash(kmsContractId, osImageHash, accountId, privateKey, networkId, rpcUrl);
  } else if (command === 'remove-os-image') {
    // Usage: bun cli.ts remove-os-image <os_image_hash>
    if (args.length < 2) {
      console.error('Usage: bun cli.ts remove-os-image <os_image_hash>');
      console.error('  os_image_hash: Hex string (with or without 0x prefix)');
      process.exit(1);
    }

    if (!kmsContractId) {
      console.error('❌ KMS_CONTRACT_ID environment variable is required');
      process.exit(1);
    }

    const osImageHash = args[1];
    await removeOsImageHash(kmsContractId, osImageHash, accountId, privateKey, networkId, rpcUrl);
  } else if (command === 'add-device') {
    // Usage: bun cli.ts add-device <device_id>
    if (args.length < 2) {
      console.error('Usage: bun cli.ts add-device <device_id>');
      console.error('  device_id: Hex string (with or without 0x prefix)');
      process.exit(1);
    }

    if (!kmsContractId) {
      console.error('❌ KMS_CONTRACT_ID environment variable is required');
      process.exit(1);
    }

    const deviceId = args[1];
    await addKmsDevice(kmsContractId, deviceId, accountId, privateKey, networkId, rpcUrl);
  } else if (command === 'remove-device') {
    // Usage: bun cli.ts remove-device <device_id>
    if (args.length < 2) {
      console.error('Usage: bun cli.ts remove-device <device_id>');
      console.error('  device_id: Hex string (with or without 0x prefix)');
      process.exit(1);
    }

    if (!kmsContractId) {
      console.error('❌ KMS_CONTRACT_ID environment variable is required');
      process.exit(1);
    }

    const deviceId = args[1];
    await removeKmsDevice(kmsContractId, deviceId, accountId, privateKey, networkId, rpcUrl);
  } else if (command === 'add-mr') {
    // Usage: bun cli.ts add-mr <mr_aggregated>
    if (args.length < 2) {
      console.error('Usage: bun cli.ts add-mr <mr_aggregated>');
      console.error('  mr_aggregated: Hex string (with or without 0x prefix)');
      process.exit(1);
    }

    if (!kmsContractId) {
      console.error('❌ KMS_CONTRACT_ID environment variable is required');
      process.exit(1);
    }

    const mrAggregated = args[1];
    await addKmsAggregatedMr(kmsContractId, mrAggregated, accountId, privateKey, networkId, rpcUrl);
  } else if (command === 'remove-mr') {
    // Usage: bun cli.ts remove-mr <mr_aggregated>
    if (args.length < 2) {
      console.error('Usage: bun cli.ts remove-mr <mr_aggregated>');
      console.error('  mr_aggregated: Hex string (with or without 0x prefix)');
      process.exit(1);
    }

    if (!kmsContractId) {
      console.error('❌ KMS_CONTRACT_ID environment variable is required');
      process.exit(1);
    }

    const mrAggregated = args[1];
    await removeKmsAggregatedMr(kmsContractId, mrAggregated, accountId, privateKey, networkId, rpcUrl);
  } else {
    console.error('Unknown command:', command);
    console.error('');
    console.error('Available commands:');
    console.error('  deploy <app_id> <owner_id> [options]     - Deploy app contract via KMS');
    console.error('  add-hash <app_account_id> <hash>         - Add compose hash to app contract');
    console.error('  remove-hash <app_account_id> <hash>     - Remove compose hash from app contract');
    console.error('  add-os-image <os_image_hash>             - Add OS image hash to KMS contract');
    console.error('  remove-os-image <os_image_hash>          - Remove OS image hash from KMS contract');
    console.error('  add-device <device_id>                   - Add KMS device ID to KMS contract');
    console.error('  remove-device <device_id>                - Remove KMS device ID from KMS contract');
    console.error('  add-mr <mr_aggregated>                   - Add KMS aggregated MR to KMS contract');
    console.error('  remove-mr <mr_aggregated>               - Remove KMS aggregated MR from KMS contract');
    console.error('');
    console.error('Environment variables:');
    console.error('  NEAR_ACCOUNT_ID      - NEAR account ID (required)');
    console.error('  NEAR_PRIVATE_KEY     - NEAR account private key (required)');
    console.error('  KMS_CONTRACT_ID      - KMS contract ID (required for KMS operations)');
    console.error('  NEAR_NETWORK_ID      - Network ID (testnet/mainnet, default: testnet)');
    console.error('  NEAR_RPC_URL         - NEAR RPC URL (optional, auto-detected by network)');
    process.exit(1);
  }
}

// Run CLI if executed directly (Bun supports import.meta.main)
if (import.meta.main) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

export {
  deployApp,
  addComposeHash,
  removeComposeHash,
  getAppAccountId,
  addOsImageHash,
  removeOsImageHash,
  addKmsDevice,
  removeKmsDevice,
  addKmsAggregatedMr,
  removeKmsAggregatedMr,
};

