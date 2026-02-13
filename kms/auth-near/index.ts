// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { connect, keyStores, Near, Contract, Account } from 'near-api-js';

// zod schemas for validation - compatible with original fastify implementation
const BootInfoSchema = z.object({
  // required fields (matching original fastify schema)
  mrAggregated: z.string().describe('aggregated MR measurement'),
  osImageHash: z.string().describe('OS Image hash'),
  appId: z.string().describe('application ID'),
  composeHash: z.string().describe('compose hash'),
  instanceId: z.string().describe('instance ID'),
  deviceId: z.string().describe('device ID'),
  // optional fields (for full compatibility with BootInfo interface)
  tcbStatus: z.string().optional().default(''),
  advisoryIds: z.array(z.string()).optional().default([]),
  mrSystem: z.string().optional().default('')
});

const BootResponseSchema = z.object({
  isAllowed: z.boolean(),
  reason: z.string(),
  gatewayAppId: z.string()
});

type BootInfo = z.infer<typeof BootInfoSchema>;
type BootResponse = z.infer<typeof BootResponseSchema>;

// NEAR backend class
class NearBackend {
  private near: Near;
  private kmsContractId: string;
  private account: Account | null;

  constructor(near: Near, kmsContractId: string, account: Account | null) {
    this.near = near;
    this.kmsContractId = kmsContractId;
    this.account = account;
  }

  private ensureAccount(): Account {
    if (!this.account) {
      throw new Error('NEAR account not initialized');
    }
    return this.account;
  }

  private hexToAccountId(hex: string): string {
    // Remove '0x' prefix if present
    hex = hex.startsWith('0x') ? hex.slice(2) : hex;
    // For NEAR, we'll use the hex string as-is or convert to a valid account ID format
    // Since NEAR account IDs are strings, we'll use the hex as a subaccount or convert
    // For now, we'll assume the hex represents a valid account ID or use it directly
    // In production, you might want to map hex addresses to NEAR account IDs
    return hex;
  }

    async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    // Create boot info struct for NEAR contract call
    const bootInfoStruct = {
      app_id: this.hexToAccountId(bootInfo.appId),
      compose_hash: bootInfo.composeHash,
      instance_id: this.hexToAccountId(bootInfo.instanceId),
      device_id: bootInfo.deviceId,
      mr_aggregated: bootInfo.mrAggregated,
      mr_system: bootInfo.mrSystem || '',
      os_image_hash: bootInfo.osImageHash,
      tcb_status: bootInfo.tcbStatus || '',
      advisory_ids: bootInfo.advisoryIds || []
    };

    const account = this.ensureAccount();
    let response: [boolean, string];
    if (isKms) {
      // Call is_kms_allowed on KMS contract
      response = await account.viewFunction({
        contractId: this.kmsContractId,
        methodName: 'is_kms_allowed',
        args: bootInfoStruct
      });
    } else {
      // For app boot, follow the same flow as Ethereum contract:
      // 1. Check if app is registered in KMS contract
      const isRegistered = await account.viewFunction({
        contractId: this.kmsContractId,
        methodName: 'is_app_registered',
        args: { app_id: bootInfoStruct.app_id }
      });

      if (!isRegistered) {
        return {
          isAllowed: false,
          reason: 'App not registered',
          gatewayAppId: ''
        };
      }

      // 2. Check if OS image is allowed in KMS contract
      const isOsImageAllowed = await account.viewFunction({
        contractId: this.kmsContractId,
        methodName: 'is_os_image_allowed',
        args: { os_image_hash: bootInfoStruct.os_image_hash }
      });

      if (!isOsImageAllowed) {
        return {
          isAllowed: false,
          reason: 'OS image is not allowed',
          gatewayAppId: ''
        };
      }

      // 3. Call is_app_allowed on the app contract
      // The app_id in bootInfo is the app contract account ID
      response = await account.viewFunction({
        contractId: bootInfoStruct.app_id,
        methodName: 'is_app_allowed',
        args: bootInfoStruct
      });
    }

    const [isAllowed, reason] = response;
    
    // Get gateway app ID from KMS contract
    const gatewayAppId = await account.viewFunction({
      contractId: this.kmsContractId,
      methodName: 'get_gateway_app_id',
      args: {}
    });

    return {
      isAllowed,
      reason: reason || '',
      gatewayAppId: gatewayAppId || ''
    };
  }

  async getGatewayAppId(): Promise<string> {
    try {
      const account = this.ensureAccount();
      const result = await account.viewFunction({
        contractId: this.kmsContractId,
        methodName: 'get_gateway_app_id',
        args: {}
      });
      return result || '';
    } catch (error) {
      console.error('Error getting gateway app ID:', error);
      return '';
    }
  }

  async getNetworkId(): Promise<string> {
    return this.near.config.networkId;
  }

  async getAppImplementation(): Promise<string> {
    // NEAR doesn't have appImplementation like Ethereum
    // Return empty string for compatibility
    return '';
  }
}

// Initialize app
const app = new Hono();

// Initialize NEAR connection
const rpcUrl = process.env.NEAR_RPC_URL || 'https://free.rpc.fastnear.com';
const networkId = process.env.NEAR_NETWORK_ID || 'mainnet';
const kmsContractId = process.env.KMS_CONTRACT_ID || '';

if (!kmsContractId) {
  console.error('KMS_CONTRACT_ID environment variable is required');
  process.exit(1);
}

const keyStore = new keyStores.InMemoryKeyStore();
const nearConfig = {
  networkId,
  nodeUrl: rpcUrl,
  keyStore,
  headers: {}
};

// Initialize NEAR connection
let nearBackend: NearBackend | null = null;

// Initialize NEAR connection asynchronously
(async () => {
  try {
    const near = await connect(nearConfig);
    // For view calls, we can use any account ID - it doesn't need to exist or be controlled by us
    // Using the contract ID itself as the account for view calls (no private key needed)
    const account = await near.account(kmsContractId);
    nearBackend = new NearBackend(near, kmsContractId, account);
    console.log(`NEAR backend initialized: network=${networkId}, contract=${kmsContractId}`);
  } catch (error) {
    console.error('Failed to initialize NEAR connection:', error);
    // Don't exit - let the health check handle it
  }
})();

// Health check and info endpoint
app.get('/', async (c) => {
  try {
    if (!nearBackend) {
      return c.json({ 
        status: 'error', 
        message: 'NEAR backend not initialized yet' 
      }, 503);
    }

    const batch = await Promise.all([
      nearBackend.getGatewayAppId(),
      nearBackend.getNetworkId(),
      nearBackend.getAppImplementation(),
    ]);
    
    return c.json({
      status: 'ok',
      kmsContractAddr: kmsContractId,
      gatewayAppId: batch[0],
      chainId: batch[1], // Using network ID as chain identifier
      appAuthImplementation: batch[2], // NOTE: for backward compatibility
      appImplementation: batch[2],
    });
  } catch (error) {
    console.error('error in health check:', error);
    return c.json({ 
      status: 'error', 
      message: error instanceof Error ? error.message : String(error) 
    }, 500);
  }
});

// app boot authentication
app.post('/bootAuth/app', 
  zValidator('json', BootInfoSchema),
  async (c) => {
    try {
      if (!nearBackend) {
        return c.json({
          isAllowed: false,
          gatewayAppId: '',
          reason: 'NEAR backend not initialized'
        }, 503);
      }

      const bootInfo = c.req.valid('json');
      const result = await nearBackend.checkBoot(bootInfo, false);
      return c.json(result);
    } catch (error) {
      console.error('error in app boot auth:', error);
      return c.json({
        isAllowed: false,
        gatewayAppId: '',
        reason: error instanceof Error ? error.message : String(error)
      });
    }
  }
);

// KMS boot authentication
app.post('/bootAuth/kms',
  zValidator('json', BootInfoSchema),
  async (c) => {
    try {
      if (!nearBackend) {
        return c.json({
          isAllowed: false,
          gatewayAppId: '',
          reason: 'NEAR backend not initialized'
        }, 503);
      }

      const bootInfo = c.req.valid('json');
      const result = await nearBackend.checkBoot(bootInfo, true);
      return c.json(result);
    } catch (error) {
      console.error('error in KMS boot auth:', error);
      return c.json({
        isAllowed: false,
        gatewayAppId: '',
        reason: error instanceof Error ? error.message : String(error)
      });
    }
  }
);

// start server
const port = parseInt(process.env.PORT || '3000');
console.log(`starting NEAR auth server on port ${port}`);

export default {
  port,
  fetch: app.fetch,
};

