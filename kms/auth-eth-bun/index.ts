// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { createPublicClient, http, type Address, type Hex } from 'viem';

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

// DstackKms contract ABI (minimal required functions)
const DSTACK_KMS_ABI = [
  {
    name: 'isKmsAllowed',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      {
        name: 'bootInfo',
        type: 'tuple',
        components: [
          { name: 'appId', type: 'address' },
          { name: 'composeHash', type: 'bytes32' },
          { name: 'instanceId', type: 'address' },
          { name: 'deviceId', type: 'bytes32' },
          { name: 'mrAggregated', type: 'bytes32' },
          { name: 'mrSystem', type: 'bytes32' },
          { name: 'osImageHash', type: 'bytes32' },
          { name: 'tcbStatus', type: 'string' },
          { name: 'advisoryIds', type: 'string[]' }
        ]
      }
    ],
    outputs: [
      { name: 'isAllowed', type: 'bool' },
      { name: 'reason', type: 'string' }
    ]
  },
  {
    name: 'isAppAllowed',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      {
        name: 'bootInfo',
        type: 'tuple',
        components: [
          { name: 'appId', type: 'address' },
          { name: 'composeHash', type: 'bytes32' },
          { name: 'instanceId', type: 'address' },
          { name: 'deviceId', type: 'bytes32' },
          { name: 'mrAggregated', type: 'bytes32' },
          { name: 'mrSystem', type: 'bytes32' },
          { name: 'osImageHash', type: 'bytes32' },
          { name: 'tcbStatus', type: 'string' },
          { name: 'advisoryIds', type: 'string[]' }
        ]
      }
    ],
    outputs: [
      { name: 'isAllowed', type: 'bool' },
      { name: 'reason', type: 'string' }
    ]
  },
  {
    name: 'gatewayAppId',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'string' }]
  },
  {
    name: 'appImplementation',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }]
  }
] as const;

// ethereum backend class
class EthereumBackend {
  private client: ReturnType<typeof createPublicClient>;
  private kmsContractAddr: Address;

  constructor(client: ReturnType<typeof createPublicClient>, kmsContractAddr: string) {
    this.client = client;
    this.kmsContractAddr = kmsContractAddr as Address;
  }

  private decodeHex(hex: string, sz: number = 32): Hex {
    // remove '0x' prefix if present
    hex = hex.startsWith('0x') ? hex.slice(2) : hex;
    // pad hex string to specified size
    hex = hex.padStart(sz * 2, '0');
    // add '0x' prefix back
    return `0x${hex}` as Hex;
  }

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    // create boot info struct for contract call
    const bootInfoStruct = {
      appId: this.decodeHex(bootInfo.appId, 20) as Address,
      composeHash: this.decodeHex(bootInfo.composeHash, 32),
      instanceId: this.decodeHex(bootInfo.instanceId, 20) as Address,
      deviceId: this.decodeHex(bootInfo.deviceId, 32),
      mrAggregated: this.decodeHex(bootInfo.mrAggregated, 32),
      mrSystem: this.decodeHex(bootInfo.mrSystem || '', 32),
      osImageHash: this.decodeHex(bootInfo.osImageHash, 32),
      tcbStatus: bootInfo.tcbStatus || '',
      advisoryIds: bootInfo.advisoryIds || []
    };

    let response;
    if (isKms) {
      response = await this.client.readContract({
        address: this.kmsContractAddr,
        abi: DSTACK_KMS_ABI,
        functionName: 'isKmsAllowed',
        args: [bootInfoStruct]
      });
    } else {
      response = await this.client.readContract({
        address: this.kmsContractAddr,
        abi: DSTACK_KMS_ABI,
        functionName: 'isAppAllowed',
        args: [bootInfoStruct]
      });
    }
    
    const [isAllowed, reason] = response;
    const gatewayAppId = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'gatewayAppId'
    });
    
    return {
      isAllowed,
      reason,
      gatewayAppId: gatewayAppId as string,
    };
  }

  async getGatewayAppId(): Promise<string> {
    const result = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'gatewayAppId'
    });
    return result as string;
  }

  async getChainId(): Promise<number> {
    const chainId = await this.client.getChainId();
    return Number(chainId);
  }

  async getAppImplementation(): Promise<string> {
    const result = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'appImplementation'
    });
    return result as string;
  }
}

// initialize app
const app = new Hono();

// initialize ethereum backend
const rpcUrl = process.env.ETH_RPC_URL || 'http://localhost:8545';
const kmsContractAddr = process.env.KMS_CONTRACT_ADDR || '0x0000000000000000000000000000000000000000';
const client = createPublicClient({
  transport: http(rpcUrl)
});
const ethereum = new EthereumBackend(client, kmsContractAddr);

// health check and info endpoint
app.get('/', async (c) => {
  try {
    const batch = await Promise.all([
      ethereum.getGatewayAppId(),
      ethereum.getChainId(),
      ethereum.getAppImplementation(),
    ]);
    console.log('batch', batch);
    
    return c.json({
      status: 'ok',
      kmsContractAddr: kmsContractAddr,
      gatewayAppId: batch[0],
      chainId: batch[1],
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
      const bootInfo = c.req.valid('json');
      const result = await ethereum.checkBoot(bootInfo, false);
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
      const bootInfo = c.req.valid('json');
      const result = await ethereum.checkBoot(bootInfo, true);
      return c.json(result);
    } catch (error) {
      // don't log test backend errors
      if (!(error instanceof Error && "Test backend error" === error.message)) {
        console.error('error in KMS boot auth:', error);
      }
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
console.log(`starting server on port ${port}`);

export default {
  port,
  fetch: app.fetch,
}; 