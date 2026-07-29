// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { createPublicClient, http, type Address, type Hex } from 'viem';

// zod schemas for validation - compatible with original fastify implementation
const boundedHex = (bytes: number, description: string) =>
  z.string()
    .regex(/^(?:0x)?[0-9a-fA-F]*$/, `${description} must be hexadecimal`)
    .refine(
      (value) => value.replace(/^0x/, '').length <= bytes * 2,
      `${description} exceeds ${bytes} bytes`,
    );

const BootInfoSchema = z.object({
  // Short hexadecimal values remain compatible with the original backend,
  // which left-pads them before making the contract call.
  mrAggregated: boundedHex(32, 'aggregated MR measurement'),
  osImageHash: boundedHex(32, 'OS Image hash'),
  appId: boundedHex(20, 'application ID'),
  composeHash: boundedHex(32, 'compose hash'),
  instanceId: boundedHex(20, 'instance ID'),
  deviceId: boundedHex(32, 'device ID'),
  tcbStatus: z.string().max(128).optional().default(''),
  advisoryIds: z.array(z.string().max(256)).max(128).optional().default([]),
  mrSystem: boundedHex(32, 'system MR measurement').optional().default('')
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

const publicRpcEndpoint = (value: string): string => {
  try {
    const endpoint = new URL(value);
    return `${endpoint.protocol}//${endpoint.host}`;
  } catch {
    return 'configured';
  }
};

const backendUnavailable = 'authorization backend unavailable';

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
      ethRpcUrl: publicRpcEndpoint(rpcUrl),
      gatewayAppId: batch[0],
      chainId: batch[1],
      appAuthImplementation: batch[2], // NOTE: for backward compatibility
      appImplementation: batch[2],
    });
  } catch (error) {
    console.error('authorization backend health check failed');
    return c.json({
      status: 'error',
      message: backendUnavailable
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
      console.error('application authorization backend failed');
      return c.json({
        isAllowed: false,
        gatewayAppId: '',
        reason: backendUnavailable
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
        console.error('KMS authorization backend failed');
      }
      return c.json({
        isAllowed: false,
        gatewayAppId: '',
        reason: backendUnavailable
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
