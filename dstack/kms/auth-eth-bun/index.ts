// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { secureHeaders } from 'hono/secure-headers';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { createPublicClient, http, keccak256, toBytes, type Address, type Hex } from 'viem';

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
  mrSystem: boundedHex(32, 'system MR measurement').optional().default(''),
  // The root epoch the asking KMS serves and its chain hash; absent from a KMS
  // that predates root epochs, and from KMS checks made while onboarding.
  rootEpoch: z.number().int().min(0).optional(),
  rootEpochHash: boundedHex(32, 'root epoch chain hash').optional()
});

const AuthorizationRequestSchema = BootInfoSchema.omit({ rootEpoch: true, rootEpochHash: true }).extend({
  operation: z.enum(['kms_bootstrap', 'kms_serve', 'kms_export_keys', 'kms_import_keys', 'app_get_key', 'app_get_cert']),
  requestedAppEpoch: z.number().int().min(0).max(0xffffffff).optional(),
  requestedRootEpoch: z.number().int().min(0).max(0xffffffff).optional(),
});
type AuthorizationRequest = z.infer<typeof AuthorizationRequestSchema>;

const BootResponseSchema = z.object({
  isAllowed: z.boolean(),
  reason: z.string(),
  gatewayAppId: z.string()
});

// The current root epoch and its chain hash, which commits to the root public
// keys of epochs 0..=rootEpoch; both absent when none is registered.
type RootEpochInfo = { rootEpoch?: number; rootEpochHash?: Hex };

type BootInfo = z.infer<typeof BootInfoSchema>;
type BootResponse = z.infer<typeof BootResponseSchema>;

const normHash = (hash?: string) => hash?.toLowerCase().replace(/^0x/, '');

// Only a KMS serving the current root epoch, with the registered keys up to it,
// may authorize. A KMS that predates root epochs reports none and holds only
// epoch 0, so it is served only until another epoch is activated.
function rootEpochDenial(bootInfo: BootInfo, current: RootEpochInfo): string | undefined {
  const currentEpoch = current.rootEpoch ?? 0;
  if (bootInfo.rootEpoch === undefined) {
    return currentEpoch === 0 ? undefined : `root epoch ${currentEpoch} is current, but the KMS reports none`;
  }
  if (current.rootEpoch === undefined) {
    return bootInfo.rootEpoch === 0 ? undefined : `root epoch ${bootInfo.rootEpoch} is not registered`;
  }
  if (bootInfo.rootEpoch !== currentEpoch) {
    return `the KMS serves root epoch ${bootInfo.rootEpoch}, but ${currentEpoch} is current`;
  }
  if (normHash(bootInfo.rootEpochHash) !== normHash(current.rootEpochHash)) {
    return `the KMS root keys up to epoch ${currentEpoch} are not the registered ones`;
  }
  return undefined;
}

const APP_INFO_COMPONENTS = [
  { name: 'appId', type: 'address' },
  { name: 'composeHash', type: 'bytes32' },
  { name: 'instanceId', type: 'address' },
  { name: 'deviceId', type: 'bytes32' },
  { name: 'mrAggregated', type: 'bytes32' },
  { name: 'mrSystem', type: 'bytes32' },
  { name: 'osImageHash', type: 'bytes32' },
  { name: 'tcbStatus', type: 'string' },
  { name: 'advisoryIds', type: 'string[]' }
] as const;

const AUTHORIZATION_ABI = {
  type: 'function',
  stateMutability: 'view',
  inputs: [{ name: 'request', type: 'tuple', components: [
    { name: 'appInfo', type: 'tuple', components: APP_INFO_COMPONENTS },
    { name: 'operation', type: 'bytes32' },
    { name: 'requestedAppEpoch', type: 'tuple', components: [
      { name: 'isSet', type: 'bool' }, { name: 'value', type: 'uint256' },
    ] },
    { name: 'requestedRootEpoch', type: 'tuple', components: [
      { name: 'isSet', type: 'bool' }, { name: 'value', type: 'uint256' },
    ] },
  ] }],
  outputs: [{
    name: 'result',
    type: 'tuple',
    components: [
      { name: 'authorized', type: 'bool' },
      { name: 'rejectionReason', type: 'string' },
      { name: 'gatewayAppId', type: 'string' },
      { name: 'currentRootEpoch', type: 'uint256' },
      { name: 'currentRootEpochHash', type: 'bytes32' },
      { name: 'currentAppEpoch', type: 'uint256' },
      { name: 'latestRootEpoch', type: 'uint256' },
      { name: 'latestRootEpochHash', type: 'bytes32' },
    ],
  }],
} as const;

// DstackKms contract ABI (minimal required functions)
const DSTACK_KMS_ABI = [
  { name: 'currentAppEpoch', type: 'function', stateMutability: 'view', inputs: [{ name: 'appId', type: 'address' }], outputs: [{ name: '', type: 'uint256' }] },
  { ...AUTHORIZATION_ABI, name: 'authorizeKms' },
  { ...AUTHORIZATION_ABI, name: 'authorizeApp' },
  {
    name: 'isKmsAllowed',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      {
        name: 'bootInfo',
        type: 'tuple',
        components: APP_INFO_COMPONENTS
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
        components: APP_INFO_COMPONENTS
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
  },
  {
    name: 'rootEpochCount',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }]
  },
  {
    name: 'currentRootEpoch',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [
      { name: 'epoch', type: 'uint256' },
      { name: 'chainHash', type: 'bytes32' }
    ]
  }
] as const;

// ethereum backend class
class EthereumBackend {
  private client: ReturnType<typeof createPublicClient>;
  private kmsContractAddr: Address;
  private expectedChainId?: number;
  private finalityConfirmations: bigint;

  constructor(
    client: ReturnType<typeof createPublicClient>,
    kmsContractAddr: string,
    expectedChainId: number | undefined,
    finalityConfirmations: bigint,
  ) {
    this.client = client;
    this.kmsContractAddr = kmsContractAddr as Address;
    this.expectedChainId = expectedChainId;
    this.finalityConfirmations = finalityConfirmations;
  }

  private async finalizedBlockNumber(): Promise<bigint> {
    const chainId = await this.client.getChainId();
    if (this.expectedChainId !== undefined && chainId !== this.expectedChainId) {
      throw new Error('authorization backend chain ID mismatch');
    }
    const head = await this.client.getBlockNumber();
    if (head < this.finalityConfirmations) {
      throw new Error('authorization backend has not reached configured finality');
    }
    return head - this.finalityConfirmations;
  }

  private decodeHex(hex: string, sz: number = 32): Hex {
    // remove '0x' prefix if present
    hex = hex.startsWith('0x') ? hex.slice(2) : hex;
    // pad hex string to specified size
    hex = hex.padStart(sz * 2, '0');
    // add '0x' prefix back
    return `0x${hex}` as Hex;
  }

  private contractAppInfo(bootInfo: BootInfo) {
    // create boot info struct for contract call
    return {
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

  }

  async checkAuthorization(appInfo: AuthorizationRequest, method: 'authorizeKms' | 'authorizeApp') {
    const blockNumber = await this.finalizedBlockNumber();
    const result = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: method,
      args: [{
        appInfo: this.contractAppInfo(appInfo),
        operation: keccak256(toBytes(appInfo.operation)),
        requestedAppEpoch: { isSet: appInfo.requestedAppEpoch !== undefined, value: BigInt(appInfo.requestedAppEpoch ?? 0) },
        requestedRootEpoch: { isSet: appInfo.requestedRootEpoch !== undefined, value: BigInt(appInfo.requestedRootEpoch ?? 0) },
      }],
      blockNumber,
    });
    const currentRootEpoch = Number(result.currentRootEpoch);
    if (!Number.isSafeInteger(currentRootEpoch)) {
      throw new Error('current root epoch exceeds the supported range');
    }
    const currentAppEpoch = Number(result.currentAppEpoch);
    if (!Number.isSafeInteger(currentAppEpoch)) throw new Error('current app epoch exceeds the supported range');
    const latestRootEpoch = Number(result.latestRootEpoch);
    if (!Number.isSafeInteger(latestRootEpoch)) throw new Error('latest root epoch exceeds the supported range');
    return { ...result, currentRootEpoch, currentAppEpoch, latestRootEpoch };
  }

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    const bootInfoStruct = this.contractAppInfo(bootInfo);
    const blockNumber = await this.finalizedBlockNumber();
    let response;
    if (isKms) {
      response = await this.client.readContract({
        address: this.kmsContractAddr,
        abi: DSTACK_KMS_ABI,
        functionName: 'isKmsAllowed',
        args: [bootInfoStruct],
        blockNumber
      });
    } else {
      response = await this.client.readContract({
        address: this.kmsContractAddr,
        abi: DSTACK_KMS_ABI,
        functionName: 'isAppAllowed',
        args: [bootInfoStruct],
        blockNumber
      });
    }

    const [allowed, contractReason] = response;
    const gatewayAppId = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'gatewayAppId',
      blockNumber
    });

    const epochDenial = allowed
      ? rootEpochDenial(bootInfo, await this.getRootEpoch(blockNumber))
      : undefined;
    return {
      isAllowed: allowed && !epochDenial,
      reason: epochDenial ?? contractReason,
      gatewayAppId: gatewayAppId as string,
    };
  }

  // The current root epoch and its chain hash; empty only when no epoch is registered.
  async getRootEpoch(blockNumber?: bigint): Promise<RootEpochInfo> {
    blockNumber ??= await this.finalizedBlockNumber();
    const count = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'rootEpochCount',
      blockNumber
    });
    if (count === 0n) return {};
    const [epoch, chainHash] = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'currentRootEpoch',
      blockNumber
    });
    return { rootEpoch: Number(epoch), rootEpochHash: chainHash };
  }

  async getAppEpoch(appId: string): Promise<number> {
    const epoch = Number(await this.client.readContract({
      address: this.kmsContractAddr, abi: DSTACK_KMS_ABI, functionName: 'currentAppEpoch',
      args: [this.decodeHex(appId, 20)], blockNumber: await this.finalizedBlockNumber(),
    }));
    if (!Number.isSafeInteger(epoch)) throw new Error('app epoch exceeds the supported range');
    return epoch;
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
const parseNonNegativeInteger = (name: string, value: string | undefined): number | undefined => {
  if (value === undefined || value === '') return undefined;
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) throw new Error(`${name} must be a non-negative integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${name} exceeds the safe integer range`);
  return parsed;
};
const expectedChainId = parseNonNegativeInteger('ETH_CHAIN_ID', process.env.ETH_CHAIN_ID);
const finalityConfirmations = BigInt(
  parseNonNegativeInteger('ETH_FINALITY_CONFIRMATIONS', process.env.ETH_FINALITY_CONFIRMATIONS) ?? 0,
);
const client = createPublicClient({
  transport: http(rpcUrl)
});
const ethereum = new EthereumBackend(client, kmsContractAddr, expectedChainId, finalityConfirmations);

const publicRpcEndpoint = (value: string): string => {
  try {
    const endpoint = new URL(value);
    return `${endpoint.protocol}//${endpoint.host}`;
  } catch {
    return 'configured';
  }
};

const backendUnavailable = 'authorization backend unavailable';
const invalidRequest = { isAllowed: false, reason: 'invalid authorization request', gatewayAppId: '' };
const invalidAuthorization = {
  authorized: false,
  rejectionReason: 'invalid authorization request',
  gatewayAppId: '',
  currentRootEpoch: 0,
  currentRootEpochHash: '0x' + '00'.repeat(32),
  currentAppEpoch: 0,
  latestRootEpoch: 0,
  latestRootEpochHash: '0x' + '00'.repeat(32),
};

// The schema caps a valid BootInfo well under this (advisoryIds alone at
// 128 x 256 chars is 32 KiB); the limit stops an oversized body from being
// buffered and parsed before validation rejects it.
const MAX_BOOT_INFO_BYTES = 128 * 1024;

// Every response is JSON for the KMS, never a page; the headers keep a browser
// that reaches this port from sniffing or framing one.
app.use('*', secureHeaders());
app.use('/bootAuth/*', bodyLimit({
  maxSize: MAX_BOOT_INFO_BYTES,
  onError: (c) => c.json(invalidRequest, 413),
}));

// health check and info endpoint
app.get('/', async (c) => {
  try {
    const batch = await Promise.all([
      ethereum.getGatewayAppId(),
      ethereum.getChainId(),
      ethereum.getAppImplementation(),
      ethereum.getRootEpoch(),
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
      ...batch[3],
    });
  } catch {
    console.error('authorization backend health check failed');
    return c.json({
      status: 'error',
      message: backendUnavailable
    }, 500);
  }
});

app.get('/app/:appId', async (c) => {
  const appId = c.req.param('appId');
  if (!/^0x[0-9a-fA-F]{40}$/.test(appId)) return c.json({ error: 'invalid app ID' }, 400);
  try {
    return c.json({ currentAppEpoch: await ethereum.getAppEpoch(appId) });
  } catch {
    return c.json({ error: 'authorization backend unavailable' }, 503);
  }
});

// Malformed JSON is rejected before the validator hook runs; keep the
// AuthorizationResult shape for it on the authorization routes.
const AUTHORIZATION_PATHS = new Set(['/authorizeKms', '/authorizeApp']);
app.onError((error, c) => {
  if (error instanceof HTTPException) {
    if (error.status === 400 && AUTHORIZATION_PATHS.has(c.req.path)) return c.json(invalidAuthorization, 400);
    return error.getResponse();
  }
  console.error(error);
  return c.text('Internal Server Error', 500);
});

for (const method of ['authorizeKms', 'authorizeApp'] as const) {
  app.post(`/${method}`,
    bodyLimit({ maxSize: MAX_BOOT_INFO_BYTES, onError: (c) => c.json(invalidAuthorization, 413) }),
    zValidator('json', AuthorizationRequestSchema, (result, c) => {
      if (!result.success) return c.json(invalidAuthorization, 400);
    }),
    async (c) => {
      try {
        return c.json(await ethereum.checkAuthorization(c.req.valid('json'), method));
      } catch {
        console.error('authorization backend failed');
        return c.json({ status: 'error', message: backendUnavailable }, 503);
      }
    }
  );
}

// app boot authentication
app.post('/bootAuth/app',
  zValidator('json', BootInfoSchema, (result, c) => {
    if (!result.success) return c.json(invalidRequest, 400);
  }),
  async (c) => {
    try {
      const bootInfo = c.req.valid('json');
      const result = await ethereum.checkBoot(bootInfo, false);
      return c.json(result);
    } catch {
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
  zValidator('json', BootInfoSchema, (result, c) => {
    if (!result.success) return c.json(invalidRequest, 400);
  }),
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

// Bun defaults idleTimeout to 10s and closes the socket while the handler is
// still awaiting eth_call. KMS's webhook timeout is 60s; stay above that so the
// client times out first. Bun's documented maximum is 255.
export default {
  port,
  idleTimeout: 255,
  fetch: app.fetch,
};
