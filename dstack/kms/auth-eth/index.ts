// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { secureHeaders } from 'hono/secure-headers';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { BaseError, createPublicClient, custom, http, keccak256, toBytes, type Address, type Hex } from 'viem';

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
  teeVariant: z.string().min(1).max(64),
  operation: z.enum(['kms_bootstrap', 'kms_serve', 'kms_export_keys', 'kms_import_keys', 'app_get_key', 'app_get_cert']),
  requestedAppEpoch: z.number().int().min(0).max(0xffffffff).optional(),
  requestedRootEpoch: z.number().int().min(0).max(0xffffffff).optional(),
  // The hash of the launch ticket the attested subject presented; absent when none.
  launchTicketHash: boundedHex(32, 'launch ticket hash').optional(),
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
    { name: 'teeVariant', type: 'string' },
    { name: 'launchTicketHash', type: 'bytes32' },
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
  { name: 'sevSnpTcbRequirements', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'string' }] },
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
  },
  {
    name: 'rootEpoch',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'epoch', type: 'uint256' }],
    outputs: [
      { name: 'caPubkey', type: 'bytes' },
      { name: 'k256Pubkey', type: 'bytes' },
      { name: 'evidenceUrl', type: 'string' },
      { name: 'chainHash', type: 'bytes32' }
    ]
  }
] as const;

// ethereum backend class
const BLOCK_TAGS = ['latest', 'safe', 'finalized'] as const;
type BlockTag = typeof BLOCK_TAGS[number];

export function parseBlockTag(value: string | undefined): BlockTag {
  const tag = value || 'finalized';
  if (!(BLOCK_TAGS as readonly string[]).includes(tag)) {
    throw new Error(`ETH_BLOCK_TAG must be one of ${BLOCK_TAGS.join(', ')}`);
  }
  return tag as BlockTag;
}

export function parseRpcConfig(env: Record<string, string | undefined>) {
  const { ETH_RPC_URL: single, ETH_RPC_URLS: list } = env;
  const given = list || single;
  if (!given || (single && list)) throw new Error('set exactly one of ETH_RPC_URL and ETH_RPC_URLS');
  const urls = given.trim().split(/\s+/);

  // A single ETH_RPC_URL needs no ETH_RPC_QUORUM.
  const quorum = env.ETH_RPC_QUORUM || (list ? '' : '1/1');
  const match = /^(\d+)\/(\d+)$/.exec(quorum);
  const threshold = Number(match?.[1]);
  const total = Number(match?.[2]);
  if (!match || threshold < 1 || threshold > total) {
    throw new Error('ETH_RPC_QUORUM must be n/m with 1 <= n <= m');
  }
  // The count is pinned apart from the list, so a value interpolated into one
  // URL cannot add an endpoint.
  if (urls.length !== total) throw new Error(`ETH_RPC_QUORUM expects ${total} RPC URLs, got ${urls.length}`);

  // URLs carry API keys: never put one in an error.
  const origins = urls.map((url, i) => {
    if (!URL.canParse(url)) throw new Error(`RPC URL ${i + 1} is invalid`);
    return new URL(url).origin;
  });
  if (new Set(origins).size !== total) throw new Error('RPC URLs must have distinct origins');
  // Providers that lag or lie can hold the block back; only its age bounds that.
  if (total > 1 && !env.ETH_MAX_BLOCK_AGE) throw new Error('ETH_MAX_BLOCK_AGE is required with several RPC URLs');

  return { urls, origins, quorum, threshold };
}

// One RPC endpoint; the origin is the only part of its URL that is public.
type RpcProvider = {
  origin: string;
  request: (args: { method: string; params?: unknown }) => Promise<unknown>;
};
type RpcBlock = { hash: string; number: string; timestamp: string };

// viem puts a one-line summary without the request URL in shortMessage.
const errorSummary = (err: unknown): string =>
  (err as { shortMessage?: string }).shortMessage ?? (err instanceof Error ? err.message : String(err));

// Only a viem error has that summary; the text of any other error stays out of the log.
const logFailure = (what: string, err: unknown) => {
  const reason = (err as { shortMessage?: string }).shortMessage;
  console.error(reason ? `${what}: ${reason}` : what);
};

/// A transport that answers a request only with what `threshold` of the
/// providers answer alike. A provider that fails or reverts casts no vote.
export function quorumTransport(providers: RpcProvider[], threshold: number) {
  const failure = (i: number, err: unknown) => `${providers[i].origin}: ${errorSummary(err)}`;

  // The first answer that `threshold` votes share under `key`.
  const agree = <T>(method: string, votes: Promise<T>[], key: (answer: T) => string) => {
    const counts = new Map<string, number>();
    const failures: string[] = [];
    // A vote fulfils only if it is the one that completes a quorum.
    const quorum = votes.map(async (vote, i) => {
      try {
        const answer = await vote;
        const answerKey = key(answer).toLowerCase();
        const count = (counts.get(answerKey) ?? 0) + 1;
        counts.set(answerKey, count);
        if (count >= threshold) return answer;
      } catch (err) {
        failures.push(failure(i, err));
      }
      throw new BaseError('no quorum');
    });
    return Promise.any(quorum).catch(() => {
      const detail = failures.length ? ` (${failures.join('; ')})` : '';
      throw new BaseError(`no ${threshold} of ${votes.length} RPCs agree on ${method}${detail}`);
    });
  };

  // The highest block `threshold` of the providers have reached, since they
  // reach a tag at different times. Fewer than `threshold` providers cannot
  // push it past a block one of the others has reached, but as few as
  // m - threshold + 1 that lag or lie can hold it back: only
  // ETH_MAX_BLOCK_AGE bounds that.
  const reached = async (tag: unknown, votes: Promise<RpcBlock>[]) => {
    const settled = await Promise.allSettled(votes.map(async (vote) => {
      const tip = await vote;
      return { tip, height: BigInt(tip.number) };
    }));
    const tips = settled
      .flatMap((vote) => (vote.status === 'fulfilled' ? [vote.value] : []))
      .sort((a, b) => Number(b.height - a.height));
    if (tips.length >= threshold) return tips[threshold - 1].tip;
    const failures = settled.flatMap((vote, i) => (vote.status === 'rejected' ? [failure(i, vote.reason)] : []));
    throw new BaseError(`fewer than ${threshold} RPCs serve block ${tag} (${failures.join('; ')})`);
  };

  return custom({
    async request({ method, params }: { method: string; params?: unknown[] }) {
      if (!['eth_chainId', 'eth_call', 'eth_getBlockByNumber'].includes(method)) {
        throw new BaseError(`RPC method ${method} is not supported`);
      }
      const votes = providers.map((provider) => provider.request({ method, params }));
      if (method !== 'eth_getBlockByNumber') return agree(method, votes as Promise<string>[], (result) => result);
      const blocks = votes as Promise<RpcBlock>[];
      const block = params?.[0];
      if (!String(block).startsWith('0x')) return reached(block, blocks);
      return agree(method, blocks, ({ hash, number, timestamp }) => `${hash}:${number}:${timestamp}`);
    },
  }, { retryCount: 0 });
}

// The block every read of a request is pinned to.
type Snapshot = { number: bigint; at: { blockHash: Hex; requireCanonical: true } };

export class EthereumBackend {
  private client: ReturnType<typeof createPublicClient>;
  private kmsContractAddr: Address;
  private expectedChainId?: number;
  readonly blockTag: BlockTag;
  readonly finalityConfirmations: bigint;
  readonly maxBlockAge?: number;

  constructor(
    client: ReturnType<typeof createPublicClient>,
    kmsContractAddr: string,
    expectedChainId: number | undefined,
    blockTag: BlockTag,
    finalityConfirmations: bigint,
    maxBlockAge?: number,
  ) {
    this.client = client;
    this.kmsContractAddr = kmsContractAddr as Address;
    this.expectedChainId = expectedChainId;
    this.blockTag = blockTag;
    this.finalityConfirmations = finalityConfirmations;
    this.maxBlockAge = maxBlockAge;
  }

  /// Resolve the tag, less the confirmation depth, to one block so that every
  /// read of a request sees the same state. Reads are pinned to its hash, so
  /// they fail rather than follow a reorg. An RPC that does not support the
  /// tag fails closed.
  async resolveBlock(tag: BlockTag = this.blockTag, confirmations = this.finalityConfirmations): Promise<Snapshot> {
    const chainId = await this.client.getChainId();
    if (this.expectedChainId !== undefined && chainId !== this.expectedChainId) {
      throw new BaseError('authorization backend chain ID mismatch');
    }
    const tip = await this.client.getBlock({ blockTag: tag });
    if (tip.number === null || tip.number < confirmations) {
      throw new BaseError('authorization backend has not reached configured finality');
    }
    const { hash, number, timestamp } = await this.client.getBlock({ blockNumber: tip.number - confirmations });
    if (hash === null || number === null) throw new BaseError('authorization backend block is pending');
    if (this.maxBlockAge !== undefined && Date.now() / 1000 - Number(timestamp) > this.maxBlockAge) {
      throw new BaseError('authorization backend block is older than ETH_MAX_BLOCK_AGE');
    }
    return { number, at: { blockHash: hash, requireCanonical: true } };
  }

  /// Resolve the tag once at startup, so an RPC that cannot serve it fails the
  /// deployment instead of every later request.
  async probeBlockTag(): Promise<void> {
    try {
      await this.resolveBlock();
    } catch (err) {
      const hint = this.blockTag === 'latest' ? '' : '; an RPC that cannot serve the tag, as OP-stack via Helios, requires latest';
      throw new Error(`cannot resolve ETH_BLOCK_TAG=${this.blockTag} (${errorSummary(err)})${hint}`);
    }
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
    const block = await this.resolveBlock();
    const result = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: method,
      args: [{
        appInfo: this.contractAppInfo(appInfo),
        operation: keccak256(toBytes(appInfo.operation)),
        requestedAppEpoch: { isSet: appInfo.requestedAppEpoch !== undefined, value: BigInt(appInfo.requestedAppEpoch ?? 0) },
        requestedRootEpoch: { isSet: appInfo.requestedRootEpoch !== undefined, value: BigInt(appInfo.requestedRootEpoch ?? 0) },
        teeVariant: appInfo.teeVariant,
        launchTicketHash: this.decodeHex(appInfo.launchTicketHash ?? '', 32),
      }],
      ...block.at,
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
    const block = await this.resolveBlock();
    let response;
    if (isKms) {
      response = await this.client.readContract({
        address: this.kmsContractAddr,
        abi: DSTACK_KMS_ABI,
        functionName: 'isKmsAllowed',
        args: [bootInfoStruct],
        ...block.at
      });
    } else {
      response = await this.client.readContract({
        address: this.kmsContractAddr,
        abi: DSTACK_KMS_ABI,
        functionName: 'isAppAllowed',
        args: [bootInfoStruct],
        ...block.at
      });
    }

    const [allowed, contractReason] = response;
    const gatewayAppId = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'gatewayAppId',
      ...block.at
    });

    const epochDenial = allowed
      ? rootEpochDenial(bootInfo, await this.getRootEpoch(block))
      : undefined;
    return {
      isAllowed: allowed && !epochDenial,
      reason: epochDenial ?? contractReason,
      gatewayAppId: gatewayAppId as string,
    };
  }

  // The current root epoch and its chain hash; empty only when no epoch is registered.
  async getRootEpoch(block?: Snapshot): Promise<RootEpochInfo> {
    block ??= await this.resolveBlock();
    const count = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'rootEpochCount',
      ...block.at
    });
    if (count === 0n) return {};
    const [epoch, chainHash] = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'currentRootEpoch',
      ...block.at
    });
    return { rootEpoch: Number(epoch), rootEpochHash: chainHash };
  }

  // The root CA public key (P-256 SPKI DER) of the current root epoch, which
  // signs the RPC certificate of every KMS serving it.
  async getRootCaPubkey(block: Snapshot, current: RootEpochInfo): Promise<Hex | undefined> {
    if (current.rootEpoch === undefined) return undefined;
    const [caPubkey] = await this.client.readContract({
      address: this.kmsContractAddr, abi: DSTACK_KMS_ABI, functionName: 'rootEpoch',
      args: [BigInt(current.rootEpoch)], ...block.at,
    });
    return caPubkey;
  }

  async getAppEpoch(appId: string): Promise<number> {
    const epoch = Number(await this.client.readContract({
      address: this.kmsContractAddr, abi: DSTACK_KMS_ABI, functionName: 'currentAppEpoch',
      args: [this.decodeHex(appId, 20)], ...(await this.resolveBlock('latest', 0n)).at,
    }));
    if (!Number.isSafeInteger(epoch)) throw new Error('app epoch exceeds the supported range');
    return epoch;
  }

  async getSevSnpTcbRequirements(): Promise<string> {
    return await this.client.readContract({
      address: this.kmsContractAddr, abi: DSTACK_KMS_ABI, functionName: 'sevSnpTcbRequirements',
      ...(await this.resolveBlock()).at,
    });
  }

  async getGatewayAppId(block?: Snapshot): Promise<string> {
    const result = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'gatewayAppId',
      ...(block ?? await this.resolveBlock()).at,
    });
    return result as string;
  }

  async getChainId(): Promise<number> {
    const chainId = await this.client.getChainId();
    return Number(chainId);
  }

  async getAppImplementation(block?: Snapshot): Promise<string> {
    const result = await this.client.readContract({
      address: this.kmsContractAddr,
      abi: DSTACK_KMS_ABI,
      functionName: 'appImplementation',
      ...(block ?? await this.resolveBlock()).at,
    });
    return result as string;
  }
}

// initialize app
const app = new Hono();

// initialize ethereum backend
const rpc = parseRpcConfig(process.env);
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
  transport: quorumTransport(rpc.urls.map((url, i) => ({
    origin: rpc.origins[i],
    // A redirect would take the request off the configured origin. With
    // several providers the others stand in for a retry, which would only
    // hold the decision up behind a dead one.
    request: http(url, {
      fetchOptions: { redirect: 'error' },
      retryCount: rpc.urls.length > 1 ? 0 : undefined,
    })({}).request,
  })), rpc.threshold),
});
const ethereum = new EthereumBackend(
  client, kmsContractAddr, expectedChainId, parseBlockTag(process.env.ETH_BLOCK_TAG), finalityConfirmations,
  parseNonNegativeInteger('ETH_MAX_BLOCK_AGE', process.env.ETH_MAX_BLOCK_AGE),
);
const ethRpcUrl = rpc.origins.join(',');

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
    const block = await ethereum.resolveBlock();
    const batch = await Promise.all([
      ethereum.getGatewayAppId(block),
      ethereum.getChainId(),
      ethereum.getAppImplementation(block),
      ethereum.getRootEpoch(block),
    ]);
    const rootCaPubkey = await ethereum.getRootCaPubkey(block, batch[3]);

    return c.json({
      status: 'ok',
      kmsContractAddr: kmsContractAddr,
      ethRpcUrl,
      gatewayAppId: batch[0],
      chainId: batch[1],
      appAuthImplementation: batch[2], // NOTE: for backward compatibility
      appImplementation: batch[2],
      // Forwarded verbatim by the KMS's unauthenticated GetMeta: public only.
      authApiInfo: JSON.stringify({
        kmsContractAddr,
        chainId: batch[1],
        appImplementation: batch[2],
        ethRpcUrl,
        ethRpcUrls: rpc.origins,
        rpcQuorum: rpc.quorum,
        blockTag: ethereum.blockTag,
        finalityConfirmations: Number(ethereum.finalityConfirmations),
        maxBlockAge: ethereum.maxBlockAge,
        policyBlockNumber: Number(block.number),
      }),
      ...batch[3],
      ...(rootCaPubkey && { rootCaPubkey }),
    });
  } catch (err) {
    logFailure('authorization backend health check failed', err);
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

// The JSON list the KMS judges an SEV-SNP TCB against; empty when governance
// sets none. A contract that predates the list fails the read, and the KMS
// refuses SEV-SNP requests.
app.get('/sevSnpTcbRequirements', async (c) => {
  try {
    return c.json({ requirements: await ethereum.getSevSnpTcbRequirements() });
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
      } catch (err) {
        logFailure('authorization backend failed', err);
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
    } catch (err) {
      logFailure('application authorization backend failed', err);
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
        logFailure('KMS authorization backend failed', error);
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
if (import.meta.main) await ethereum.probeBlockTag();
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
