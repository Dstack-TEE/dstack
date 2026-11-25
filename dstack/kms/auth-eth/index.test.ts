// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import openApiSpec from './openapi.json';
import { keccak256, toBytes } from 'viem';

// Mock viem
const mockReadContract = vi.fn();
const mockGetChainId = vi.fn();
const mockGetBlock = vi.fn();

vi.mock('viem', async (importOriginal) => ({
  ...await importOriginal<typeof import('viem')>(),
  createPublicClient: vi.fn(() => ({
    readContract: mockReadContract,
    getChainId: mockGetChainId,
    getBlock: mockGetBlock,
  })),
  http: vi.fn(() => () => ({ request: vi.fn() })),
  getContract: vi.fn(),
}));

// A chain whose tagged block is `tip` and whose block n has hash blockHash(n).
const blockHash = (n: bigint) => `0x${n.toString(16).padStart(64, '0')}`;
const chainAt = (tip: bigint, timestamp = 0n) => ({ blockTag, blockNumber }: { blockTag?: string; blockNumber?: bigint }) =>
  blockTag ? { number: tip } : { number: blockNumber, hash: blockHash(blockNumber!), timestamp };

// Dynamic import after mocking
let appFetch: any;

beforeAll(async () => {
  // Set environment variables for testing
  process.env.ETH_RPC_URL = 'http://localhost:8545';
  process.env.KMS_CONTRACT_ADDR = '0x1234567890123456789012345678901234567890';
  process.env.PORT = '3001';
  process.env.ETH_CHAIN_ID = '1337';
  process.env.ETH_FINALITY_CONFIRMATIONS = '2';

  // Import the app after mocking
  const indexModule = await import('./index.ts');
  appFetch = indexModule.default.fetch;
});

beforeEach(() => {
  // Reset mocks before each test
  vi.clearAllMocks();
  mockGetChainId.mockResolvedValue(1337);
  mockGetBlock.mockImplementation(chainAt(100n));
});

describe('server runtime config', () => {
  it('keeps Bun idleTimeout above the KMS webhook timeout', async () => {
    // Vitest calls `fetch` directly and never hits Bun.serve, so this pins the
    // config that production actually loads. Bun's default of 10s closes the
    // socket while GET / is still awaiting eth_call.
    const indexModule = await import('./index.ts');
    expect(indexModule.default.idleTimeout).toBeGreaterThanOrEqual(60);
  });
});

describe('API Compatibility Tests', () => {
  describe('GET /', () => {
    it('should return system info matching OpenAPI spec', async () => {
      // Mock contract calls
      mockReadContract.mockImplementation((params) => {
        if (params.functionName === 'rootEpochCount') return 0n;
        if (params.functionName === 'gatewayAppId') {
          return '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd';
        }
        if (params.functionName === 'appImplementation') {
          return '0x9876543210987654321098765432109876543210';
        }
      });
      mockGetChainId.mockResolvedValue(1337);

      const response = await appFetch(new Request('http://localhost:3001/'));
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data).toMatchObject({
        status: 'ok',
        kmsContractAddr: '0x1234567890123456789012345678901234567890',
        ethRpcUrl: 'http://localhost:8545',
        gatewayAppId: expect.any(String),
        chainId: expect.any(Number),
        appAuthImplementation: expect.any(String),
        appImplementation: expect.any(String),
      });

      // Verify response structure matches OpenAPI spec
      const systemInfoSchema = openApiSpec.components.schemas.SystemInfo;
      const requiredFields = systemInfoSchema.required;

      requiredFields.forEach(field => {
        expect(data).toHaveProperty(field);
      });
    });

    it('should report public chain info in authApiInfo', async () => {
      mockReadContract.mockImplementation((params) => {
        if (params.functionName === 'rootEpochCount') return 0n;
        if (params.functionName === 'gatewayAppId') {
          return '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd';
        }
        if (params.functionName === 'appImplementation') {
          return '0x9876543210987654321098765432109876543210';
        }
      });

      mockGetChainId.mockResolvedValue(1337);

      const response = await appFetch(new Request('http://localhost:3001/'));
      const data = await response.json();

      expect(response.status).toBe(200);
      // ETH_BLOCK_TAG is unset (default 'finalized'),
      // ETH_FINALITY_CONFIRMATIONS=2 and the tag resolves to block 100.
      expect(JSON.parse(data.authApiInfo)).toEqual({
        kmsContractAddr: '0x1234567890123456789012345678901234567890',
        chainId: 1337,
        appImplementation: '0x9876543210987654321098765432109876543210',
        ethRpcUrl: 'http://localhost:8545',
        ethRpcUrls: ['http://localhost:8545'],
        rpcQuorum: '1/1',
        blockTag: 'finalized',
        finalityConfirmations: 2,
        policyBlockNumber: 98,
      });
    });

    it('should handle errors gracefully', async () => {
      // Mock contract calls to throw error
      mockReadContract.mockRejectedValue(new Error('contract error'));
      mockGetChainId.mockRejectedValue(new Error('network error'));

      const response = await appFetch(new Request('http://localhost:3001/'));
      const data = await response.json();

      expect(response.status).toBe(500);
      expect(data).toMatchObject({
        status: 'error',
        message: 'authorization backend unavailable',
      });
    });
  });

  describe('POST /bootAuth/app', () => {
    const validBootInfo = {
      mrAggregated: '0x1234567890123456789012345678901234567890123456789012345678901234',
      osImageHash: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      appId: '0x1111111111111111111111111111111111111111',
      composeHash: '0x2222222222222222222222222222222222222222222222222222222222222222',
      instanceId: '0x3333333333333333333333333333333333333333',
      deviceId: '0x4444444444444444444444444444444444444444444444444444444444444444',
    };

    it('should validate app boot with required fields only', async () => {
      // Mock successful contract response
      mockReadContract.mockImplementation((params) => {
        if (params.functionName === 'rootEpochCount') return 0n;
        if (params.functionName === 'isAppAllowed') {
          return [true, 'success'];
        }
        if (params.functionName === 'gatewayAppId') {
          return '0xgateway123456789012345678901234567890';
        }
      });

      const response = await appFetch(new Request('http://localhost:3001/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data).toMatchObject({
        isAllowed: true,
        reason: 'success',
        gatewayAppId: expect.any(String),
      });

      // Verify response matches OpenAPI spec
      const bootResponseSchema = openApiSpec.components.schemas.BootResponse;
      const requiredFields = bootResponseSchema.required;

      requiredFields.forEach(field => {
        expect(data).toHaveProperty(field);
      });
    });

    it('should handle full BootInfo with optional fields', async () => {
      const fullBootInfo = {
        ...validBootInfo,
        tcbStatus: 'OK',
        advisoryIds: ['INTEL-SA-00123'],
        mrSystem: '0x5555555555555555555555555555555555555555555555555555555555555555',
      };

      mockReadContract.mockImplementation((params) => {
        if (params.functionName === 'rootEpochCount') return 0n;
        if (params.functionName === 'isAppAllowed') {
          return [true, 'success with full info'];
        }
        if (params.functionName === 'gatewayAppId') {
          return '0xgateway123456789012345678901234567890';
        }
      });

      const response = await appFetch(new Request('http://localhost:3001/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(fullBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.isAllowed).toBe(true);
      expect(data.reason).toBe('success with full info');
    });

    it('should handle contract errors', async () => {
      mockReadContract.mockRejectedValue(new Error('contract call failed'));

      const response = await appFetch(new Request('http://localhost:3001/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data).toMatchObject({
        isAllowed: false,
        gatewayAppId: '',
        reason: 'authorization backend unavailable',
      });
    });

    it('should reject invalid request body', async () => {
      const invalidBootInfo = {
        mrAggregated: '0x1234', // missing required fields
      };

      const response = await appFetch(new Request('http://localhost:3001/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(invalidBootInfo),
      }));

      expect(response.status).toBe(400);
    });


    it('should reject oversized and non-hex measurements before backend use', async () => {
      for (const mrAggregated of ['0x' + 'ab'.repeat(33), 'not-hex']) {
        const response = await appFetch(new Request('http://localhost:3001/bootAuth/app', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...validBootInfo, mrAggregated }),
        }));

        expect(response.status).toBe(400);
        expect(await response.json()).toEqual({ isAllowed: false, reason: 'invalid authorization request', gatewayAppId: '' });
      }
      expect(mockReadContract).not.toHaveBeenCalled();
    });
});

  describe('root epochs', () => {
    const validBootInfo = {
      mrAggregated: '0x' + '12'.repeat(32),
      osImageHash: '0x' + 'ab'.repeat(32),
      appId: '0x' + '11'.repeat(20),
      composeHash: '0x' + '22'.repeat(32),
      instanceId: '0x' + '33'.repeat(20),
      deviceId: '0x' + '44'.repeat(32),
    };

    const hash = '0x' + '11'.repeat(32);
    const mockChain = (currentRootEpoch: () => unknown, rootEpochCount = () => 2n) =>
      mockReadContract.mockImplementation((params) => {
        switch (params.functionName) {
          case 'isAppAllowed': return [true, ''];
          case 'isKmsAllowed': return [true, ''];
          case 'gatewayAppId': return '0xgateway';
          case 'appImplementation': return '0x9876543210987654321098765432109876543210';
          case 'rootEpochCount': return rootEpochCount();
          case 'currentRootEpoch': return currentRootEpoch();
          case 'rootEpoch': return ['0x30' + params.args[0].toString(16).padStart(2, '0'), '0x02', '', hash];
        }
      });
    const boot = async (path: string, fields: object) => {
      const response = await appFetch(new Request(`http://localhost:3001/bootAuth/${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...validBootInfo, ...fields }),
      }));
      return response.json();
    };

    it('allows only a KMS serving the current root epoch', async () => {
      mockChain(() => [1n, hash]);

      expect((await boot('app', { rootEpoch: 1, rootEpochHash: hash })).isAllowed).toBe(true);
      const stale = await boot('app', { rootEpoch: 0, rootEpochHash: hash });
      expect(stale.isAllowed).toBe(false);
      expect(stale.reason).toMatch(/1 is current/);
      const forked = await boot('app', { rootEpoch: 1, rootEpochHash: '0x' + '22'.repeat(32) });
      expect(forked.reason).toMatch(/not the registered/);
      // A KMS predating root epochs, and its apps, are cut off.
      expect((await boot('app', {})).reason).toMatch(/reports none/);
      expect((await boot('kms', {})).reason).toMatch(/reports none/);

      const info = await appFetch(new Request('http://localhost:3001/'));
      // The CA key of the current epoch, which signs every serving KMS's RPC certificate.
      expect(await info.json()).toMatchObject({ rootEpoch: 1, rootEpochHash: hash, rootCaPubkey: '0x3001' });
    });

    it('supports an upgraded empty registry without querying the current epoch', async () => {
      const current = vi.fn(() => { throw new Error('no root epoch registered'); });
      mockChain(current, () => 0n);

      expect((await boot('app', {})).isAllowed).toBe(true);
      expect((await boot('kms', {})).isAllowed).toBe(true);
      expect((await boot('app', { rootEpoch: 0, rootEpochHash: hash })).isAllowed).toBe(true);
      expect((await boot('app', { rootEpoch: 1, rootEpochHash: hash })).reason).toMatch(/not registered/);
      const info = await appFetch(new Request('http://localhost:3001/'));
      expect(info.status).toBe(200);
      const body = await info.json();
      expect(body).not.toHaveProperty('rootEpoch');
      expect(body).not.toHaveProperty('rootCaPubkey');
      expect(current).not.toHaveBeenCalled();
    });

    it('serves an old KMS, and its apps, while epoch 0 is current', async () => {
      mockChain(() => [0n, hash], () => 1n);
      expect((await boot('app', {})).isAllowed).toBe(true);
      expect((await boot('kms', {})).isAllowed).toBe(true);
    });

    it.each(['app', 'info'])('reads the registry at the same finalized block for %s', async (endpoint) => {
      mockChain(() => [1n, hash]);
      if (endpoint === 'app') {
        expect((await boot('app', { rootEpoch: 1, rootEpochHash: hash })).isAllowed).toBe(true);
      } else {
        const response = await appFetch(new Request('http://localhost:3001/'));
        expect(response.status).toBe(200);
      }
      const calls = mockReadContract.mock.calls.map(([params]) => params)
        .filter(({ functionName }) => ['rootEpochCount', 'currentRootEpoch', 'rootEpoch'].includes(functionName));
      expect(calls.map(({ functionName }) => functionName)).toEqual(endpoint === 'app'
        ? ['rootEpochCount', 'currentRootEpoch']
        : ['rootEpochCount', 'currentRootEpoch', 'rootEpoch']);
      expect(calls.every((call) => call.blockHash === blockHash(98n) && call.requireCanonical)).toBe(true);
      expect(mockGetBlock).toHaveBeenCalledTimes(2);
    });

    describe.each(['rootEpochCount', 'currentRootEpoch'])('%s failures', (getter) => {
      it.each([
        ['missing getter', { name: 'ContractFunctionZeroDataError' }],
        ['revert', { name: 'ContractFunctionRevertedError' }],
        ['RPC failure', new Error('RPC unavailable')],
      ])('fails closed on %s', async (_name, cause) => {
        const failure = () => { throw Object.assign(new Error('query failed'), { cause }); };
        mockChain(getter === 'currentRootEpoch' ? failure : () => [1n, hash],
          getter === 'rootEpochCount' ? failure : () => 2n);

        for (const path of ['app', 'kms']) {
          expect(await boot(path, {})).toEqual({
            isAllowed: false, reason: 'authorization backend unavailable', gatewayAppId: '',
          });
          expect((await boot(path, { rootEpoch: 0, rootEpochHash: hash })).isAllowed).toBe(false);
        }
        const info = await appFetch(new Request('http://localhost:3001/'));
        expect(info.status).toBe(500);
      });

      it.each(['0x', '0x1234'] as const)('fails closed on malformed ABI data %s', async (data) => {
        const { decodeFunctionResult } = await vi.importActual<typeof import('viem')>('viem');
        mockReadContract.mockImplementation((params) => {
          if (params.functionName === getter) return decodeFunctionResult({ ...params, data });
          if (params.functionName === 'rootEpochCount') return 2n;
          if (params.functionName === 'isAppAllowed') return [true, ''];
          if (params.functionName === 'gatewayAppId') return 'gateway-app';
          if (params.functionName === 'appImplementation') return '0x' + '11'.repeat(20);
          throw new Error(`unexpected function ${params.functionName}`);
        });
        expect((await boot('app', {})).isAllowed).toBe(false);
        const info = await appFetch(new Request('http://localhost:3001/'));
        expect(info.status).toBe(500);
      });
    });
  });

  describe('POST /bootAuth/kms', () => {
    const validBootInfo = {
      mrAggregated: '0x1234567890123456789012345678901234567890123456789012345678901234',
      osImageHash: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      appId: '0x1111111111111111111111111111111111111111',
      composeHash: '0x2222222222222222222222222222222222222222222222222222222222222222',
      instanceId: '0x3333333333333333333333333333333333333333',
      deviceId: '0x4444444444444444444444444444444444444444444444444444444444444444',
    };

    it('should validate KMS boot successfully', async () => {
      // Mock successful contract response
      mockReadContract.mockImplementation((params) => {
        if (params.functionName === 'rootEpochCount') return 0n;
        if (params.functionName === 'isKmsAllowed') {
          return [true, 'KMS allowed'];
        }
        if (params.functionName === 'gatewayAppId') {
          return '0xgateway123456789012345678901234567890';
        }
      });

      const response = await appFetch(new Request('http://localhost:3001/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data).toMatchObject({
        isAllowed: true,
        reason: 'KMS allowed',
        gatewayAppId: expect.any(String),
      });
    });

    it('should handle KMS rejection', async () => {
      mockReadContract.mockImplementation((params) => {
        if (params.functionName === 'rootEpochCount') return 0n;
        if (params.functionName === 'isKmsAllowed') {
          return [false, 'KMS not authorized'];
        }
        if (params.functionName === 'gatewayAppId') {
          return '0xgateway123456789012345678901234567890';
        }
      });

      const response = await appFetch(new Request('http://localhost:3001/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data).toMatchObject({
        isAllowed: false,
        reason: 'KMS not authorized',
        gatewayAppId: expect.any(String),
      });
    });

    it('should not log "Test backend error" messages', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      mockReadContract.mockRejectedValue(new Error('Test backend error'));

      const response = await appFetch(new Request('http://localhost:3001/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.isAllowed).toBe(false);
      expect(data.reason).toBe('authorization backend unavailable');

      // Verify that console.error was not called for test errors
      expect(consoleSpy).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });

    it('should log other error messages', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      mockReadContract.mockRejectedValue(new Error('real error'));

      const response = await appFetch(new Request('http://localhost:3001/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.isAllowed).toBe(false);
      expect(data.reason).toBe('authorization backend unavailable');

      // Diagnostics identify the failing boundary without retaining backend details.
      expect(consoleSpy).toHaveBeenCalledWith('KMS authorization backend failed');
      expect(JSON.stringify(consoleSpy.mock.calls)).not.toContain('real error');

      consoleSpy.mockRestore();
    });
  });
});

describe('API Schema Compatibility', () => {
  it('should match BootInfo schema requirements', () => {
    const bootInfoSchema = openApiSpec.components.schemas.BootInfo;

    // Required fields should match original fastify schema
    expect(bootInfoSchema.required).toEqual([
      'mrAggregated',
      'osImageHash',
      'appId',
      'composeHash',
      'instanceId',
      'deviceId'
    ]);

    // Optional fields should be present for full compatibility
    expect(bootInfoSchema.properties).toHaveProperty('tcbStatus');
    expect(bootInfoSchema.properties).toHaveProperty('advisoryIds');
    expect(bootInfoSchema.properties).toHaveProperty('mrSystem');
  });

  it('should match BootResponse schema requirements', () => {
    const bootResponseSchema = openApiSpec.components.schemas.BootResponse;

    expect(bootResponseSchema.required).toEqual([
      'isAllowed',
      'reason',
      'gatewayAppId'
    ]);
  });

  it('should match SystemInfo schema requirements', () => {
    const systemInfoSchema = openApiSpec.components.schemas.SystemInfo;

    expect(systemInfoSchema.required).toEqual([
      'status',
      'kmsContractAddr',
      'ethRpcUrl',
      'gatewayAppId',
      'chainId',
      'appAuthImplementation',
      'appImplementation'
    ]);
  });
});

describe('Hex Decoding Compatibility', () => {
  it('should handle hex values with and without 0x prefix', async () => {
    const bootInfoWithoutPrefix = {
      mrAggregated: '1234567890123456789012345678901234567890123456789012345678901234',
      osImageHash: 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      appId: '1111111111111111111111111111111111111111',
      composeHash: '2222222222222222222222222222222222222222222222222222222222222222',
      instanceId: '3333333333333333333333333333333333333333',
      deviceId: '4444444444444444444444444444444444444444444444444444444444444444',
    };

    mockReadContract.mockImplementation((params) => {
      if (params.functionName === 'rootEpochCount') return 0n;
      if (params.functionName === 'isAppAllowed') {
        // Verify that hex values are properly formatted
        const [bootInfoStruct] = params.args;
        expect(bootInfoStruct.mrAggregated).toMatch(/^0x[0-9a-f]{64}$/i);
        expect(bootInfoStruct.appId).toMatch(/^0x[0-9a-f]{40}$/i);
        return [true, 'success'];
      }
      if (params.functionName === 'gatewayAppId') {
        return '0xgateway123456789012345678901234567890';
      }
    });

    const response = await appFetch(new Request('http://localhost:3001/bootAuth/app', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bootInfoWithoutPrefix),
    }));

    expect(response.status).toBe(200);
  });
});

describe('Authorization freshness and domain binding', () => {
  const requestBody = {
    mrAggregated: '0x' + '11'.repeat(32),
    osImageHash: '0x' + '22'.repeat(32),
    appId: '0x' + '33'.repeat(20),
    composeHash: '0x' + '44'.repeat(32),
    instanceId: '0x' + '55'.repeat(20),
    deviceId: '0x' + '66'.repeat(32),
  };

  const postApp = (body = requestBody) => appFetch(new Request(
    'http://localhost:3001/bootAuth/app',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  ));

  it('re-evaluates replayed payloads instead of caching an earlier allow', async () => {
    let decisions = 0;
    mockReadContract.mockImplementation((params) => {
      expect(params.address).toBe('0x1234567890123456789012345678901234567890');
      if (params.functionName === 'rootEpochCount') return 0n;
      if (params.functionName === 'isAppAllowed') {
        decisions += 1;
        return decisions === 1 ? [true, 'initial allow'] : [false, 'policy changed'];
      }
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });

    const first = await postApp();
    const replay = await postApp();

    expect(await first.json()).toMatchObject({ isAllowed: true, reason: 'initial allow' });
    expect(await replay.json()).toMatchObject({ isAllowed: false, reason: 'policy changed' });
    expect(decisions).toBe(2);
  });

  it('binds changed measurements and identities into distinct contract arguments', async () => {
    const calls: unknown[] = [];
    mockReadContract.mockImplementation((params) => {
      if (params.functionName === 'rootEpochCount') return 0n;
      if (params.functionName === 'isAppAllowed') {
        calls.push(params.args[0]);
        return [true, 'allowed'];
      }
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });

    await postApp();
    await postApp({ ...requestBody, composeHash: '0x' + '77'.repeat(32) });
    await postApp({ ...requestBody, appId: '0x' + '88'.repeat(20) });

    expect(calls).toHaveLength(3);
    expect(calls[0]).not.toEqual(calls[1]);
    expect(calls[0]).not.toEqual(calls[2]);
  });

  it('fails closed during backend interruption and succeeds after recovery', async () => {
    mockReadContract.mockRejectedValueOnce(new Error('backend unavailable'));
    const interrupted = await postApp();
    expect(await interrupted.json()).toEqual({
      isAllowed: false,
      gatewayAppId: '',
      reason: 'authorization backend unavailable',
    });

    mockReadContract.mockImplementation((params) => {
      if (params.functionName === 'rootEpochCount') return 0n;
      if (params.functionName === 'isAppAllowed') return [true, 'recovered'];
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });
    const recovered = await postApp();
    expect(await recovered.json()).toMatchObject({ isAllowed: true, reason: 'recovered' });
  });
});


describe('Ethereum finalized snapshot authorization', () => {
  const requestBody = {
    mrAggregated: '0x' + '11'.repeat(32),
    osImageHash: '0x' + '22'.repeat(32),
    appId: '0x' + '33'.repeat(20),
    composeHash: '0x' + '44'.repeat(32),
    instanceId: '0x' + '55'.repeat(20),
    deviceId: '0x' + '66'.repeat(32),
  };

  const authorize = () => appFetch(new Request('http://localhost:3001/bootAuth/app', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(requestBody),
  }));

  it('reads the decision and gateway identity from one confirmation-depth snapshot', async () => {
    mockReadContract.mockImplementation((params) => {
      expect(params.blockHash).toBe(blockHash(98n));
      if (params.functionName === 'rootEpochCount') return 0n;
      if (params.functionName === 'isAppAllowed') return [true, 'finalized allow'];
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });

    const response = await authorize();
    expect(await response.json()).toMatchObject({ isAllowed: true, reason: 'finalized allow' });
    expect(mockGetBlock.mock.calls).toEqual([[{ blockTag: 'finalized' }], [{ blockNumber: 98n }]]);
  });

  it('probes the block tag and a pinned read at startup and names what the RPC cannot serve', async () => {
    const { EthereumBackend } = await import('./index.ts');
    const getBlock = vi.fn(chainAt(5n));
    const call = vi.fn(async (_: unknown) => ({}));
    const client = { getChainId: async () => 1337, getBlock, call };
    const backend = new EthereumBackend(client as never, '0x' + '11'.repeat(20), 1337, 'safe', 0n);
    await expect(backend.probe()).resolves.toBeUndefined();
    expect(getBlock).toHaveBeenCalledWith({ blockTag: 'safe' });
    expect(call.mock.calls[0][0]).toMatchObject({ blockHash: blockHash(5n), requireCanonical: true });
    call.mockRejectedValueOnce(new Error('invalid params'));
    await expect(backend.probe()).rejects.toThrow(/^cannot read at a block hash, .+ \(invalid params\)$/);
    getBlock.mockRejectedValue(new Error('invalid block tag'));
    await expect(backend.probe()).rejects.toThrow(
      /^cannot resolve ETH_BLOCK_TAG=safe \(invalid block tag\); .+ requires latest$/,
    );
    // Behind the confirmation depth counts as unavailable too.
    getBlock.mockResolvedValue({ number: 1n });
    const deep = new EthereumBackend(client as never, '0x' + '11'.repeat(20), 1337, 'finalized', 2n);
    await expect(deep.probe()).rejects.toThrow(/ETH_BLOCK_TAG=finalized/);
  });

  it('fails closed when the block is older than ETH_MAX_BLOCK_AGE', async () => {
    const { EthereumBackend } = await import('./index.ts');
    const now = BigInt(Math.floor(Date.now() / 1000));
    const backend = (timestamp: bigint) => new EthereumBackend(
      { getChainId: async () => 1337, getBlock: chainAt(5n, timestamp) } as never, '0x' + '11'.repeat(20), 1337, 'latest', 0n, 60,
    );
    await expect(backend(now - 30n).resolveBlock()).resolves.toMatchObject({ number: 5n });
    await expect(backend(now - 90n).resolveBlock()).rejects.toThrow(/ETH_MAX_BLOCK_AGE/);
  });

  it('accepts only the supported block tags, defaulting to finalized', async () => {
    const { parseBlockTag } = await import('./index.ts');
    expect(parseBlockTag(undefined)).toBe('finalized');
    expect(parseBlockTag('')).toBe('finalized');
    for (const tag of ['latest', 'safe', 'finalized']) expect(parseBlockTag(tag)).toBe(tag);
    expect(() => parseBlockTag('pending')).toThrow(/ETH_BLOCK_TAG/);
    expect(() => parseBlockTag('0x10')).toThrow(/ETH_BLOCK_TAG/);
  });

  it('re-evaluates the canonical finalized snapshot after a short reorg', async () => {
    let decisions = 0;
    const observedBlocks: string[] = [];
    mockReadContract.mockImplementation((params) => {
      if (params.functionName === 'rootEpochCount') return 0n;
      if (params.functionName === 'isAppAllowed') {
        observedBlocks.push(params.blockHash);
        decisions += 1;
        return decisions === 1 ? [true, 'old canonical allow'] : [false, 'new canonical deny'];
      }
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });

    const before = await authorize();
    mockGetBlock.mockImplementation(chainAt(101n));
    const after = await authorize();
    expect(await before.json()).toMatchObject({ isAllowed: true });
    expect(await after.json()).toMatchObject({ isAllowed: false, reason: 'new canonical deny' });
    expect(observedBlocks).toEqual([blockHash(98n), blockHash(99n)]);
  });

  it.each([
    ['wrong chain', () => mockGetChainId.mockResolvedValue(1)],
    ['stale head', () => mockGetBlock.mockResolvedValue({ number: 1n })],
    ['head timeout', () => mockGetBlock.mockRejectedValue(new Error('timeout'))],
    ['unsupported block tag', () => mockGetBlock.mockRejectedValue(new Error('invalid block tag'))],
  ])('fails closed for %s and recovers without retained decisions', async (_name, inject) => {
    inject();
    const failed = await authorize();
    expect(await failed.json()).toEqual({
      isAllowed: false,
      gatewayAppId: '',
      reason: 'authorization backend unavailable',
    });

    mockGetChainId.mockResolvedValue(1337);
    mockGetBlock.mockImplementation(chainAt(102n));
    mockReadContract.mockImplementation((params) => {
      if (params.functionName === 'rootEpochCount') return 0n;
      if (params.functionName === 'isAppAllowed') return [true, 'recovered'];
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });
    const recovered = await authorize();
    expect(await recovered.json()).toMatchObject({ isAllowed: true, reason: 'recovered' });
  });
});

// The body dstack-kms 0.6.x posts: `dstack_verifier::PolicyBootInfo`, camelCase,
// bytes as unprefixed lowercase hex, plus fields this backend does not read.
describe('dstack-kms 0.6 bootAuth payload', () => {
  const kmsPayload = (overrides: Record<string, unknown> = {}) => ({
    teeVariant: 'dstack-tdx',
    mrAggregated: '11'.repeat(32),
    osImageHash: 'ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6',
    mrSystem: '22'.repeat(32),
    appId: '33'.repeat(20),
    composeHash: '44'.repeat(32),
    instanceId: '55'.repeat(20),
    deviceId: '66'.repeat(32),
    keyProviderInfo: '7b226e616d65223a226b6d73227d'.repeat(40),
    tcbStatus: 'UpToDate',
    advisoryIds: ['INTEL-SA-00837'],
    ...overrides,
  });

  const post = (path: string, body: unknown) =>
    appFetch(new Request(`http://localhost:3001${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }));

  const bootInfoArg = (functionName: string) =>
    mockReadContract.mock.calls.map(([params]) => params)
      .find((params) => params.functionName === functionName).args[0];

  beforeEach(() => {
    mockReadContract.mockImplementation((params) => {
      if (params.functionName === 'rootEpochCount') return 0n;
      if (params.functionName === 'isKmsAllowed' || params.functionName === 'isAppAllowed') {
        return [true, ''];
      }
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });
  });

  it.each([
    ['/bootAuth/kms', 'isKmsAllowed'],
    ['/bootAuth/app', 'isAppAllowed'],
  ])('%s forwards every policy field to %s', async (path, functionName) => {
    const response = await post(path, kmsPayload());

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ isAllowed: true, reason: '', gatewayAppId: 'gateway-app' });
    expect(bootInfoArg(functionName)).toEqual({
      appId: `0x${'33'.repeat(20)}`,
      composeHash: `0x${'44'.repeat(32)}`,
      instanceId: `0x${'55'.repeat(20)}`,
      deviceId: `0x${'66'.repeat(32)}`,
      mrAggregated: `0x${'11'.repeat(32)}`,
      mrSystem: `0x${'22'.repeat(32)}`,
      osImageHash: '0xec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6',
      tcbStatus: 'UpToDate',
      advisoryIds: ['INTEL-SA-00837'],
    });
  });

  it('maps the empty instance ID of an instance-less app to the zero address', async () => {
    const response = await post('/bootAuth/app', kmsPayload({ instanceId: '' }));

    expect(await response.json()).toMatchObject({ isAllowed: true });
    expect(bootInfoArg('isAppAllowed').instanceId).toBe(`0x${'00'.repeat(20)}`);
  });

  it('passes a non-UpToDate TCB status through for the contract to judge', async () => {
    await post('/bootAuth/kms', kmsPayload({ tcbStatus: 'OutOfDate' }));

    expect(bootInfoArg('isKmsAllowed').tcbStatus).toBe('OutOfDate');
  });
});

describe('request hardening', () => {
  const bootInfo = {
    mrAggregated: '11'.repeat(32),
    osImageHash: '22'.repeat(32),
    appId: '33'.repeat(20),
    composeHash: '44'.repeat(32),
    instanceId: '55'.repeat(20),
    deviceId: '66'.repeat(32),
  };

  const post = (body: string, contentType: string) =>
    appFetch(new Request('http://localhost:3001/bootAuth/app', {
      method: 'POST',
      headers: { 'Content-Type': contentType, Origin: 'https://evil.example' },
      body,
    }));

  it.each(['text/plain', 'application/x-www-form-urlencoded'])(
    'rejects a cross-origin simple request sent as %s without reading the contract',
    async (contentType) => {
      const response = await post(JSON.stringify(bootInfo), contentType);

      expect(response.status).toBe(400);
      expect(response.headers.get('access-control-allow-origin')).toBeNull();
      expect(mockReadContract).not.toHaveBeenCalled();
    },
  );

  it('rejects an oversized body before parsing it', async () => {
    const response = await post(
      JSON.stringify({ ...bootInfo, padding: 'a'.repeat(256 * 1024) }),
      'application/json',
    );

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({
      isAllowed: false,
      reason: 'invalid authorization request',
      gatewayAppId: '',
    });
    expect(mockReadContract).not.toHaveBeenCalled();
  });

  it('marks JSON responses as not sniffable and not frameable', async () => {
    const response = await appFetch(new Request('http://localhost:3001/no-such-route'));

    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('x-frame-options')).toBe('SAMEORIGIN');
  });
});


describe('GET /app/:appId', () => {
  it('reports an app epoch only when the contract can vouch for it', async () => {
    const url = `http://localhost/app/0x${'11'.repeat(20)}`;
    mockReadContract.mockRejectedValueOnce(new Error('execution reverted: AppNotRegistered()'));
    expect((await appFetch(new Request(url))).status).toBe(503);
    mockReadContract.mockResolvedValueOnce(0n);
    const legacy = await appFetch(new Request(url));
    expect(legacy.status).toBe(200);
    expect(await legacy.json()).toEqual({ currentAppEpoch: 0 });
    expect(mockGetBlock).toHaveBeenCalledWith({ blockTag: 'latest' });
    expect(mockReadContract.mock.lastCall![0].blockHash).toBe(blockHash(100n));
    // Without agreement on the newest block, the read steps back by the confirmation depth.
    mockGetBlock.mockImplementationOnce(chainAt(100n)).mockRejectedValueOnce(new Error('no quorum'));
    mockReadContract.mockResolvedValueOnce(3n);
    expect(await (await appFetch(new Request(url))).json()).toEqual({ currentAppEpoch: 3 });
    expect(mockReadContract.mock.lastCall![0].blockHash).toBe(blockHash(98n));
  });
});

describe('GET /sevSnpTcbRequirements', () => {
  it('serves the contract value, and fails closed when it cannot be read', async () => {
    const url = 'http://localhost/sevSnpTcbRequirements';
    mockReadContract.mockResolvedValueOnce('[]');
    const response = await appFetch(new Request(url));
    expect(await response.json()).toEqual({ requirements: '[]' });
    expect(mockReadContract).toHaveBeenCalledWith(
      expect.objectContaining({ functionName: 'sevSnpTcbRequirements', blockHash: blockHash(98n) }),
    );
    mockReadContract.mockRejectedValueOnce(new Error('execution reverted'));
    expect((await appFetch(new Request(url))).status).toBe(503);
  });
});

describe('POST /authorizeApp', () => {
  const appInfo = {
    teeVariant: 'dstack-amd-sev-snp', appId: '0x' + '11'.repeat(20), composeHash: '0x' + '22'.repeat(32),
    instanceId: '', deviceId: '0x' + '33'.repeat(32),
    mrAggregated: '0x' + '44'.repeat(32), mrSystem: '0x' + '55'.repeat(32),
    osImageHash: '0x' + '66'.repeat(32), tcbStatus: 'UpToDate', advisoryIds: [],
  };
  const authorize = (requestedRootEpoch?: number) => appFetch(new Request('http://localhost/authorizeApp', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...appInfo, operation: 'app_get_key', requestedRootEpoch }),
  }));

  it('reads the complete result with one contract call at configured finality', async () => {
    const result = {
      authorized: false, rejectionReason: 'App not registered', gatewayAppId: 'gateway',
      currentAppEpoch: 0n, currentRootEpoch: 2n, currentRootEpochHash: '0x' + '77'.repeat(32),
      latestRootEpoch: 3n, latestRootEpochHash: '0x' + '88'.repeat(32),
    };
    mockReadContract.mockResolvedValueOnce(result);
    const response = await authorize();
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ...result, currentRootEpoch: 2, currentAppEpoch: 0, latestRootEpoch: 3 });
    expect(mockReadContract).toHaveBeenCalledTimes(1);
    expect(mockReadContract).toHaveBeenCalledWith(expect.objectContaining({
      functionName: 'authorizeApp', blockHash: blockHash(98n),
      args: [expect.objectContaining({ appInfo: expect.objectContaining({ appId: appInfo.appId }), requestedAppEpoch: { isSet: false, value: 0n }, requestedRootEpoch: { isSet: false, value: 0n }, teeVariant: appInfo.teeVariant })],
    }));
  });

  it('forwards the launch ticket hash, zero when absent', async () => {
    const result = {
      authorized: true, rejectionReason: '', gatewayAppId: 'gateway',
      currentAppEpoch: 0n, currentRootEpoch: 1n, currentRootEpochHash: '0x' + '77'.repeat(32),
      latestRootEpoch: 1n, latestRootEpochHash: '0x' + '77'.repeat(32),
    };
    mockReadContract.mockResolvedValue(result);
    const ticket = '0x' + '99'.repeat(32);
    for (const [launchTicketHash, expected] of [[ticket, ticket], [undefined, '0x' + '00'.repeat(32)]]) {
      const response = await appFetch(new Request('http://localhost/authorizeApp', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...appInfo, operation: 'app_get_key', launchTicketHash }),
      }));
      expect(response.status).toBe(200);
      expect(mockReadContract).toHaveBeenLastCalledWith(expect.objectContaining({
        args: [expect.objectContaining({ launchTicketHash: expected })],
      }));
    }
  });

  it('encodes an explicit epoch zero as present', async () => {
    mockReadContract.mockResolvedValueOnce({
      authorized: true, rejectionReason: '', gatewayAppId: 'gateway',
      currentAppEpoch: 0n, currentRootEpoch: 1n, currentRootEpochHash: '0x' + '77'.repeat(32),
      latestRootEpoch: 1n, latestRootEpochHash: '0x' + '77'.repeat(32),
    });
    expect((await authorize(0)).status).toBe(200);
    expect(mockReadContract).toHaveBeenCalledWith(expect.objectContaining({
      args: [expect.objectContaining({ requestedRootEpoch: { isSet: true, value: 0n } })],
    }));
  });

  it.each([
    ['authorizeKms', 'kms_import_keys', { requestedRootEpoch: 2 }],
    ['authorizeApp', 'app_get_key', { requestedRootEpoch: 1, requestedAppEpoch: 3 }],
    ['authorizeApp', 'app_get_cert', {}],
  ] as const)('forwards the operation and both epochs to %s (%s)', async (method, operation, epochs) => {
    mockReadContract.mockResolvedValueOnce({
      authorized: true, rejectionReason: '', gatewayAppId: 'gateway',
      currentAppEpoch: 3n, currentRootEpoch: 2n, currentRootEpochHash: '0x' + '77'.repeat(32),
      latestRootEpoch: 2n, latestRootEpochHash: '0x' + '77'.repeat(32),
    });
    const response = await appFetch(new Request(`http://localhost/${method}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...appInfo, operation, ...epochs }),
    }));
    expect(response.status).toBe(200);
    const selector = (value?: number) => ({ isSet: value !== undefined, value: BigInt(value ?? 0) });
    const { requestedRootEpoch, requestedAppEpoch } = epochs as { requestedRootEpoch?: number, requestedAppEpoch?: number };
    expect(mockReadContract).toHaveBeenCalledTimes(1);
    expect(mockReadContract).toHaveBeenCalledWith(expect.objectContaining({
      functionName: method,
      args: [expect.objectContaining({
        operation: keccak256(toBytes(operation)),
        requestedRootEpoch: selector(requestedRootEpoch),
        requestedAppEpoch: selector(requestedAppEpoch),
      })],
    }));
  });

  it('rejects invalid, malformed and oversized requests in the AuthorizationResult shape', async () => {
    const rejection = {
      authorized: false, rejectionReason: 'invalid authorization request', gatewayAppId: '',
      currentRootEpoch: 0, currentRootEpochHash: '0x' + '00'.repeat(32), currentAppEpoch: 0,
      latestRootEpoch: 0, latestRootEpochHash: '0x' + '00'.repeat(32),
    };
    const requests = [
      { status: 400, body: JSON.stringify({ ...appInfo, operation: 'unknown' }) },
      { status: 400, body: JSON.stringify({ ...appInfo, operation: 'app_get_key', mrAggregated: 'not-hex' }) },
      { status: 400, body: JSON.stringify({ ...appInfo, operation: 'app_get_key', teeVariant: undefined }) },
      { status: 400, body: JSON.stringify({ ...appInfo, operation: 'app_get_key', teeVariant: '' }) },
      { status: 400, body: JSON.stringify({ ...appInfo, operation: 'app_get_key', launchTicketHash: '0x' + '99'.repeat(33) }) },
      { status: 400, body: '{"appId":' },
      { status: 413, body: JSON.stringify({ ...appInfo, operation: 'app_get_key', padding: 'a'.repeat(256 * 1024) }) },
    ];
    for (const path of ['/authorizeApp', '/authorizeKms']) {
      for (const { status, body } of requests) {
        const response = await appFetch(new Request(`http://localhost${path}`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
        }));
        expect(response.status).toBe(status);
        expect(await response.json()).toEqual(rejection);
      }
    }
    expect(mockReadContract).not.toHaveBeenCalled();
  });

  it('does not fall back to legacy authorization on a failed contract call', async () => {
    mockReadContract.mockRejectedValueOnce(new Error('contract unavailable'));
    expect((await authorize()).status).toBe(503);
    expect(mockReadContract).toHaveBeenCalledTimes(1);
  });
});

describe('RPC quorum', () => {
  const block = (number: number, fork = 'a') => ({ number: `0x${number.toString(16)}`, hash: `0x${fork}${number}`, timestamp: '0x1' });
  // Each answer is a value to return, or an Error to fail with.
  const transport = async (threshold: number, answers: unknown[]) => {
    const { quorumTransport } = await import('./index.ts');
    const providers = answers.map((answer, i) => ({
      origin: `https://rpc${i}.example`,
      request: async () => { if (answer instanceof Error) throw answer; return answer; },
    }));
    return quorumTransport(providers, threshold)({});
  };
  const call = { method: 'eth_call', params: [{}, 'latest'] };

  it('answers only with what the threshold of providers agree on', async () => {
    const request = async (threshold: number, answers: unknown[]) => (await transport(threshold, answers)).request(call);
    await expect(request(2, ['0xAB', '0x01', '0xab'])).resolves.toBe('0xab');
    await expect(request(2, ['0x01', new Error('down'), '0x01'])).resolves.toBe('0x01');
    await expect(request(2, ['0x01', '0x02', '0x03'])).rejects.toThrow(/no 2 of 3 RPCs agree on eth_call/);
    await expect(request(3, ['0x01', '0x01', new Error('execution reverted')])).rejects.toThrow(
      'https://rpc2.example: execution reverted',
    );
  });

  it('resolves a tag to the highest block the threshold has reached', async () => {
    const tag = { method: 'eth_getBlockByNumber', params: ['finalized', false] };
    const request = async (answers: unknown[]) => (await transport(2, answers)).request(tag);
    await expect(request([block(5), block(100), block(99)])).resolves.toEqual(block(99));
    await expect(request([block(1_000_000), block(100), block(100)])).resolves.toEqual(block(100));
    await expect(request([block(100), new Error('down'), block(98)])).resolves.toEqual(block(98));
    await expect(request([block(100), new Error('invalid block tag'), null])).rejects.toThrow(
      /fewer than 2 RPCs serve block finalized \(https:\/\/rpc1\.example: invalid block tag/,
    );
  });

  it('agrees on a numbered block by hash and timestamp', async () => {
    const numbered = { method: 'eth_getBlockByNumber', params: ['0x62', false] };
    const request = async (answers: unknown[]) => (await transport(2, answers)).request(numbered);
    await expect(request([block(98), { ...block(98), extra: 1 }, block(98, 'b')])).resolves.toMatchObject(block(98));
    await expect(request([block(98), block(98, 'b'), null])).rejects.toThrow(/no 2 of 3 RPCs agree/);
    await expect(request([block(98), { ...block(98), number: '0x1' }, null])).rejects.toThrow(/no 2 of 3 RPCs agree/);
  });

  it('refuses methods it has no agreement rule for', async () => {
    const request = (await transport(1, ['0x1'])).request({ method: 'eth_getBalance', params: [] });
    await expect(request).rejects.toThrow(/eth_getBalance is not supported/);
  });

  it('pins the endpoint count and keeps URLs out of errors', async () => {
    const { parseRpcConfig } = await import('./index.ts');
    const urls = 'https://a.example/v2/key1\n  https://b.example/v3/key2\nhttps://c.example\n';
    expect(parseRpcConfig({ ETH_RPC_URLS: urls, ETH_RPC_QUORUM: '2/3', ETH_MAX_BLOCK_AGE: '1800' })).toMatchObject({
      origins: ['https://a.example', 'https://b.example', 'https://c.example'], threshold: 2,
    });
    expect(parseRpcConfig({ ETH_RPC_URL: 'http://node:8545' })).toMatchObject({ quorum: '1/1', threshold: 1 });
    for (const [env, error] of [
      [{ ETH_RPC_URLS: urls }, /ETH_RPC_QUORUM must be n\/m/],
      [{ ETH_RPC_URLS: urls, ETH_RPC_QUORUM: '4/3' }, /ETH_RPC_QUORUM must be n\/m/],
      [{ ETH_RPC_URLS: urls, ETH_RPC_QUORUM: '2' }, /ETH_RPC_QUORUM must be n\/m/],
      // One provider of three, or either half of four, could answer alone.
      [{ ETH_RPC_URLS: urls, ETH_RPC_QUORUM: '1/3' }, /ETH_RPC_QUORUM must be n\/m/],
      [{ ETH_RPC_URLS: urls + ' https://d.example', ETH_RPC_QUORUM: '2/4' }, /ETH_RPC_QUORUM must be n\/m/],
      // A key that smuggles in an endpoint changes the count.
      [{ ETH_RPC_URLS: urls + ' https://evil.example', ETH_RPC_QUORUM: '2/3' }, /expects 3 RPC URLs, got 4/],
      [{ ETH_RPC_URLS: 'https://a.example/1 https://a.example/2', ETH_RPC_QUORUM: '2/2' }, /distinct origins/],
      [{ ETH_RPC_URLS: 'https://a.example/key1 key2', ETH_RPC_QUORUM: '2/2' }, /^RPC URL 2 is invalid$/],
      [{ ETH_RPC_URL: 'http://a', ETH_RPC_URLS: 'http://b', ETH_RPC_QUORUM: '1/1' }, /exactly one of/],
      [{}, /exactly one of/],
      [{ ETH_RPC_URLS: urls, ETH_RPC_QUORUM: '2/3' }, /ETH_MAX_BLOCK_AGE is required/],
    ] as const) {
      expect(() => parseRpcConfig(env)).toThrow(error);
    }
  });
});

describe('delegated app authorization', () => {
  const CURRENT_HASH = '0x' + 'aa'.repeat(32);
  const LATEST_HASH = '0x' + 'bb'.repeat(32);
  const GATEWAY = 'chain-gateway';
  const ZERO_HASH = '0x' + '00'.repeat(32);
  const launchTicketHash = 'ab'.repeat(32);
  const userConfigHash = 'cd'.repeat(32);
  const appId = '0x' + '11'.repeat(20);
  // Key order and the uninterpreted userConfigHash must survive the forward.
  // A re-serialized body would drop the unknown field and reorder the rest.
  const rawBody = [
    '{',
    `"userConfigHash":"${userConfigHash}",`,
    `"launchTicketHash":"${launchTicketHash}",`,
    '"operation":"app_get_key",',
    '"teeVariant":"dstack-tdx",',
    `"requestedRootEpoch":1,`,
    `"appId":"${appId}",`,
    `"composeHash":"${'22'.repeat(32)}",`,
    '"instanceId":"",',
    `"deviceId":"${'33'.repeat(32)}",`,
    `"mrAggregated":"${'44'.repeat(32)}",`,
    `"osImageHash":"${'66'.repeat(32)}"`,
    '}',
  ].join('');

  type DelegateCall = {
    url: string;
    method: string;
    body?: string;
    redirect?: RequestRedirect;
    cache?: RequestCache;
  };
  let calls: DelegateCall[];

  const chainRoots = {
    gatewayAppId: GATEWAY,
    currentRootEpoch: 2,
    currentRootEpochHash: CURRENT_HASH,
    latestRootEpoch: 3,
    latestRootEpochHash: LATEST_HASH,
  };

  function mockChain({ count = 4n, fail = false }: { count?: bigint; fail?: boolean } = {}) {
    mockReadContract.mockImplementation((params) => {
      if (fail) return Promise.reject(new Error('rpc down'));
      switch (params.functionName) {
        case 'gatewayAppId': return GATEWAY;
        case 'rootEpochCount': return count;
        case 'currentRootEpoch': return [2n, CURRENT_HASH];
        case 'rootEpoch': return ['0x' + '11'.repeat(32), '0x' + '22'.repeat(32), 'evidence', LATEST_HASH];
        case 'appImplementation': return '0x' + '99'.repeat(20);
        case 'sevSnpTcbRequirements': return '[]';
        case 'authorizeKms': return {
          authorized: true, rejectionReason: '', gatewayAppId: GATEWAY,
          currentAppEpoch: 0n, currentRootEpoch: 2n, currentRootEpochHash: CURRENT_HASH,
          latestRootEpoch: 3n, latestRootEpochHash: LATEST_HASH,
        };
        case 'isAppAllowed': return [true, 'on-chain'];
        default: return Promise.reject(new Error(`unexpected contract call ${params.functionName}`));
      }
    });
  }

  function stubDelegate(handler: (call: DelegateCall) => Response | Promise<Response>) {
    calls = [];
    vi.stubGlobal('fetch', async (url: string, init: RequestInit = {}) => {
      const body = typeof init.body === 'string' || init.body == null
        ? init.body ?? undefined
        : await new Response(init.body).text();
      const call: DelegateCall = {
        url: String(url),
        method: init.method ?? 'GET',
        body,
        redirect: init.redirect,
        cache: init.cache,
      };
      calls.push(call);
      return handler(call);
    });
  }

  function delegateOk(extra: Record<string, unknown> = {}) {
    return new Response(JSON.stringify({
      authorized: true,
      rejectionReason: '',
      gatewayAppId: 'delegate-gateway',
      currentRootEpoch: 9,
      currentRootEpochHash: '0x' + 'ff'.repeat(32),
      currentAppEpoch: 7,
      latestRootEpoch: 9,
      latestRootEpochHash: '0x' + 'ee'.repeat(32),
      note: 'not-part-of-the-result',
      ...extra,
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  }

  async function load(url?: string) {
    if (url === undefined) delete process.env.APP_AUTH_URL;
    else process.env.APP_AUTH_URL = url;
    vi.resetModules();
    const mod = await import('./index.ts');
    return mod.default.fetch as (request: Request) => Promise<Response>;
  }

  const postApp = (fetchApp: (request: Request) => Promise<Response>, body = rawBody) => fetchApp(new Request('http://localhost/authorizeApp', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
  }));

  beforeEach(() => {
    calls = [];
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    delete process.env.APP_AUTH_URL;
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it('keeps the chain path when APP_AUTH_URL is unset, even if the env appears later', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    process.env.APP_AUTH_URL = 'http://127.0.0.1:9';
    mockReadContract.mockResolvedValueOnce({
      authorized: false, rejectionReason: 'App not registered', gatewayAppId: 'gateway',
      currentAppEpoch: 0n, currentRootEpoch: 2n, currentRootEpochHash: CURRENT_HASH,
      latestRootEpoch: 2n, latestRootEpochHash: CURRENT_HASH,
    });
    const response = await appFetch(new Request('http://localhost/authorizeApp', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        teeVariant: 'dstack-tdx', operation: 'app_get_key', appId,
        composeHash: '0x' + '22'.repeat(32), instanceId: '', deviceId: '0x' + '33'.repeat(32),
        mrAggregated: '0x' + '44'.repeat(32), osImageHash: '0x' + '66'.repeat(32),
      }),
    }));
    expect(response.status).toBe(200);
    expect((await response.json()).rejectionReason).toBe('App not registered');
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(mockReadContract).toHaveBeenCalledWith(expect.objectContaining({ functionName: 'authorizeApp' }));
  });

  it('forwards the authorizeApp body byte for byte and overwrites root fields from the pinned chain block', async () => {
    mockChain();
    stubDelegate(() => delegateOk());
    const fetchApp = await load('http://127.0.0.1:9/delegate/');
    const response = await postApp(fetchApp);
    expect(response.status).toBe(200);
    expect(calls).toEqual([{
      url: 'http://127.0.0.1:9/delegate/authorizeApp',
      method: 'POST',
      body: rawBody,
      redirect: 'error',
      cache: 'no-store',
    }]);
    expect(await response.json()).toEqual({
      authorized: true,
      rejectionReason: '',
      currentAppEpoch: 7,
      ...chainRoots,
    });
    expect(mockReadContract).not.toHaveBeenCalledWith(expect.objectContaining({
      functionName: 'authorizeApp',
    }));
    expect(mockReadContract).not.toHaveBeenCalledWith(expect.objectContaining({
      functionName: 'currentAppEpoch',
    }));
    for (const params of mockReadContract.mock.calls.map((call) => call[0])) {
      expect(params.blockHash).toBe(blockHash(98n));
      expect(params.requireCanonical).toBe(true);
    }
    expect(mockReadContract).toHaveBeenCalledWith(expect.objectContaining({
      functionName: 'rootEpoch', args: [3n], blockHash: blockHash(98n),
    }));

    const info = await (await fetchApp(new Request('http://localhost/'))).json();
    expect(info.gatewayAppId).toBe(GATEWAY);
    expect(info.rootEpoch).toBe(2);
    expect(info.rootEpochHash).toBe(CURRENT_HASH);
    expect(calls).toHaveLength(1);
  });

  it('keeps a delegate denial, including its app epoch, and still overwrites root fields', async () => {
    mockChain();
    stubDelegate(() => delegateOk({
      authorized: false, rejectionReason: 'compose hash is not allowed', currentAppEpoch: 4,
    }));
    const fetchApp = await load('http://127.0.0.1:9');
    const response = await postApp(fetchApp);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      authorized: false,
      rejectionReason: 'compose hash is not allowed',
      currentAppEpoch: 4,
      ...chainRoots,
    });
  });

  it('denies a requested root epoch newer than the current one without calling the delegate', async () => {
    mockChain();
    stubDelegate(() => delegateOk());
    const fetchApp = await load('http://127.0.0.1:9');
    const newer = rawBody.replace('"requestedRootEpoch":1', '"requestedRootEpoch":3');
    const denied = await postApp(fetchApp, newer);
    expect(denied.status).toBe(200);
    expect(await denied.json()).toEqual({
      authorized: false,
      rejectionReason: 'Requested root epoch is not active',
      currentAppEpoch: 0,
      ...chainRoots,
    });
    expect(calls).toEqual([]);

    const current = rawBody.replace('"requestedRootEpoch":1', '"requestedRootEpoch":2');
    expect((await postApp(fetchApp, current)).status).toBe(200);
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toBe(current);
  });

  it('denies app authorization when no root epoch is registered, without calling the delegate', async () => {
    mockChain({ count: 0n });
    stubDelegate(() => delegateOk());
    const fetchApp = await load('http://127.0.0.1:9');
    const response = await postApp(fetchApp);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      authorized: false,
      rejectionReason: 'Root epoch not registered',
      gatewayAppId: GATEWAY,
      currentRootEpoch: 0,
      currentRootEpochHash: ZERO_HASH,
      currentAppEpoch: 0,
      latestRootEpoch: 0,
      latestRootEpochHash: ZERO_HASH,
    });
    expect(calls).toEqual([]);
    expect(mockReadContract).not.toHaveBeenCalledWith(expect.objectContaining({ functionName: 'currentRootEpoch' }));
    expect(mockReadContract).not.toHaveBeenCalledWith(expect.objectContaining({ functionName: 'rootEpoch' }));
  });

  it('denies a KMS operation on /authorizeApp without calling the delegate', async () => {
    mockChain();
    stubDelegate(() => delegateOk());
    const fetchApp = await load('http://127.0.0.1:9');
    const response = await postApp(fetchApp, rawBody.replace('app_get_key', 'kms_serve'));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      authorized: false,
      rejectionReason: 'Invalid authorization operation',
      currentAppEpoch: 0,
      ...chainRoots,
    });
    expect(calls).toEqual([]);
  });

  it.each([
    ['network', () => { throw new TypeError('connect ECONNREFUSED'); }, 'app authorization delegate unavailable'],
    ['timeout', () => { throw new DOMException('The operation was timed out', 'TimeoutError'); }, 'app authorization delegate timed out'],
    ['HTTP error', () => new Response('super-secret-policy', { status: 502 }), 'app authorization delegate returned HTTP 502'],
    ['invalid JSON', () => new Response('not-json', { status: 200 }), 'app authorization delegate returned invalid JSON'],
    ['invalid shape', () => new Response('{"authorized":true}', { status: 200 }), 'app authorization delegate returned an invalid response'],
    ['oversized', () => new Response('{}', { status: 200, headers: { 'content-length': String(128 * 1024) } }), 'app authorization delegate response is too large'],
  ])('fails closed when the delegate returns %s', async (_label, respond, reason) => {
    mockChain();
    stubDelegate(respond);
    const fetchApp = await load('http://127.0.0.1:9');
    const response = await postApp(fetchApp);
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data).toEqual({
      authorized: false,
      rejectionReason: reason,
      currentAppEpoch: 0,
      ...chainRoots,
    });
    expect(JSON.stringify(data)).not.toContain('super-secret-policy');
  });

  it('does not call the delegate when the chain cannot supply root fields', async () => {
    mockChain({ fail: true });
    stubDelegate(() => delegateOk());
    const fetchApp = await load('http://127.0.0.1:9');
    const response = await postApp(fetchApp);
    expect(response.status).toBe(503);
    expect(calls).toEqual([]);
  });

  it('rejects an invalid authorizeApp body before calling the delegate', async () => {
    mockChain();
    stubDelegate(() => delegateOk());
    const fetchApp = await load('http://127.0.0.1:9');
    const response = await postApp(fetchApp, '{"operation":"app_get_key"}');
    expect(response.status).toBe(400);
    expect(calls).toEqual([]);
    expect(mockReadContract).not.toHaveBeenCalled();
  });

  it('leaves KMS authorization, boot, and TCB requirements on chain', async () => {
    mockChain();
    stubDelegate(() => delegateOk());
    const fetchApp = await load('http://127.0.0.1:9');
    const kms = await fetchApp(new Request('http://localhost/authorizeKms', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: rawBody.replace('app_get_key', 'kms_serve'),
    }));
    expect(kms.status).toBe(200);
    expect(mockReadContract).toHaveBeenCalledWith(expect.objectContaining({ functionName: 'authorizeKms' }));

    mockReadContract.mockClear();
    mockChain();
    const boot = await fetchApp(new Request('http://localhost/bootAuth/app', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        appId, composeHash: '0x' + '22'.repeat(32), instanceId: '0x' + '33'.repeat(20),
        deviceId: '0x' + '44'.repeat(32), mrAggregated: '0x' + '55'.repeat(32),
        osImageHash: '0x' + '66'.repeat(32),
        rootEpoch: 2, rootEpochHash: CURRENT_HASH,
      }),
    }));
    expect(boot.status).toBe(200);
    expect(await boot.json()).toMatchObject({ isAllowed: true, reason: 'on-chain' });
    expect(mockReadContract).toHaveBeenCalledWith(expect.objectContaining({ functionName: 'isAppAllowed' }));

    const tcb = await fetchApp(new Request('http://localhost/sevSnpTcbRequirements'));
    expect(await tcb.json()).toEqual({ requirements: '[]' });
    expect(calls).toEqual([]);
  });

  it('forwards GET /app/:appId and fails closed instead of inventing an epoch', async () => {
    stubDelegate((call) => {
      if (call.url.endsWith('/app/' + '0xAb' + 'cd'.repeat(19))) {
        return new Response(JSON.stringify({ currentAppEpoch: 5, extra: true }), { status: 200 });
      }
      return new Response('nope', { status: 500 });
    });
    const fetchApp = await load('http://127.0.0.1:9/delegate');
    const appIdPath = '0xAb' + 'cd'.repeat(19);
    const ok = await fetchApp(new Request(`http://localhost/app/${appIdPath}`));
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ currentAppEpoch: 5 });
    expect(calls[0]).toMatchObject({ url: `http://127.0.0.1:9/delegate/app/${appIdPath}`, method: 'GET' });
    expect(mockReadContract).not.toHaveBeenCalled();

    const failed = await fetchApp(new Request(`http://localhost/app/0x${'12'.repeat(20)}`));
    expect(failed.status).toBe(503);
    expect(await failed.json()).not.toHaveProperty('currentAppEpoch');

    const invalid = await fetchApp(new Request('http://localhost/app/not-an-id'));
    expect(invalid.status).toBe(400);
    expect(calls).toHaveLength(2);
  });

  it('refuses to start when APP_AUTH_URL is not an absolute http(s) URL', async () => {
    process.env.APP_AUTH_URL = 'file:///tmp/auth';
    vi.resetModules();
    await expect(import('./index.ts')).rejects.toThrow(/APP_AUTH_URL/);
  });

  it('treats a blank APP_AUTH_URL as unset and rejects credentials in the URL', async () => {
    delete process.env.APP_AUTH_URL;
    vi.resetModules();
    const { parseAppAuthUrl } = await import('./index.ts');
    expect(parseAppAuthUrl(undefined)).toBeUndefined();
    expect(parseAppAuthUrl('   ')).toBeUndefined();
    expect(parseAppAuthUrl('http://127.0.0.1:9/delegate/')).toBe('http://127.0.0.1:9/delegate');
    expect(() => parseAppAuthUrl('http://user:pass@127.0.0.1:9')).toThrow(/credentials/);
  });

  it('returns a delegate failure before the KMS webhook timeout', async () => {
    delete process.env.APP_AUTH_URL;
    vi.resetModules();
    const { APP_AUTH_TIMEOUT_MS } = await import('./index.ts');
    expect(APP_AUTH_TIMEOUT_MS).toBeGreaterThan(0);
    expect(APP_AUTH_TIMEOUT_MS).toBeLessThan(60_000);
  });
});
