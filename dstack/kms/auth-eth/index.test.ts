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
  http: vi.fn(),
  getContract: vi.fn(),
}));

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
  mockGetBlock.mockResolvedValue({ number: 100n });
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
      expect(await info.json()).toMatchObject({ rootEpoch: 1, rootEpochHash: hash });
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
      expect(await info.json()).not.toHaveProperty('rootEpoch');
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
        .filter(({ functionName }) => ['rootEpochCount', 'currentRootEpoch'].includes(functionName));
      expect(calls.map(({ functionName }) => functionName)).toEqual(['rootEpochCount', 'currentRootEpoch']);
      expect(calls.every(({ blockNumber }) => blockNumber === 98n)).toBe(true);
      expect(mockGetBlock).toHaveBeenCalledTimes(1);
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
    mockGetBlock.mockResolvedValue({ number: 100n });
    mockReadContract.mockImplementation((params) => {
      expect(params.blockNumber).toBe(98n);
      if (params.functionName === 'rootEpochCount') return 0n;
      if (params.functionName === 'isAppAllowed') return [true, 'finalized allow'];
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });

    const response = await authorize();
    expect(await response.json()).toMatchObject({ isAllowed: true, reason: 'finalized allow' });
    expect(mockGetBlock).toHaveBeenCalledTimes(1);
    expect(mockGetBlock).toHaveBeenCalledWith({ blockTag: 'finalized' });
  });

  it('probes the block tag at startup and names the fix when the RPC cannot serve it', async () => {
    const { EthereumBackend } = await import('./index.ts');
    const getBlock = vi.fn().mockResolvedValue({ number: 5n });
    const client = { getChainId: async () => 1337, getBlock };
    const backend = new EthereumBackend(client as never, '0x' + '11'.repeat(20), 1337, 'safe', 0n);
    await expect(backend.probeBlockTag()).resolves.toBeUndefined();
    expect(getBlock).toHaveBeenCalledWith({ blockTag: 'safe' });
    getBlock.mockRejectedValue(new Error('invalid block tag'));
    await expect(backend.probeBlockTag()).rejects.toThrow(
      /^ETH_BLOCK_TAG=safe is not supported by the RPC \(.+\); OP-stack via Helios requires latest$/,
    );
    // Behind the confirmation depth counts as unavailable too.
    getBlock.mockResolvedValue({ number: 1n });
    const deep = new EthereumBackend(client as never, '0x' + '11'.repeat(20), 1337, 'finalized', 2n);
    await expect(deep.probeBlockTag()).rejects.toThrow(/ETH_BLOCK_TAG=finalized/);
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
    mockGetBlock.mockResolvedValueOnce({ number: 100n }).mockResolvedValueOnce({ number: 101n });
    let decisions = 0;
    const observedBlocks: bigint[] = [];
    mockReadContract.mockImplementation((params) => {
      if (params.functionName === 'rootEpochCount') return 0n;
      if (params.functionName === 'isAppAllowed') {
        observedBlocks.push(params.blockNumber);
        decisions += 1;
        return decisions === 1 ? [true, 'old canonical allow'] : [false, 'new canonical deny'];
      }
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });

    const before = await authorize();
    const after = await authorize();
    expect(await before.json()).toMatchObject({ isAllowed: true });
    expect(await after.json()).toMatchObject({ isAllowed: false, reason: 'new canonical deny' });
    expect(observedBlocks).toEqual([98n, 99n]);
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
    mockGetBlock.mockResolvedValue({ number: 102n });
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
      functionName: 'authorizeApp', blockNumber: 98n,
      args: [expect.objectContaining({ appInfo: expect.objectContaining({ appId: appInfo.appId }), requestedAppEpoch: { isSet: false, value: 0n }, requestedRootEpoch: { isSet: false, value: 0n }, teeVariant: appInfo.teeVariant })],
    }));
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
