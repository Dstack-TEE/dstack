// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import openApiSpec from './openapi.json';

// Mock viem
const mockReadContract = vi.fn();
const mockGetChainId = vi.fn();
const mockGetBlockNumber = vi.fn();

vi.mock('viem', () => ({
  createPublicClient: vi.fn(() => ({
    readContract: mockReadContract,
    getChainId: mockGetChainId,
    getBlockNumber: mockGetBlockNumber,
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
  mockGetBlockNumber.mockResolvedValue(100n);
});

describe('API Compatibility Tests', () => {
  describe('GET /', () => {
    it('should return system info matching OpenAPI spec', async () => {
      // Mock contract calls
      mockReadContract.mockImplementation((params) => {
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

      // Verify that console.error was called for real errors
      expect(consoleSpy).toHaveBeenCalledWith('error in KMS boot auth:', expect.any(Error));

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
    mockGetBlockNumber.mockResolvedValue(100n);
    mockReadContract.mockImplementation((params) => {
      expect(params.blockNumber).toBe(98n);
      if (params.functionName === 'isAppAllowed') return [true, 'finalized allow'];
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });

    const response = await authorize();
    expect(await response.json()).toMatchObject({ isAllowed: true, reason: 'finalized allow' });
    expect(mockGetBlockNumber).toHaveBeenCalledTimes(1);
  });

  it('re-evaluates the canonical finalized snapshot after a short reorg', async () => {
    mockGetBlockNumber.mockResolvedValueOnce(100n).mockResolvedValueOnce(101n);
    let decisions = 0;
    const observedBlocks: bigint[] = [];
    mockReadContract.mockImplementation((params) => {
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
    ['stale head', () => mockGetBlockNumber.mockResolvedValue(1n)],
    ['head timeout', () => mockGetBlockNumber.mockRejectedValue(new Error('timeout'))],
  ])('fails closed for %s and recovers without retained decisions', async (_name, inject) => {
    inject();
    const failed = await authorize();
    expect(await failed.json()).toEqual({
      isAllowed: false,
      gatewayAppId: '',
      reason: 'authorization backend unavailable',
    });

    mockGetChainId.mockResolvedValue(1337);
    mockGetBlockNumber.mockResolvedValue(102n);
    mockReadContract.mockImplementation((params) => {
      if (params.functionName === 'isAppAllowed') return [true, 'recovered'];
      if (params.functionName === 'gatewayAppId') return 'gateway-app';
      throw new Error(`unexpected function ${params.functionName}`);
    });
    const recovered = await authorize();
    expect(await recovered.json()).toMatchObject({ isAllowed: true, reason: 'recovered' });
  });
});
