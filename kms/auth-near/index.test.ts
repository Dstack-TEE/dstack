// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';

// Mock near-api-js
const mockViewFunction = vi.fn();
const mockAccount = {
  viewFunction: mockViewFunction,
};

const mockConnect = vi.fn(() => ({
  account: vi.fn(() => Promise.resolve(mockAccount)),
  config: { networkId: 'testnet' },
}));

vi.mock('near-api-js', () => ({
  connect: mockConnect,
  keyStores: {
    InMemoryKeyStore: vi.fn(),
  },
}));

// Dynamic import after mocking
let appFetch: any;

beforeAll(async () => {
  // Set environment variables for testing
  process.env.NEAR_RPC_URL = 'https://rpc.testnet.fastnear.com';
  process.env.NEAR_NETWORK_ID = 'testnet';
  process.env.KMS_CONTRACT_ID = 'kms.testnet';
  process.env.PORT = '3002';
  
  // Import the app after mocking
  const indexModule = await import('./index.ts');
  appFetch = indexModule.default.fetch;
  
  // Wait for NEAR initialization
  await new Promise(resolve => setTimeout(resolve, 100));
});

beforeEach(() => {
  // Reset mocks before each test
  vi.clearAllMocks();
});

describe('auth-near API Tests', () => {
  describe('GET /', () => {
    it('should return system info', async () => {
      // Mock contract calls
      mockViewFunction.mockImplementation((params) => {
        if (params.methodName === 'get_gateway_app_id') {
          return Promise.resolve('gateway.testnet');
        }
        return Promise.resolve('');
      });

      const response = await appFetch(new Request('http://localhost:3002/'));
      expect(response.status).toBe(200);
      
      const data = await response.json();
      expect(data.status).toBe('ok');
      expect(data.kmsContractAddr).toBe('kms.testnet');
    });
  });

  describe('POST /bootAuth/app', () => {
    it('should validate app boot request', async () => {
      const bootInfo = {
        mrAggregated: '0x' + 'a'.repeat(64),
        osImageHash: '0x' + 'b'.repeat(64),
        appId: '0x' + 'c'.repeat(40),
        composeHash: '0x' + 'd'.repeat(64),
        instanceId: '0x' + 'e'.repeat(40),
        deviceId: '0x' + 'f'.repeat(64),
        tcbStatus: 'UpToDate',
        advisoryIds: [],
        mrSystem: '0x' + '1'.repeat(64),
      };

      // Mock contract calls
      mockViewFunction.mockImplementation((params) => {
        if (params.methodName === 'is_app_registered') {
          return Promise.resolve(true);
        }
        if (params.methodName === 'is_os_image_allowed') {
          return Promise.resolve(true);
        }
        if (params.methodName === 'is_app_allowed') {
          return Promise.resolve([true, '']);
        }
        if (params.methodName === 'get_gateway_app_id') {
          return Promise.resolve('gateway.testnet');
        }
        return Promise.resolve('');
      });

      const response = await appFetch(
        new Request('http://localhost:3002/bootAuth/app', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(bootInfo),
        })
      );

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.isAllowed).toBe(true);
      expect(data.gatewayAppId).toBe('gateway.testnet');
    });

    it('should reject unregistered app', async () => {
      const bootInfo = {
        mrAggregated: '0x' + 'a'.repeat(64),
        osImageHash: '0x' + 'b'.repeat(64),
        appId: '0x' + 'c'.repeat(40),
        composeHash: '0x' + 'd'.repeat(64),
        instanceId: '0x' + 'e'.repeat(40),
        deviceId: '0x' + 'f'.repeat(64),
      };

      mockViewFunction.mockImplementation((params) => {
        if (params.methodName === 'is_app_registered') {
          return Promise.resolve(false);
        }
        return Promise.resolve('');
      });

      const response = await appFetch(
        new Request('http://localhost:3002/bootAuth/app', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(bootInfo),
        })
      );

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.isAllowed).toBe(false);
      expect(data.reason).toContain('not registered');
    });
  });

  describe('POST /bootAuth/kms', () => {
    it('should validate KMS boot request', async () => {
      const bootInfo = {
        mrAggregated: '0x' + 'a'.repeat(64),
        osImageHash: '0x' + 'b'.repeat(64),
        appId: '0x' + 'c'.repeat(40),
        composeHash: '0x' + 'd'.repeat(64),
        instanceId: '0x' + 'e'.repeat(40),
        deviceId: '0x' + 'f'.repeat(64),
        tcbStatus: 'UpToDate',
      };

      mockViewFunction.mockImplementation((params) => {
        if (params.methodName === 'is_kms_allowed') {
          return Promise.resolve([true, '']);
        }
        if (params.methodName === 'get_gateway_app_id') {
          return Promise.resolve('gateway.testnet');
        }
        return Promise.resolve('');
      });

      const response = await appFetch(
        new Request('http://localhost:3002/bootAuth/kms', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(bootInfo),
        })
      );

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.isAllowed).toBe(true);
    });
  });
});


