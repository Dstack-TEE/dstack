// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { FastifyInstance } from 'fastify';
import { build } from './server';
import { BootInfo } from './types';

// Mock EthereumBackend
jest.mock('./ethereum', () => {
  return {
    EthereumBackend: jest.fn().mockImplementation(() => ({
      checkBoot: jest.fn()
    }))
  };
});

describe('Server', () => {
  let app: FastifyInstance;
  const mockBootInfo: BootInfo = {
    tcbStatus: "UpToDate",
    advisoryIds: [],
    mrAggregated: '0x1234',
    osImageHash: '0x5678',
    mrSystem: '0x9012',
    appId: '0x9012345678901234567890123456789012345678',
    composeHash: '0xabcd',
    instanceId: '0x3456789012345678901234567890123456789012',
    deviceId: '0xef12'
  };

  beforeAll(async () => {
    app = await build();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /bootAuth/app', () => {
    it('should return 200 when backend check passes', async () => {
      // Mock successful response
      const mockCheckBoot = jest.fn().mockResolvedValue({
        isAllowed: true,
        reason: '',
        gatewayAppId: ''
      });
      app.ethereum.checkBoot = mockCheckBoot;

      const response = await app.inject({
        method: 'POST',
        url: '/bootAuth/app',
        payload: mockBootInfo
      });

      expect(response.statusCode).toBe(200);
      const result = JSON.parse(response.payload);
      expect(result.isAllowed).toBe(true);
      expect(result.reason).toBe('');
      expect(mockCheckBoot).toHaveBeenCalledWith(mockBootInfo, false);
    });

    it('should return 400 for invalid boot info', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/bootAuth/app',
        payload: {
          // Missing required fields
          mrAggregated: '0x1234'
        }
      });

      expect(response.statusCode).toBe(400);
    });
  });

  describe('POST /bootAuth/kms', () => {
    it('should return 200 when backend check passes', async () => {
      // Mock successful response
      const mockCheckBoot = jest.fn().mockResolvedValue({
        isAllowed: true,
        reason: '',
        gatewayAppId: '0x1234',
      });
      app.ethereum.checkBoot = mockCheckBoot;

      const response = await app.inject({
        method: 'POST',
        url: '/bootAuth/kms',
        payload: mockBootInfo,
      });

      const result = JSON.parse(response.payload);
      expect(response.statusCode).toBe(200);
      expect(result.isAllowed).toBe(true);
      expect(result.reason).toBe('');
      expect(mockCheckBoot).toHaveBeenCalledWith(mockBootInfo, true);
    });

    it('should handle backend errors gracefully', async () => {
      // Mock error response
      const mockCheckBoot = jest.fn().mockRejectedValue(new Error('Test backend error'));
      app.ethereum.checkBoot = mockCheckBoot;

      const response = await app.inject({
        method: 'POST',
        url: '/bootAuth/kms',
        payload: mockBootInfo
      });

      expect(response.statusCode).toBe(200);
      const result = JSON.parse(response.payload);
      expect(result.isAllowed).toBe(false);
      expect(result.reason).toMatch(/Test backend error/);
    });
  });
});
