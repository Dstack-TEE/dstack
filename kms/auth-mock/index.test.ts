// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import openApiSpec from './openapi.json';

// Dynamic import
let appFetch: any;

beforeAll(async () => {
  // Set environment variables for testing
  process.env.KMS_CONTRACT_ADDR = '0xmockcontract1234567890123456789012345678';
  process.env.PORT = '3002';
  
  // Import the app
  const indexModule = await import('./index.ts');
  appFetch = indexModule.default.fetch;
});

beforeEach(() => {
  // Reset console spy before each test
  vi.clearAllMocks();
});

describe('Mock Backend Tests', () => {
  describe('GET /', () => {
    it('should return mock system info', async () => {
      const response = await appFetch(new Request('http://localhost:3002/'));
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data).toMatchObject({
        status: 'ok',
        kmsContractAddr: expect.any(String),
        gatewayAppId: expect.any(String),
        chainId: expect.any(Number),
        appAuthImplementation: expect.any(String),
        appImplementation: expect.any(String),
        note: 'this is a mock backend - all authentications will succeed'
      });

      // Verify mock values (using same defaults as implementation)
      expect(data.gatewayAppId).toBe(process.env.MOCK_GATEWAY_APP_ID || '0xmockgateway1234567890123456789012345678');
      expect(data.chainId).toBe(parseInt(process.env.MOCK_CHAIN_ID || '1337'));
      expect(data.appImplementation).toBe(process.env.MOCK_APP_IMPLEMENTATION || '0xmockapp9876543210987654321098765432109');
      
      // Verify response structure matches OpenAPI spec
      const systemInfoSchema = openApiSpec.components.schemas.MockSystemInfo;
      const requiredFields = systemInfoSchema.required;
      
      requiredFields.forEach(field => {
        expect(data).toHaveProperty(field);
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

    it('should always return success for app auth', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      
      const response = await appFetch(new Request('http://localhost:3002/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data).toMatchObject({
        isAllowed: true,
        reason: 'mock app always allowed',
        gatewayAppId: process.env.MOCK_GATEWAY_APP_ID || '0xmockgateway1234567890123456789012345678',
      });

      // Verify console log was called
      expect(consoleSpy).toHaveBeenCalledWith('mock app boot auth request:', {
        appId: validBootInfo.appId,
        instanceId: validBootInfo.instanceId,
        note: 'always returning success'
      });

      // Verify response matches OpenAPI spec
      const bootResponseSchema = openApiSpec.components.schemas.BootResponse;
      const requiredFields = bootResponseSchema.required;
      
      requiredFields.forEach(field => {
        expect(data).toHaveProperty(field);
      });

      consoleSpy.mockRestore();
    });

    it('should handle full BootInfo with optional fields', async () => {
      const fullBootInfo = {
        ...validBootInfo,
        tcbStatus: 'OK',
        advisoryIds: ['INTEL-SA-00123'],
        mrSystem: '0x5555555555555555555555555555555555555555555555555555555555555555',
      };

      const response = await appFetch(new Request('http://localhost:3002/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(fullBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.isAllowed).toBe(true);
      expect(data.reason).toBe('mock app always allowed');
    });

    it('should reject invalid request body', async () => {
      const invalidBootInfo = {
        mrAggregated: '0x1234', // missing required fields
      };

      const response = await appFetch(new Request('http://localhost:3002/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(invalidBootInfo),
      }));

      expect(response.status).toBe(400);
    });

    it('should return success even with minimal data', async () => {
      const minimalBootInfo = {
        mrAggregated: 'minimal',
        osImageHash: 'minimal',
        appId: 'minimal',
        composeHash: 'minimal',
        instanceId: 'minimal',
        deviceId: 'minimal',
      };

      const response = await appFetch(new Request('http://localhost:3002/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(minimalBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.isAllowed).toBe(true);
      expect(data.reason).toBe('mock app always allowed');
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

    it('should always return success for KMS auth', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      
      const response = await appFetch(new Request('http://localhost:3002/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data).toMatchObject({
        isAllowed: true,
        reason: 'mock KMS always allowed',
        gatewayAppId: process.env.MOCK_GATEWAY_APP_ID || '0xmockgateway1234567890123456789012345678',
      });

      // Verify console log was called
      expect(consoleSpy).toHaveBeenCalledWith('mock KMS boot auth request:', {
        appId: validBootInfo.appId,
        instanceId: validBootInfo.instanceId,
        note: 'always returning success'
      });

      consoleSpy.mockRestore();
    });

    it('should handle different request patterns', async () => {
      const randomBootInfo = {
        mrAggregated: 'random-mr-value',
        osImageHash: 'random-os-hash',
        appId: 'random-app-id',
        composeHash: 'random-compose-hash',
        instanceId: 'random-instance-id',
        deviceId: 'random-device-id',
        tcbStatus: 'FAIL', // even with fail status
        advisoryIds: ['CRITICAL-ADVISORY'],
      };

      const response = await appFetch(new Request('http://localhost:3002/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(randomBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.isAllowed).toBe(true); // Always true in mock
      expect(data.reason).toBe('mock KMS always allowed');
    });

    it('should handle "Test backend error" appropriately', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      // This shouldn't actually throw an error in mock backend, but test the error handling path
      const response = await appFetch(new Request('http://localhost:3002/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validBootInfo),
      }));

      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.isAllowed).toBe(true); // Still success in mock

      // Verify console.error was not called (no errors in mock)
      expect(consoleSpy).not.toHaveBeenCalled();
      
      consoleSpy.mockRestore();
    });
  });
});

describe('API Schema Compatibility', () => {
  it('should match BootInfo schema requirements', () => {
    const bootInfoSchema = openApiSpec.components.schemas.BootInfo;
    
    // Required fields should match original schema
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

    // Verify mock-specific examples
    expect(bootResponseSchema.properties.isAllowed.example).toBe(true);
    expect(bootResponseSchema.properties.reason.example).toBe('mock app always allowed');
  });

  it('should match MockSystemInfo schema requirements', () => {
    const systemInfoSchema = openApiSpec.components.schemas.MockSystemInfo;
    
    expect(systemInfoSchema.required).toEqual([
      'status',
      'kmsContractAddr',
      'gatewayAppId',
      'chainId',
      'appAuthImplementation',
      'appImplementation',
      'note'
    ]);

    // Verify the note field is required (unique to mock)
    expect(systemInfoSchema.properties.note.example).toBe('this is a mock backend - all authentications will succeed');
  });
});

describe('Mock Behavior Verification', () => {
  it('should always return success regardless of input validity', async () => {
    // Test with completely bogus data
    const bogusBootInfo = {
      mrAggregated: 'invalid-data',
      osImageHash: 'also-invalid',
      appId: 'not-a-real-address',
      composeHash: 'fake-hash',
      instanceId: 'fake-instance',
      deviceId: 'fake-device',
      tcbStatus: 'COMPROMISED', // even compromised status
      advisoryIds: ['CRITICAL-001', 'CRITICAL-002'],
    };

    const appResponse = await appFetch(new Request('http://localhost:3002/bootAuth/app', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bogusBootInfo),
    }));

    const kmsResponse = await appFetch(new Request('http://localhost:3002/bootAuth/kms', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bogusBootInfo),
    }));

    const appData = await appResponse.json();
    const kmsData = await kmsResponse.json();

    // Both should return success
    expect(appData.isAllowed).toBe(true);
    expect(kmsData.isAllowed).toBe(true);
    expect(appData.reason).toBe('mock app always allowed');
    expect(kmsData.reason).toBe('mock KMS always allowed');
  });
}); 