// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, unlinkSync, existsSync } from 'fs';
import app from './index';

const TEST_CONFIG_PATH = './test-auth-config.json';

const baseBootInfo = {
  mrAggregated: '0xabc123',
  osImageHash: '0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a',
  appId: '0xapp123',
  composeHash: '0xcompose456',
  instanceId: '0xinstance789',
  deviceId: '0xdevice999',
  tcbStatus: 'UpToDate',
  advisoryIds: [],
  mrSystem: ''
};

function writeTestConfig(config: object) {
  writeFileSync(TEST_CONFIG_PATH, JSON.stringify(config, null, 2));
}

describe('auth-simple', () => {
  beforeAll(() => {
    process.env.AUTH_CONFIG_PATH = TEST_CONFIG_PATH;
  });

  afterAll(() => {
    if (existsSync(TEST_CONFIG_PATH)) {
      unlinkSync(TEST_CONFIG_PATH);
    }
  });

  describe('GET /', () => {
    it('returns health check info', async () => {
      writeTestConfig({ gatewayAppId: '0xgateway' });

      const res = await app.fetch(new Request('http://localhost/', { method: 'GET' }));
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.status).toBe('ok');
      expect(json.gatewayAppId).toBe('0xgateway');
    });
  });

  describe('POST /bootAuth/kms', () => {
    it('allows KMS boot with valid config', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        kms: {
          mrAggregated: ['0xabc123'],
          devices: ['0xdevice999'],
          allowAnyDevice: false
        }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(true);
      expect(json.reason).toBe('');
    });

    it('rejects KMS boot with invalid TCB status', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        kms: { allowAnyDevice: true }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...baseBootInfo, tcbStatus: 'OutOfDate' })
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(false);
      expect(json.reason).toContain('TCB status');
    });

    it('rejects KMS boot with invalid OS image', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0xdifferentimage'],
        kms: { allowAnyDevice: true }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(false);
      expect(json.reason).toContain('OS image');
    });

    it('rejects KMS boot with invalid mrAggregated', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        kms: {
          mrAggregated: ['0xdifferentmr'],
          allowAnyDevice: true
        }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(false);
      expect(json.reason).toContain('MR');
    });

    it('allows KMS boot with allowAnyDevice', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        kms: {
          mrAggregated: ['0xabc123'],
          devices: ['0xotherdevice'],
          allowAnyDevice: true
        }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(true);
    });
  });

  describe('POST /bootAuth/app', () => {
    it('allows app boot with valid config', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        apps: {
          '0xapp123': {
            composeHashes: ['0xcompose456'],
            devices: ['0xdevice999'],
            allowAnyDevice: false
          }
        }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(true);
      expect(json.reason).toBe('');
    });

    it('rejects app boot with unregistered app', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        apps: {}
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(false);
      expect(json.reason).toContain('not registered');
    });

    it('rejects app boot with invalid compose hash', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        apps: {
          '0xapp123': {
            composeHashes: ['0xdifferenthash'],
            allowAnyDevice: true
          }
        }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(false);
      expect(json.reason).toContain('compose hash');
    });

    it('rejects app boot with invalid device', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        apps: {
          '0xapp123': {
            composeHashes: ['0xcompose456'],
            devices: ['0xotherdevice'],
            allowAnyDevice: false
          }
        }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(false);
      expect(json.reason).toContain('device');
    });

    it('allows app boot with allowAnyDevice', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        apps: {
          '0xapp123': {
            composeHashes: ['0xcompose456'],
            devices: [],
            allowAnyDevice: true
          }
        }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(true);
    });
  });

  describe('hex normalization', () => {
    it('handles uppercase hex', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1FBB0CF9CC6CFBF23D6B779776FABAD2C5403D643BADB9E5E238615E4960A78A'],
        apps: {
          '0xAPP123': {
            composeHashes: ['0xCOMPOSE456'],
            allowAnyDevice: true
          }
        }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(true);
    });

    it('handles hex without 0x prefix', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        apps: {
          'app123': {
            composeHashes: ['compose456'],
            allowAnyDevice: true
          }
        }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/app', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(true);
    });
  });
});
