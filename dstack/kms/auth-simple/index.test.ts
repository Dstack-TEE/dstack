// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, unlinkSync, existsSync } from 'fs';
import app from './index';

const TEST_CONFIG_PATH = './test-auth-config.json';

const baseBootInfo = {
  teeVariant: 'dstack-tdx',
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
        kms: {
          mrAggregated: ['0xabc123'],
          allowAnyDevice: true
        }
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

    it('requires explicit opt-in for non-UpToDate SEV-SNP TCB status', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        kms: {
          mrAggregated: ['0xabc123'],
          devices: ['0xdevice999'],
          allowAnyDevice: false
        }
      });

      const sevSnpBootInfo = {
        ...baseBootInfo,
        teeVariant: 'dstack-amd-sev-snp',
        tcbStatus: 'OutOfDate'
      };
      const denied = await app.fetch(new Request('http://localhost/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sevSnpBootInfo)
      }));
      expect((await denied.json()).isAllowed).toBe(false);

      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        allowedTcbStatuses: ['OutOfDate'],
        kms: {
          mrAggregated: ['0xabc123'],
          devices: ['0xdevice999'],
          allowAnyDevice: false
        }
      });

      const allowed = await app.fetch(new Request('http://localhost/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sevSnpBootInfo)
      }));
      const allowedJson = await allowed.json();

      expect(allowedJson.isAllowed).toBe(true);
      expect(allowedJson.reason).toBe('');
    });

    it('rejects unallowlisted advisory IDs by default', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        kms: {
          mrAggregated: ['0xabc123'],
          allowAnyDevice: true
        }
      });

      const denied = await app.fetch(new Request('http://localhost/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...baseBootInfo, advisoryIds: ['INTEL-SA-TEST'] })
      }));
      const deniedJson = await denied.json();

      expect(deniedJson.isAllowed).toBe(false);
      expect(deniedJson.reason).toContain('advisory');

      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        allowedAdvisoryIds: ['INTEL-SA-TEST'],
        kms: {
          mrAggregated: ['0xabc123'],
          allowAnyDevice: true
        }
      });

      const allowed = await app.fetch(new Request('http://localhost/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...baseBootInfo, advisoryIds: ['INTEL-SA-TEST'] })
      }));
      const allowedJson = await allowed.json();

      expect(allowedJson.isAllowed).toBe(true);
    });

    it('rejects KMS boot with invalid OS image', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0xdifferentimage'],
        kms: {
          mrAggregated: ['0xabc123'],
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

    it('rejects KMS boot when the identity allowlist is empty', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        kms: {
          mrAggregated: [],
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
    it('rejects KMS boot with an empty device allowlist', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        kms: {
          mrAggregated: ['0xabc123'],
          devices: [],
          allowAnyDevice: false
        }
      });

      const res = await app.fetch(new Request('http://localhost/bootAuth/kms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(baseBootInfo)
      }));
      const json = await res.json();

      expect(json.isAllowed).toBe(false);
      expect(json.reason).toContain('device');
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

    it('rejects app boot with an empty device allowlist', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: ['0x1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a'],
        apps: {
          '0xapp123': {
            composeHashes: ['0xcompose456'],
            devices: [],
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

    // Stricter than a legacy DstackApp by design; see DstackApp.t.sol
    // test_IsAppAllowed_RejectsOutdatedTcbWhenRequired.
    it('rejects app boot with out-of-date TCB or unallowlisted advisory ID', async () => {
      writeTestConfig({
        gatewayAppId: '0xgateway',
        osImages: [baseBootInfo.osImageHash],
        apps: { '0xapp123': { composeHashes: ['0xcompose456'], allowAnyDevice: true } }
      });

      for (const [patch, reason] of [
        [{ tcbStatus: 'OutOfDate' }, 'TCB status is not allowed'],
        [{ advisoryIds: ['INTEL-SA-00614'] }, 'advisory ID is not allowed'],
      ] as const) {
        const res = await app.fetch(new Request('http://localhost/bootAuth/app', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...baseBootInfo, ...patch })
        }));
        const json = await res.json();
        expect(json.isAllowed).toBe(false);
        expect(json.reason).toBe(reason);
      }
    });
  });

  describe('root epochs', () => {
    const rootEpochs = [
      // Well-formed keys whose point bytes repeat one value.
      { caPubkey: '0x3059301306072a8648ce3d020106082a8648ce3d03010703420004' + 'a0'.repeat(64), k256Pubkey: '0x02' + 'b0'.repeat(32) },
      { caPubkey: '0x3059301306072a8648ce3d020106082a8648ce3d03010703420004' + 'a1'.repeat(64), k256Pubkey: '0x02' + 'b1'.repeat(32) }
    ];
    // Shared with the DstackKms contract tests.
    const h0 = '0x10ab6b6c8e7601901b0f1767985bf40d35bf3129e0866fe12dcc7c8f04a298f2';
    const h1 = '0x50152a82023f2219a31723b476c13bc5f608ab4147946dabdec15d4f3d648ed4';

    const config = {
      gatewayAppId: '0xgateway',
      osImages: [baseBootInfo.osImageHash],
      kms: { mrAggregated: [baseBootInfo.mrAggregated], allowAnyDevice: true },
      apps: { '0xapp123': { composeHashes: ['0xcompose456'], allowAnyDevice: true } },
      rootEpochs
    };
    const boot = async (path: string, fields: object) =>
      (await app.fetch(new Request(`http://localhost/bootAuth/${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...baseBootInfo, ...fields })
      }))).json();
    const info = async () =>
      (await app.fetch(new Request('http://localhost/', { method: 'GET' }))).json();

    const authorize = async (fields: object = {}, isKms = false) =>
      (await app.fetch(new Request(`http://localhost/${isKms ? 'authorizeKms' : 'authorizeApp'}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...baseBootInfo, ...fields }),
      }))).json();

    it('checks the requested policy and returns the epoch on rejection', async () => {
      const kmsContractAddr = '0x' + '11'.repeat(20);
      writeTestConfig({ ...config, kmsContractAddr, currentRootEpoch: 1 });
      expect(await authorize()).toMatchObject({
        isAllowed: true, rejectionReason: '', currentRootEpoch: 1, currentRootEpochHash: h1,
      });
      expect(await authorize({ requestedRootEpoch: 0 })).toMatchObject({ isAllowed: true, currentRootEpoch: 1 });
      expect(await authorize({ requestedRootEpoch: 1 })).toMatchObject({ isAllowed: true });
            expect(await authorize({ requestedAppEpoch: 1 })).toMatchObject({ isAllowed: false, rejectionReason: 'Requested app epoch must be zero', currentRootEpoch: 1 });
      expect(await authorize({ requestedAppEpoch: 0 })).toMatchObject({ isAllowed: true });
      expect(await authorize({ requestedRootEpoch: 2 })).toMatchObject({
        isAllowed: false, rejectionReason: 'Requested root epoch is not active', currentRootEpoch: 1, currentRootEpochHash: h1,
      });
      expect(await authorize({ appId: kmsContractAddr, composeHash: 'not-an-app-compose' }, true)).toMatchObject({ isAllowed: true });
      expect(await authorize({ appId: kmsContractAddr, mrAggregated: '0xbad' }, true)).toMatchObject({
        isAllowed: false, currentRootEpoch: 1, currentRootEpochHash: h1,
      });
      expect(await authorize({ appId: '0x' + '22'.repeat(20) })).toMatchObject({ isAllowed: false });
    });

    it('denies authorization without registered roots, while bootstrap remains available', async () => {
      writeTestConfig({ ...config, rootEpochs: [] });
      expect(await authorize()).toMatchObject({
        isAllowed: false, rejectionReason: 'Root epoch not registered',
        currentRootEpoch: 0, currentRootEpochHash: '0x' + '00'.repeat(32),
      });
      expect((await boot('kms', {})).isAllowed).toBe(true);
    });

    it('allows only a KMS serving the current root epoch', async () => {
      writeTestConfig(config);
      expect(await info()).toMatchObject({ rootEpoch: 0, rootEpochHash: h0 });
      expect((await boot('app', { rootEpoch: 0, rootEpochHash: h0 })).isAllowed).toBe(true);
      expect((await boot('app', {})).isAllowed).toBe(true);

      writeTestConfig({ ...config, currentRootEpoch: 1 });
      expect(await info()).toMatchObject({ rootEpoch: 1, rootEpochHash: h1 });
      expect((await boot('app', { rootEpoch: 1, rootEpochHash: h1 })).isAllowed).toBe(true);
      expect((await boot('app', { rootEpoch: 0, rootEpochHash: h0 })).reason).toMatch(/1 is current/);
      expect((await boot('app', { rootEpoch: 1, rootEpochHash: h0 })).reason).toMatch(/not the registered/);
      // A KMS predating root epochs is cut off; onboarding checks carry none.
      expect((await boot('app', {})).reason).toMatch(/reports none/);
      expect((await boot('kms', {})).isAllowed).toBe(true);
    });

    it.each([
      { currentRootEpoch: 1, rootEpochs: [] },
      { currentRootEpoch: 1, rootEpochs: undefined },
      { currentRootEpoch: 2, rootEpochs },
      { rootEpochs: [{ ...rootEpochs[0], caPubkey: '0xINVALID' }] },
      { rootEpochs: [{ ...rootEpochs[0], k256Pubkey: '0xINVALID' }] }
    ])('fails closed for invalid root epoch config %j', async (epochs) => {
      writeTestConfig({ ...config, ...epochs });
      const health = await app.fetch(new Request('http://localhost/'));
      expect(health.status).toBe(500);
      for (const path of ['app', 'kms']) {
        for (const fields of [{}, { rootEpoch: 0 }, { rootEpoch: 1 }]) {
          expect((await boot(path, fields)).isAllowed).toBe(false);
        }
      }
    });

    it('serves only epoch 0 when none is configured', async () => {
      writeTestConfig({ ...config, rootEpochs: [] });
      expect((await info()).rootEpoch).toBeUndefined();
      expect((await boot('app', { rootEpoch: 0, rootEpochHash: h0 })).isAllowed).toBe(true);
      expect((await boot('app', { rootEpoch: 1, rootEpochHash: h1 })).reason).toMatch(/not registered/);
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
