// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';

if (process.env.NODE_ENV === 'production') {
  throw new Error('auth-mock must not run with NODE_ENV=production');
}

// zod schemas for validation - compatible with original fastify implementation
const BootInfoSchema = z.object({
  // required fields (matching original fastify schema)
  mrAggregated: z.string().describe('aggregated MR measurement'),
  osImageHash: z.string().describe('OS Image hash'),
  appId: z.string().describe('application ID'),
  composeHash: z.string().describe('compose hash'),
  instanceId: z.string().describe('instance ID'),
  deviceId: z.string().describe('device ID'),
  // optional fields (for full compatibility with BootInfo interface)
  tcbStatus: z.string().optional().default(''),
  advisoryIds: z.array(z.string()).optional().default([]),
  mrSystem: z.string().optional().default(''),
  // The root epoch the asking KMS serves and its chain hash; absent from a KMS
  // that predates root epochs, and from KMS checks made while onboarding.
  rootEpoch: z.number().int().min(0).optional(),
  rootEpochHash: z.string().optional()
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

// MOCK_ROOT_EPOCH and MOCK_ROOT_EPOCH_HASH: the current KMS root epoch and its
// chain hash; both unset means none is registered
function getRootEpoch(): { rootEpoch?: number; rootEpochHash?: string } {
  const epoch = process.env.MOCK_ROOT_EPOCH;
  const hash = process.env.MOCK_ROOT_EPOCH_HASH;
  if (!epoch && !hash) return {};
  if (!epoch || !hash) throw new Error('set both MOCK_ROOT_EPOCH and MOCK_ROOT_EPOCH_HASH');
  return { rootEpoch: z.coerce.number().int().min(0).parse(epoch), rootEpochHash: hash };
}

type BootInfo = z.infer<typeof BootInfoSchema>;
type BootResponse = z.infer<typeof BootResponseSchema>;

const normHash = (hash?: string) => hash?.toLowerCase().replace(/^0x/, '');

// Only a KMS serving the current root epoch, with the registered keys up to it,
// may authorize. A KMS that predates root epochs reports none and holds only
// epoch 0, so it is served only until another epoch is activated.
function rootEpochDenial(bootInfo: BootInfo): string | undefined {
  const current = getRootEpoch();
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

// authorization policy - configurable via environment variables
// MOCK_POLICY: "allow-all" (default), "deny-kms", "deny-app", "deny-all",
//              "allowlist-device", "allowlist-mr"
// MOCK_ALLOWED_DEVICE_IDS: comma-separated device IDs (for allowlist-device policy)
// MOCK_ALLOWED_MR_AGGREGATED: comma-separated MR aggregated values (for allowlist-mr policy)

type MockPolicy = 'allow-all' | 'deny-kms' | 'deny-app' | 'deny-all' | 'allowlist-device' | 'allowlist-mr';

function getPolicy(): MockPolicy {
  const policy = process.env.MOCK_POLICY || 'allow-all';
  const valid: MockPolicy[] = ['allow-all', 'deny-kms', 'deny-app', 'deny-all', 'allowlist-device', 'allowlist-mr'];
  if (!valid.includes(policy as MockPolicy)) {
    throw new Error(`unknown MOCK_POLICY "${policy}"`);
  }
  return policy as MockPolicy;
}

function parseList(envVar: string): Set<string> {
  const raw = process.env[envVar] || '';
  return new Set(raw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean));
}

// mock backend class - no blockchain interaction
class MockBackend {
  private mockGatewayAppId: string;
  private mockChainId: number;
  private mockAppImplementation: string;

  constructor() {
    // mock values - configurable via environment variables
    this.mockGatewayAppId = process.env.MOCK_GATEWAY_APP_ID || '0xmockgateway1234567890123456789012345678';
    this.mockChainId = parseInt(process.env.MOCK_CHAIN_ID || '1337');
    this.mockAppImplementation = process.env.MOCK_APP_IMPLEMENTATION || '0xmockapp9876543210987654321098765432109';
  }

  async getAppEpoch(_appId: string): Promise<number> {
    return z.coerce.number().int().min(0).max(0xffffffff).parse(process.env.MOCK_APP_EPOCH ?? 0);
  }

  async checkAuthorization(appInfo: AuthorizationRequest, isKms: boolean) {
    const current = getRootEpoch();
    const epoch = {
      currentAppEpoch: isKms ? 0 : await this.getAppEpoch(appInfo.appId),
      currentRootEpoch: current.rootEpoch ?? 0,
      currentRootEpochHash: current.rootEpochHash ?? '0x' + '00'.repeat(32),
    };
    const kmsOperation = ['kms_bootstrap', 'kms_serve', 'kms_export_keys', 'kms_import_keys'].includes(appInfo.operation);
    if (kmsOperation !== isKms) {
      return { isAllowed: false, rejectionReason: 'Invalid authorization operation', gatewayAppId: this.mockGatewayAppId, ...epoch };
    }
    if (current.rootEpoch === undefined && appInfo.operation !== 'kms_bootstrap') {
      return { isAllowed: false, rejectionReason: 'Root epoch not registered', gatewayAppId: this.mockGatewayAppId, ...epoch };
    }
    if (appInfo.requestedRootEpoch !== undefined && appInfo.requestedRootEpoch > (current.rootEpoch ?? 0)) {
      return { isAllowed: false, rejectionReason: 'Requested root epoch is not active', gatewayAppId: this.mockGatewayAppId, ...epoch };
    }
    if (appInfo.requestedAppEpoch !== undefined && appInfo.requestedAppEpoch > epoch.currentAppEpoch) {
      return { isAllowed: false, rejectionReason: 'Requested app epoch is not active', gatewayAppId: this.mockGatewayAppId, ...epoch };
    }
    const result = this.evaluateBoot(appInfo, isKms);
    return { isAllowed: result.isAllowed, rejectionReason: result.isAllowed ? '' : result.reason,
      gatewayAppId: this.mockGatewayAppId, ...epoch };
  }

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    if (!isKms && await this.getAppEpoch(bootInfo.appId) !== 0) {
      return { isAllowed: false, reason: "App epoch requires epoch-aware authorization", gatewayAppId: "" };
    }
    const response = this.evaluateBoot(bootInfo, isKms);
    const epochDenial = response.isAllowed ? rootEpochDenial(bootInfo) : undefined;
    return epochDenial ? { isAllowed: false, reason: epochDenial, gatewayAppId: '' } : response;
  }

  private evaluateBoot(bootInfo: BootInfo, isKms: boolean): BootResponse {
    const policy = getPolicy();
    const deny = (reason: string): BootResponse => ({
      isAllowed: false,
      reason,
      gatewayAppId: '',
    });
    const allow = (reason: string): BootResponse => ({
      isAllowed: true,
      reason,
      gatewayAppId: this.mockGatewayAppId,
    });

    switch (policy) {
      case 'deny-all':
        return deny(`mock policy: deny-all`);
      case 'deny-kms':
        if (isKms) return deny(`mock policy: deny-kms`);
        return allow('mock app allowed (deny-kms policy)');
      case 'deny-app':
        if (!isKms) return deny(`mock policy: deny-app`);
        return allow('mock KMS allowed (deny-app policy)');
      case 'allowlist-device': {
        const allowed = parseList('MOCK_ALLOWED_DEVICE_IDS');
        const deviceId = bootInfo.deviceId.toLowerCase().replace(/^0x/, '');
        if (allowed.size === 0) return deny('mock policy: allowlist-device with empty list');
        if (!allowed.has(deviceId)) return deny(`mock policy: device ${bootInfo.deviceId} not in allowlist`);
        return allow(`mock policy: device ${bootInfo.deviceId} allowed`);
      }
      case 'allowlist-mr': {
        const allowed = parseList('MOCK_ALLOWED_MR_AGGREGATED');
        const mr = bootInfo.mrAggregated.toLowerCase().replace(/^0x/, '');
        if (allowed.size === 0) return deny('mock policy: allowlist-mr with empty list');
        if (!allowed.has(mr)) return deny(`mock policy: mrAggregated ${bootInfo.mrAggregated} not in allowlist`);
        return allow(`mock policy: mrAggregated ${bootInfo.mrAggregated} allowed`);
      }
      case 'allow-all':
      default:
        return allow(isKms ? 'mock KMS always allowed' : 'mock app always allowed');
    }
  }

  async getGatewayAppId(): Promise<string> {
    return this.mockGatewayAppId;
  }

  async getChainId(): Promise<number> {
    return this.mockChainId;
  }

  async getAppImplementation(): Promise<string> {
    return this.mockAppImplementation;
  }
}

// initialize app
const app = new Hono();

// initialize mock backend
const mockBackend = new MockBackend();

// health check and info endpoint
app.get('/', async (c) => {
  try {
    const batch = await Promise.all([
      mockBackend.getGatewayAppId(),
      mockBackend.getChainId(),
      mockBackend.getAppImplementation(),
    ]);

    return c.json({
      status: 'ok',
      kmsContractAddr: process.env.KMS_CONTRACT_ADDR || '0xmockcontract1234567890123456789012345678',
      ethRpcUrl: process.env.ETH_RPC_URL || '',
      gatewayAppId: batch[0],
      chainId: batch[1],
      appAuthImplementation: batch[2], // NOTE: for backward compatibility
      appImplementation: batch[2],
      ...getRootEpoch(),
      note: 'this is a mock backend - all authentications will succeed'
    });
  } catch (error) {
    console.error('error in health check:', error);
    return c.json({
      status: 'error',
      message: error instanceof Error ? error.message : String(error)
    }, 500);
  }
});

app.get('/app/:appId', async (c) => {
  const appId = c.req.param('appId');
  if (!/^0x[0-9a-fA-F]{40}$/.test(appId)) return c.json({ error: 'invalid app ID' }, 400);
  try {
    return c.json({ currentAppEpoch: await mockBackend.getAppEpoch(appId) });
  } catch {
    return c.json({ error: 'authorization backend unavailable' }, 503);
  }
});

for (const method of ['authorizeKms', 'authorizeApp'] as const) {
  app.post(`/${method}`, zValidator('json', AuthorizationRequestSchema), async (c) => {
    try {
      return c.json(await mockBackend.checkAuthorization(c.req.valid('json'), method === 'authorizeKms'));
    } catch {
      return c.json({ status: 'error', message: 'authorization backend unavailable' }, 503);
    }
  });
}

// app boot authentication
app.post('/bootAuth/app',
  zValidator('json', BootInfoSchema),
  async (c) => {
    try {
      const bootInfo = c.req.valid('json');
      console.log('mock app boot auth request:', {
        appId: bootInfo.appId,
        instanceId: bootInfo.instanceId,
        note: 'always returning success'
      });

      const result = await mockBackend.checkBoot(bootInfo, false);
      return c.json(result);
    } catch (error) {
      console.error('error in app boot auth:', error);
      return c.json({
        isAllowed: false,
        gatewayAppId: '',
        reason: error instanceof Error ? error.message : String(error)
      });
    }
  }
);

// KMS boot authentication
app.post('/bootAuth/kms',
  zValidator('json', BootInfoSchema),
  async (c) => {
    try {
      const bootInfo = c.req.valid('json');
      console.log('mock KMS boot auth request:', {
        appId: bootInfo.appId,
        instanceId: bootInfo.instanceId,
        note: 'always returning success'
      });

      const result = await mockBackend.checkBoot(bootInfo, true);
      return c.json(result);
    } catch (error) {
      // don't log test backend errors (keeping compatibility with original)
      if (!(error instanceof Error && "Test backend error" === error.message)) {
        console.error('error in KMS boot auth:', error);
      }
      return c.json({
        isAllowed: false,
        gatewayAppId: '',
        reason: error instanceof Error ? error.message : String(error)
      });
    }
  }
);

// start server
const port = parseInt(process.env.PORT || '3000');
const policy = getPolicy();
console.log(`starting mock auth server on port ${port} (policy: ${policy})`);

// Bun defaults idleTimeout to 10s and closes the socket while a handler is
// still awaiting work. Stay above the KMS webhook timeout (60s). Bun max: 255.
export default {
  port,
  idleTimeout: 255,
  fetch: app.fetch,
};
