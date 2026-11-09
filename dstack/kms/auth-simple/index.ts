// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { readFileSync, existsSync } from 'fs';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';

// zod schemas for validation - compatible with auth-eth implementation
const BootInfoSchema = z.object({
  teeVariant: z.string().optional().default(''),
  mrAggregated: z.string().describe('aggregated MR measurement'),
  osImageHash: z.string().describe('OS Image hash'),
  appId: z.string().describe('application ID'),
  composeHash: z.string().describe('compose hash'),
  instanceId: z.string().describe('instance ID'),
  deviceId: z.string().describe('device ID'),
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

const RootEpochSchema = z.object({
  caPubkey: z.string(),
  k256Pubkey: z.string()
});

// config schema
const AppConfigSchema = z.object({
  currentAppEpoch: z.number().int().min(0).max(0xffffffff).default(0),
  composeHashes: z.array(z.string()).default([]),
  devices: z.array(z.string()).default([]),
  allowAnyDevice: z.boolean().default(false)
});

const KmsConfigSchema = z.object({
  mrAggregated: z.array(z.string()).default([]),
  devices: z.array(z.string()).default([]),
  allowAnyDevice: z.boolean().default(false)
});

const AuthConfigSchema = z.object({
  gatewayAppId: z.string().default(''),
  // KMS expects these fields in the health check response
  kmsContractAddr: z.string().default('0x0000000000000000000000000000000000000000'),
  chainId: z.number().default(0),
  appImplementation: z.string().default('0x0000000000000000000000000000000000000000'),
  osImages: z.array(z.string()).default([]),
  // TDX and SEV-SNP production defaults remain strict: only UpToDate is
  // accepted unless operators explicitly allow another verifier-derived status.
  allowedTcbStatuses: z.array(z.string()).default(['UpToDate']),
  allowedAdvisoryIds: z.array(z.string()).default([]),
  kms: KmsConfigSchema.default({}),
  apps: z.record(z.string(), AppConfigSchema).default({}),
  // Root public keys of each KMS root epoch, indexed by epoch; append only.
  rootEpochs: z.array(RootEpochSchema).default([]),
  // The root epoch KMS instances serve; raise it once every node holds it.
  currentRootEpoch: z.number().int().min(0).default(0)
});

type BootInfo = z.infer<typeof BootInfoSchema>;
type BootResponse = z.infer<typeof BootResponseSchema>;
type AuthConfig = z.infer<typeof AuthConfigSchema>;
type AppConfig = z.infer<typeof AppConfigSchema>;

const bytesOf = (hex: string) => hexToBytes(hex.replace(/^0x/i, ''));

// The current root epoch and its chain hash, as DstackKms computes it:
// keccak256(previous || keccak256(caPubkey) || keccak256(k256Pubkey)),
// with a zero previous hash for epoch 0. Empty when no epoch is configured.
function currentRootEpoch(config: AuthConfig): { rootEpoch?: number; rootEpochHash?: string } {
  const current = config.currentRootEpoch;
  if (config.rootEpochs.length === 0 && current === 0) return {};
  if (current >= config.rootEpochs.length) {
    throw new Error('currentRootEpoch is not a configured root epoch');
  }
  let hash = new Uint8Array(32);
  for (const keys of config.rootEpochs.slice(0, current + 1)) {
    hash = keccak_256(concatBytes(
      hash, keccak_256(bytesOf(keys.caPubkey)), keccak_256(bytesOf(keys.k256Pubkey))
    ));
  }
  return { rootEpoch: current, rootEpochHash: '0x' + bytesToHex(hash) };
}

const normHash = (hash?: string) => hash?.toLowerCase().replace(/^0x/, '');

// Only a KMS serving the current root epoch, with the registered keys up to it,
// may authorize. A KMS that predates root epochs reports none and holds only
// epoch 0; KMS checks made while onboarding carry none and are not limited.
function rootEpochDenial(
  bootInfo: BootInfo,
  isKms: boolean,
  current: { rootEpoch?: number; rootEpochHash?: string }
): string | undefined {
  const currentEpoch = current.rootEpoch ?? 0;
  if (bootInfo.rootEpoch === undefined) {
    return isKms || currentEpoch === 0 ? undefined : `root epoch ${currentEpoch} is current, but the KMS reports none`;
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

// normalize hex string to lowercase with 0x prefix
function normalizeHex(hex: string): string {
  hex = hex.toLowerCase();
  if (!hex.startsWith('0x')) {
    hex = '0x' + hex;
  }
  return hex;
}

function findApp(config: AuthConfig, appId: string) {
  const normalized = normalizeHex(appId);
  return Object.entries(config.apps).find(([id]) => normalizeHex(id) === normalized)?.[1];
}

// config-based backend
class ConfigBackend {
  private getConfigPath(): string {
    return process.env.AUTH_CONFIG_PATH || './auth-config.json';
  }

  // A missing or invalid config fails every request rather than reading as an
  // empty policy, whose app epochs would silently fall back to zero.
  private loadConfig(): AuthConfig {
    const configPath = this.getConfigPath();
    if (!existsSync(configPath)) {
      throw new Error(`config file not found: ${configPath}`);
    }
    try {
      return AuthConfigSchema.parse(JSON.parse(readFileSync(configPath, 'utf-8')));
    } catch (error) {
      throw new Error(`failed to load config: ${error}`);
    }
  }

  /// The current epoch of a configured app; `undefined` for an unknown one.
  async getAppEpoch(appId: string): Promise<number | undefined> {
    return findApp(this.loadConfig(), appId)?.currentAppEpoch;
  }

  async checkAuthorization(appInfo: AuthorizationRequest, isKms: boolean) {
    const config = this.loadConfig();
    const current = currentRootEpoch(config);
    const appConfig = isKms ? undefined : findApp(config, appInfo.appId);
    const epoch = {
      currentAppEpoch: appConfig?.currentAppEpoch ?? 0,
      currentRootEpoch: current.rootEpoch ?? 0,
      currentRootEpochHash: current.rootEpochHash ?? '0x' + '00'.repeat(32),
    };
    const kmsOperation = ['kms_bootstrap', 'kms_serve', 'kms_export_keys', 'kms_import_keys'].includes(appInfo.operation);
    if (kmsOperation !== isKms) {
      return { isAllowed: false, rejectionReason: 'Invalid authorization operation', gatewayAppId: config.gatewayAppId, ...epoch };
    }
    if (current.rootEpoch === undefined && appInfo.operation !== 'kms_bootstrap') {
      return { isAllowed: false, rejectionReason: 'Root epoch not registered', gatewayAppId: config.gatewayAppId, ...epoch };
    }
    if (appInfo.requestedRootEpoch !== undefined && appInfo.requestedRootEpoch > (current.rootEpoch ?? 0)) {
      return { isAllowed: false, rejectionReason: 'Requested root epoch is not active', gatewayAppId: config.gatewayAppId, ...epoch };
    }
    if (appInfo.requestedAppEpoch !== undefined && appInfo.requestedAppEpoch > epoch.currentAppEpoch) {
      return { isAllowed: false, rejectionReason: 'Requested app epoch is not active', gatewayAppId: config.gatewayAppId, ...epoch };
    }
    const result = this.evaluateBoot(appInfo, isKms, config, appConfig);
    return { isAllowed: result.isAllowed, rejectionReason: result.reason, gatewayAppId: result.gatewayAppId, ...epoch };
  }

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    const config = this.loadConfig();
    const appConfig = isKms ? undefined : findApp(config, bootInfo.appId);
    if ((appConfig?.currentAppEpoch ?? 0) !== 0) {
      return { isAllowed: false, reason: 'App epoch requires epoch-aware authorization', gatewayAppId: config.gatewayAppId };
    }
    const response = this.evaluateBoot(bootInfo, isKms, config, appConfig);
    const epochDenial = response.isAllowed
      ? rootEpochDenial(bootInfo, isKms, currentRootEpoch(config))
      : undefined;
    return epochDenial ? { ...response, isAllowed: false, reason: epochDenial } : response;
  }

  private evaluateBoot(
    bootInfo: BootInfo, isKms: boolean, config: AuthConfig, appConfig: AppConfig | undefined
  ): BootResponse {
    const osImageHash = normalizeHex(bootInfo.osImageHash);
    const deviceId = normalizeHex(bootInfo.deviceId);

    // check TCB status
    const allowedTcbStatuses = config.allowedTcbStatuses;
    if (!allowedTcbStatuses.includes(bootInfo.tcbStatus)) {
      return {
        isAllowed: false,
        reason: 'TCB status is not allowed',
        gatewayAppId: config.gatewayAppId
      };
    }

    for (const advisoryId of bootInfo.advisoryIds) {
      if (!config.allowedAdvisoryIds.includes(advisoryId)) {
        return {
          isAllowed: false,
          reason: 'advisory ID is not allowed',
          gatewayAppId: config.gatewayAppId
        };
      }
    }

    // check OS image
    const allowedOsImages = config.osImages.map(normalizeHex);
    if (!allowedOsImages.includes(osImageHash)) {
      return {
        isAllowed: false,
        reason: 'OS image is not allowed',
        gatewayAppId: config.gatewayAppId
      };
    }

    if (isKms) {
      return this.checkKmsBoot(bootInfo, config, deviceId);
    } else {
      return this.checkAppBoot(bootInfo, config, deviceId, appConfig);
    }
  }

  private checkKmsBoot(bootInfo: BootInfo, config: AuthConfig, deviceId: string): BootResponse {
    const mrAggregated = normalizeHex(bootInfo.mrAggregated);

    // check aggregated MR
    const allowedMrs = config.kms.mrAggregated.map(normalizeHex);
    if (!allowedMrs.includes(mrAggregated)) {
      return {
        isAllowed: false,
        reason: 'aggregated MR not allowed',
        gatewayAppId: config.gatewayAppId
      };
    }

    // check device ID
    if (!config.kms.allowAnyDevice) {
      const allowedDevices = config.kms.devices.map(normalizeHex);
      if (!allowedDevices.includes(deviceId)) {
        return {
          isAllowed: false,
          reason: 'KMS is not allowed to boot on this device',
          gatewayAppId: config.gatewayAppId
        };
      }
    }

    return {
      isAllowed: true,
      reason: '',
      gatewayAppId: config.gatewayAppId
    };
  }

  private checkAppBoot(
    bootInfo: BootInfo, config: AuthConfig, deviceId: string, appConfig: AppConfig | undefined
  ): BootResponse {
    const composeHash = normalizeHex(bootInfo.composeHash);

    // check app exists
    if (!appConfig) {
      return {
        isAllowed: false,
        reason: 'app not registered',
        gatewayAppId: config.gatewayAppId
      };
    }

    // check compose hash
    const allowedHashes = appConfig.composeHashes.map(normalizeHex);
    if (!allowedHashes.includes(composeHash)) {
      return {
        isAllowed: false,
        reason: 'compose hash not allowed',
        gatewayAppId: config.gatewayAppId
      };
    }

    // check device ID
    if (!appConfig.allowAnyDevice) {
      const allowedDevices = appConfig.devices.map(normalizeHex);
      if (!allowedDevices.includes(deviceId)) {
        return {
          isAllowed: false,
          reason: 'app is not allowed to boot on this device',
          gatewayAppId: config.gatewayAppId
        };
      }
    }

    return {
      isAllowed: true,
      reason: '',
      gatewayAppId: config.gatewayAppId
    };
  }

  async getGatewayAppId(): Promise<string> {
    return this.loadConfig().gatewayAppId;
  }

  async getInfo(): Promise<{
    gatewayAppId: string;
    kmsContractAddr: string;
    chainId: number;
    appImplementation: string;
    rootEpoch?: number;
    rootEpochHash?: string;
  }> {
    const config = this.loadConfig();
    return {
      gatewayAppId: config.gatewayAppId,
      kmsContractAddr: config.kmsContractAddr,
      chainId: config.chainId,
      appImplementation: config.appImplementation,
      ...currentRootEpoch(config),
    };
  }
}

// initialize app
const app = new Hono();

// initialize backend
const backend = new ConfigBackend();

// health check and info endpoint
app.get('/', async (c) => {
  try {
    const info = await backend.getInfo();
    return c.json({
      status: 'ok',
      kmsContractAddr: info.kmsContractAddr,
      gatewayAppId: info.gatewayAppId,
      chainId: info.chainId,
      appAuthImplementation: info.appImplementation, // backward compat
      appImplementation: info.appImplementation,
      rootEpoch: info.rootEpoch,
      rootEpochHash: info.rootEpochHash,
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
  let currentAppEpoch;
  try {
    currentAppEpoch = await backend.getAppEpoch(appId);
  } catch (error) {
    console.error('app epoch lookup failed:', error);
    return c.json({ error: 'authorization backend unavailable' }, 503);
  }
  if (currentAppEpoch === undefined) return c.json({ error: 'unknown app' }, 404);
  return c.json({ currentAppEpoch });
});

for (const method of ['authorizeKms', 'authorizeApp'] as const) {
  app.post(`/${method}`, zValidator('json', AuthorizationRequestSchema), async (c) => {
    try {
      return c.json(await backend.checkAuthorization(c.req.valid('json'), method === 'authorizeKms'));
    } catch {
      console.error('authorization backend failed');
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
      console.log('app boot auth request:', {
        appId: bootInfo.appId,
        composeHash: bootInfo.composeHash,
        instanceId: bootInfo.instanceId,
      });

      const result = await backend.checkBoot(bootInfo, false);
      console.log('app boot auth result:', result);
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
      console.log('KMS boot auth request:', {
        osImageHash: bootInfo.osImageHash,
        mrAggregated: bootInfo.mrAggregated,
        instanceId: bootInfo.instanceId,
      });

      const result = await backend.checkBoot(bootInfo, true);
      console.log('KMS boot auth result:', result);
      return c.json(result);
    } catch (error) {
      console.error('error in KMS boot auth:', error);
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
const defaultConfigPath = process.env.AUTH_CONFIG_PATH || './auth-config.json';
console.log(`starting auth-simple server on port ${port}`);
console.log(`config path: ${defaultConfigPath}`);

// Bun defaults idleTimeout to 10s and closes the socket while a handler is
// still awaiting work. Stay above the KMS webhook timeout (60s). Bun max: 255.
export default {
  port,
  idleTimeout: 255,
  fetch: app.fetch,
};
