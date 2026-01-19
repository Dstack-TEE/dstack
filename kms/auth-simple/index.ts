// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { readFileSync, existsSync } from 'fs';

// zod schemas for validation - compatible with auth-eth implementation
const BootInfoSchema = z.object({
  mrAggregated: z.string().describe('aggregated MR measurement'),
  osImageHash: z.string().describe('OS Image hash'),
  appId: z.string().describe('application ID'),
  composeHash: z.string().describe('compose hash'),
  instanceId: z.string().describe('instance ID'),
  deviceId: z.string().describe('device ID'),
  tcbStatus: z.string().optional().default(''),
  advisoryIds: z.array(z.string()).optional().default([]),
  mrSystem: z.string().optional().default('')
});

const BootResponseSchema = z.object({
  isAllowed: z.boolean(),
  reason: z.string(),
  gatewayAppId: z.string()
});

// config schema
const AppConfigSchema = z.object({
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
  kms: KmsConfigSchema.default({}),
  apps: z.record(z.string(), AppConfigSchema).default({})
});

type BootInfo = z.infer<typeof BootInfoSchema>;
type BootResponse = z.infer<typeof BootResponseSchema>;
type AuthConfig = z.infer<typeof AuthConfigSchema>;

// normalize hex string to lowercase with 0x prefix
function normalizeHex(hex: string): string {
  hex = hex.toLowerCase();
  if (!hex.startsWith('0x')) {
    hex = '0x' + hex;
  }
  return hex;
}

// config-based backend
class ConfigBackend {
  private getConfigPath(): string {
    return process.env.AUTH_CONFIG_PATH || './auth-config.json';
  }

  private loadConfig(): AuthConfig {
    const configPath = this.getConfigPath();
    if (!existsSync(configPath)) {
      console.error(`config file not found: ${configPath}`);
      return AuthConfigSchema.parse({});
    }

    try {
      const content = readFileSync(configPath, 'utf-8');
      const parsed = JSON.parse(content);
      return AuthConfigSchema.parse(parsed);
    } catch (error) {
      console.error(`failed to load config: ${error}`);
      return AuthConfigSchema.parse({});
    }
  }

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    const config = this.loadConfig();
    const osImageHash = normalizeHex(bootInfo.osImageHash);
    const deviceId = normalizeHex(bootInfo.deviceId);

    // check TCB status
    if (bootInfo.tcbStatus !== 'UpToDate') {
      return {
        isAllowed: false,
        reason: 'TCB status is not up to date',
        gatewayAppId: config.gatewayAppId
      };
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
      return this.checkAppBoot(bootInfo, config, deviceId);
    }
  }

  private checkKmsBoot(bootInfo: BootInfo, config: AuthConfig, deviceId: string): BootResponse {
    const mrAggregated = normalizeHex(bootInfo.mrAggregated);

    // check aggregated MR
    const allowedMrs = config.kms.mrAggregated.map(normalizeHex);
    if (allowedMrs.length > 0 && !allowedMrs.includes(mrAggregated)) {
      return {
        isAllowed: false,
        reason: 'aggregated MR not allowed',
        gatewayAppId: config.gatewayAppId
      };
    }

    // check device ID
    if (!config.kms.allowAnyDevice) {
      const allowedDevices = config.kms.devices.map(normalizeHex);
      if (allowedDevices.length > 0 && !allowedDevices.includes(deviceId)) {
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

  private checkAppBoot(bootInfo: BootInfo, config: AuthConfig, deviceId: string): BootResponse {
    const appId = normalizeHex(bootInfo.appId);
    const composeHash = normalizeHex(bootInfo.composeHash);

    // check app exists
    const appConfig = Object.entries(config.apps).find(
      ([id]) => normalizeHex(id) === appId
    )?.[1];

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
      if (allowedDevices.length > 0 && !allowedDevices.includes(deviceId)) {
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
  }> {
    const config = this.loadConfig();
    return {
      gatewayAppId: config.gatewayAppId,
      kmsContractAddr: config.kmsContractAddr,
      chainId: config.chainId,
      appImplementation: config.appImplementation,
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
    });
  } catch (error) {
    console.error('error in health check:', error);
    return c.json({
      status: 'error',
      message: error instanceof Error ? error.message : String(error)
    }, 500);
  }
});

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

export default {
  port,
  fetch: app.fetch,
};
