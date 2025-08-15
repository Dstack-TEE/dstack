// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';

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
  mrSystem: z.string().optional().default('')
});

const BootResponseSchema = z.object({
  isAllowed: z.boolean(),
  reason: z.string(),
  gatewayAppId: z.string()
});

type BootInfo = z.infer<typeof BootInfoSchema>;
type BootResponse = z.infer<typeof BootResponseSchema>;

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

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    // always return success for mock backend
    const reason = isKms ? 'mock KMS always allowed' : 'mock app always allowed';
    
    return {
      isAllowed: true,
      reason,
      gatewayAppId: this.mockGatewayAppId,
    };
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
      gatewayAppId: batch[0],
      chainId: batch[1],
      appAuthImplementation: batch[2], // NOTE: for backward compatibility
      appImplementation: batch[2],
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
console.log(`starting mock auth server on port ${port}`);
console.log('note: this is a mock backend - all authentications will succeed');

export default {
  port,
  fetch: app.fetch,
}; 