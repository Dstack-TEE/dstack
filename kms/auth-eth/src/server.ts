import fastify, { FastifyInstance } from 'fastify';
import { EthereumBackend } from './ethereum';
import { BootInfo, BootResponse } from './types';
import { ethers } from 'ethers';

declare module 'fastify' {
  interface FastifyInstance {
    ethereum: EthereumBackend;
  }
}

export async function build(): Promise<FastifyInstance> {
  const server = fastify({
    logger: true
  });

  // Register schema for request/response validation
  server.addSchema({
    $id: 'bootInfo',
    type: 'object',
    required: ['mrAggregated', 'osImageHash', 'appId', 'composeHash', 'instanceId', 'deviceId'],
    properties: {
      mrAggregated: { type: 'string', description: 'Aggregated MR measurement' },
      osImageHash: { type: 'string', description: 'OS Image hash' },
      appId: { type: 'string', description: 'Application ID' },
      composeHash: { type: 'string', description: 'Compose hash' },
      instanceId: { type: 'string', description: 'Instance ID' },
      deviceId: { type: 'string', description: 'Device ID' }
    }
  });

  server.addSchema({
    $id: 'bootResponse',
    type: 'object',
    required: ['isAllowed', 'reason', 'gatewayAppId'],
    properties: {
      isAllowed: { type: 'boolean' },
      reason: { type: 'string' },
      gatewayAppId: { type: 'string' },
    }
  });

  // Initialize backend
  const rpcUrl = process.env.ETH_RPC_URL || 'http://localhost:8545';
  const kmsContractAddr = process.env.KMS_CONTRACT_ADDR || '0x0000000000000000000000000000000000000000';
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  server.decorate('ethereum', new EthereumBackend(provider, kmsContractAddr));

  server.get('/', async (request, reply) => {
    return {
      status: 'ok',
      kmsContractAddr: kmsContractAddr,
      gatewayAppId: await server.ethereum.getGatewayAppId(),
      chainId: await server.ethereum.getChainId(),
    };
  });

  // Define routes
  server.post<{
    Body: BootInfo;
    Reply: BootResponse;
  }>('/bootAuth/app', {
    schema: {
      body: { $ref: 'bootInfo#' },
      response: {
        200: { $ref: 'bootResponse#' }
      }
    }
  }, async (request, reply) => {
    try {
      return await server.ethereum.checkBoot(request.body, false);
    } catch (error) {
      console.error(error);
      reply.code(200).send({
        isAllowed: false,
        gatewayAppId: '',
        reason: `${error instanceof Error ? error.message : String(error)}`
      });
    }
  });

  server.post<{
    Body: BootInfo;
    Reply: BootResponse;
  }>('/bootAuth/kms', {
    schema: {
      body: { $ref: 'bootInfo#' },
      response: {
        200: { $ref: 'bootResponse#' }
      }
    }
  }, async (request, reply) => {
    try {
      return await server.ethereum.checkBoot(request.body, true);
    } catch (error) {
      console.error(error);
      reply.code(200).send({
        isAllowed: false,
        gatewayAppId: '',
        reason: `${error instanceof Error ? error.message : String(error)}`
      });
    }
  });

  return server;
}
