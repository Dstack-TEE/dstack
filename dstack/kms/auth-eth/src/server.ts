// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

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
  const hex = (bytes: number, description: string) => ({
    type: 'string',
    pattern: `^(?:0x[0-9a-fA-F]{0,${bytes * 2}}|[0-9a-fA-F]{0,${bytes * 2}})$`,
    description,
  });

  server.addSchema({
    $id: 'bootInfo',
    type: 'object',
    required: ['mrAggregated', 'osImageHash', 'appId', 'composeHash', 'instanceId', 'deviceId'],
    properties: {
      mrAggregated: hex(32, 'Aggregated MR measurement'),
      osImageHash: hex(32, 'OS Image hash'),
      appId: hex(20, 'Application ID'),
      composeHash: hex(32, 'Compose hash'),
      instanceId: hex(20, 'Instance ID'),
      deviceId: hex(32, 'Device ID'),
      tcbStatus: { type: 'string', maxLength: 128, default: '' },
      advisoryIds: { type: 'array', maxItems: 128, items: { type: 'string', maxLength: 256 }, default: [] },
      mrSystem: { ...hex(32, 'System MR measurement'), default: '' },
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

  const publicRpcEndpoint = (value: string): string => {
    try {
      const endpoint = new URL(value);
      return `${endpoint.protocol}//${endpoint.host}`;
    } catch {
      return 'configured';
    }
  };
  const backendUnavailable = 'authorization backend unavailable';
  const invalidRequest = { isAllowed: false, reason: 'invalid authorization request', gatewayAppId: '' };

  server.setErrorHandler((error, request, reply) => {
    if (typeof error === 'object' && error !== null && 'validation' in error) {
      return reply.code(400).send(invalidRequest);
    }
    request.log.error('authorization request failed');
    return reply.code(500).send({ status: 'error', message: backendUnavailable });
  });

  server.get('/', async (_request, reply) => {
    try {
      const batch = await Promise.all([
        server.ethereum.getGatewayAppId(),
        server.ethereum.getChainId(),
        server.ethereum.getAppImplementation(),
      ]);
      return {
        status: 'ok',
        kmsContractAddr: kmsContractAddr,
        ethRpcUrl: publicRpcEndpoint(rpcUrl),
        gatewayAppId: batch[0],
        chainId: batch[1],
        appAuthImplementation: batch[2], // NOTE: for backward compatibility
        appImplementation: batch[2],
      };
    } catch {
      _request.log.error('authorization backend health check failed');
      return reply.code(500).send({ status: 'error', message: backendUnavailable });
    }
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
      request.log.error('application authorization backend failed');
      reply.code(200).send({
        isAllowed: false,
        gatewayAppId: '',
        reason: backendUnavailable
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
      if (!(error instanceof Error && "Test backend error" == error.message)) {
        request.log.error('KMS authorization backend failed');
      }
      reply.code(200).send({
        isAllowed: false,
        gatewayAppId: '',
        reason: backendUnavailable
      });
    }
  });

  return server;
}
