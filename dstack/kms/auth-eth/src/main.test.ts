// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { FastifyInstance } from 'fastify';
import { ethers } from 'ethers';
import { build } from './server';
import { rootEpochDenial } from './ethereum';
import { BootInfo } from './types';

// Mock EthereumBackend
jest.mock('./ethereum', () => {
  return {
    ...jest.requireActual('./ethereum'),
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

    it('should reject oversized and non-hex measurements before backend use', async () => {
      jest.clearAllMocks();
      for (const mrAggregated of ['0x' + 'ab'.repeat(33), 'not-hex']) {
        const response = await app.inject({
          method: 'POST',
          url: '/bootAuth/app',
          payload: { ...mockBootInfo, mrAggregated }
        });
        expect(response.statusCode).toBe(400);
        expect(JSON.parse(response.payload)).toEqual({ isAllowed: false, reason: 'invalid authorization request', gatewayAppId: '' });
      }
      expect(app.ethereum.checkBoot).not.toHaveBeenCalled();
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

  describe('POST /checkAuthorization', () => {
    it('preserves the complete decision, including the epoch on rejection', async () => {
      const decision = {
        isAllowed: false, rejectReason: 'App not registered', gatewayAppId: 'gateway',
        currentRootEpoch: 1, currentRootEpochHash: '0x' + '11'.repeat(32),
      };
      app.ethereum.checkAuthorization = jest.fn().mockResolvedValue(decision);
      const response = await app.inject({ method: 'POST', url: '/checkAuthorization', payload: mockBootInfo });
      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.payload)).toEqual(decision);
      expect(app.ethereum.checkAuthorization).toHaveBeenCalledWith(mockBootInfo);
    });

    it('fails closed when the new contract method is unavailable', async () => {
      jest.clearAllMocks();
      app.ethereum.checkAuthorization = jest.fn().mockRejectedValue(new Error('missing contract method'));
      const response = await app.inject({ method: 'POST', url: '/checkAuthorization', payload: mockBootInfo });
      expect(response.statusCode).toBe(500);
      expect(app.ethereum.checkBoot).not.toHaveBeenCalled();
    });
  });

  describe('key epochs', () => {
    it('should pass the KMS root epoch through to the backend', async () => {
      const mockCheckBoot = jest.fn().mockResolvedValue({ isAllowed: true, reason: '', gatewayAppId: '' });
      app.ethereum.checkBoot = mockCheckBoot;
      const rootEpoch = { rootEpoch: 1, rootEpochHash: '0x' + '11'.repeat(32) };

      const response = await app.inject({
        method: 'POST',
        url: '/bootAuth/app',
        payload: { ...mockBootInfo, ...rootEpoch }
      });

      expect(response.statusCode).toBe(200);
      expect(mockCheckBoot).toHaveBeenCalledWith(expect.objectContaining(rootEpoch), false);
    });

    it('should allow only a KMS serving the current root epoch', () => {
      const hash = '0x' + '11'.repeat(32);
      const current = { rootEpoch: 1, rootEpochHash: hash };
      const info = (fields: object) => ({ ...mockBootInfo, ...fields });

      expect(rootEpochDenial(info({ rootEpoch: 1, rootEpochHash: hash.toUpperCase().replace('0X', '') }), false, current)).toBeUndefined();
      expect(rootEpochDenial(info({ rootEpoch: 0, rootEpochHash: hash }), false, current)).toMatch(/1 is current/);
      expect(rootEpochDenial(info({ rootEpoch: 1, rootEpochHash: '0x' + '22'.repeat(32) }), false, current)).toMatch(/not the registered/);
      // A KMS predating root epochs is cut off once a rotation is current.
      expect(rootEpochDenial(info({}), false, current)).toMatch(/reports none/);
      expect(rootEpochDenial(info({}), false, { rootEpoch: 0, rootEpochHash: hash })).toBeUndefined();
      expect(rootEpochDenial(info({}), true, current)).toBeUndefined();
      // Nothing registered: only epoch 0 serves.
      expect(rootEpochDenial(info({ rootEpoch: 0, rootEpochHash: hash }), false, {})).toBeUndefined();
      expect(rootEpochDenial(info({ rootEpoch: 1, rootEpochHash: hash }), false, {})).toMatch(/not registered/);
    });

    it('should list registered key epochs in the info response', async () => {
      const rootEpoch = { rootEpoch: 1, rootEpochHash: '0x' + '11'.repeat(32) };
      Object.assign(app.ethereum, {
        getGatewayAppId: jest.fn().mockResolvedValue('gw'),
        getChainId: jest.fn().mockResolvedValue(1),
        getAppImplementation: jest.fn().mockResolvedValue('0x00'),
        getRootEpoch: jest.fn().mockResolvedValue(rootEpoch),
      });

      const response = await app.inject({ method: 'GET', url: '/' });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.payload)).toMatchObject(rootEpoch);
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
      expect(result.reason).toBe('authorization backend unavailable');
    });
  });
});

describe('Ethereum root epoch registry', () => {
  const { EthereumBackend } = jest.requireActual<typeof import('./ethereum')>('./ethereum');
  const abi = new ethers.Interface([
    'function rootEpochCount() view returns (uint256)',
    'function currentRootEpoch() view returns (uint256, bytes32)',
    'function gatewayAppId() view returns (string)',
    'function appImplementation() view returns (address)',
  ]);
  const hash = '0x' + '11'.repeat(32);
  const bootInfo = {
    mrAggregated: '11'.repeat(32), osImageHash: '22'.repeat(32),
    appId: '33'.repeat(20), composeHash: '44'.repeat(32),
    instanceId: '55'.repeat(20), deviceId: '66'.repeat(32),
  };
  const getBlockNumber = jest.fn();
  const call = jest.fn();
  let app: FastifyInstance;
  let count: bigint;
  let epoch: bigint;

  beforeAll(async () => {
    app = await build();
    app.ethereum = new EthereumBackend({
      getBlockNumber, call, getNetwork: async () => ({ chainId: 1337n }),
    } as unknown as ethers.JsonRpcProvider,
      '0x' + '11'.repeat(20));
  });
  afterAll(async () => { await app.close(); });
  beforeEach(() => {
    jest.clearAllMocks();
    count = 2n;
    epoch = 1n;
    getBlockNumber.mockResolvedValue(100);
    call.mockImplementation(async (tx: ethers.TransactionRequest) => {
      const fn = abi.getFunction(tx.data!.slice(0, 10));
      switch (fn?.name) {
        case 'rootEpochCount': return abi.encodeFunctionResult(fn, [count]);
        case 'currentRootEpoch': return abi.encodeFunctionResult(fn, [epoch, hash]);
        case 'gatewayAppId': return abi.encodeFunctionResult(fn, ['gateway-app']);
        case 'appImplementation': return abi.encodeFunctionResult(fn, ['0x' + '11'.repeat(20)]);
        default: return ethers.AbiCoder.defaultAbiCoder().encode(['bool', 'string'], [true, '']);
      }
    });
  });
  const boot = async (path: string, fields = {}) => {
    const response = await app.inject({
      method: 'POST', url: `/bootAuth/${path}`, payload: { ...bootInfo, ...fields },
    });
    expect(response.statusCode).toBe(200);
    return response.json();
  };
  const registryCalls = () => call.mock.calls.map(([tx]) => ({
    name: abi.getFunction(tx.data.slice(0, 10))?.name, blockTag: tx.blockTag,
  })).filter(({ name }) => name === 'rootEpochCount' || name === 'currentRootEpoch');

  it('supports an upgraded empty registry without querying the current epoch', async () => {
    count = 0n;
    expect((await boot('app')).isAllowed).toBe(true);
    expect((await boot('kms')).isAllowed).toBe(true);
    expect((await boot('app', { rootEpoch: 0, rootEpochHash: hash })).isAllowed).toBe(true);
    expect((await boot('app', { rootEpoch: 1, rootEpochHash: hash })).reason).toMatch(/not registered/);
    expect(await app.ethereum.getRootEpoch()).toEqual({});
    expect(registryCalls().every(({ name }) => name === 'rootEpochCount')).toBe(true);
  });

  it('allows old KMS app requests only through epoch 0 while preserving onboarding', async () => {
    count = 1n;
    epoch = 0n;
    expect((await boot('app')).isAllowed).toBe(true);
    count = 2n;
    epoch = 1n;
    expect((await boot('app')).reason).toMatch(/reports none/);
    expect((await boot('kms')).isAllowed).toBe(true);
  });

  it.each(['app', 'info'])('pins both registry reads to the same block for %s', async (endpoint) => {
    if (endpoint === 'app') {
      expect((await boot('app', { rootEpoch: 1, rootEpochHash: hash })).isAllowed).toBe(true);
      expect(call.mock.calls.every(([tx]) => tx.blockTag === 100)).toBe(true);
    } else {
      const response = await app.inject({ method: 'GET', url: '/' });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ rootEpoch: 1, rootEpochHash: hash });
    }
    expect(registryCalls()).toEqual([
      { name: 'rootEpochCount', blockTag: 100 },
      { name: 'currentRootEpoch', blockTag: 100 },
    ]);
    expect(getBlockNumber).toHaveBeenCalledTimes(1);
  });

  describe.each(['rootEpochCount', 'currentRootEpoch'])('%s failures', (getter) => {
    it.each(['missing getter', 'revert', 'RPC failure', 'malformed ABI data'])('fails closed on %s', async (failure) => {
      const normalCall = call.getMockImplementation()!;
      call.mockImplementation(async (tx: ethers.TransactionRequest) => {
        if (abi.getFunction(tx.data!.slice(0, 10))?.name !== getter) return normalCall(tx);
        if (failure === 'missing getter') return '0x';
        if (failure === 'malformed ABI data') return '0x1234';
        if (failure === 'revert') {
          throw ethers.AbiCoder.getBuiltinCallException('call', {
            to: '0x' + '11'.repeat(20), data: tx.data!,
          }, '0x');
        }
        throw new Error('RPC unavailable');
      });
      for (const path of ['app', 'kms']) {
        expect(await boot(path)).toEqual({
          isAllowed: false, reason: 'authorization backend unavailable', gatewayAppId: '',
        });
        expect((await boot(path, { rootEpoch: 0, rootEpochHash: hash })).isAllowed).toBe(false);
      }
      const info = await app.inject({ method: 'GET', url: '/' });
      expect(info.statusCode).toBe(500);
    });
  });
});
