// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { FastifyInstance } from 'fastify';
import { ethers } from 'ethers';
import { build } from './server';
import { DSTACK_KMS_ABI, parseBlockTag, rootEpochDenial } from './ethereum';
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

  describe('POST /authorizeApp', () => {
    const appRequest = { ...mockBootInfo, operation: 'app_get_key', requestedAppEpoch: 0 };
    it('preserves the complete decision, including the epoch on rejection', async () => {
      const decision = {
        authorized: false, rejectionReason: 'App not registered', gatewayAppId: 'gateway',
        currentAppEpoch: 0, currentRootEpoch: 1, currentRootEpochHash: '0x' + '11'.repeat(32),
        latestRootEpoch: 2, latestRootEpochHash: '0x' + '22'.repeat(32),
      };
      app.ethereum.checkAuthorization = jest.fn().mockResolvedValue(decision);
      const response = await app.inject({ method: 'POST', url: '/authorizeApp', payload: appRequest });
      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.payload)).toEqual(decision);
      expect(app.ethereum.checkAuthorization).toHaveBeenCalledWith(appRequest, 'authorizeApp');
      await app.inject({ method: 'POST', url: '/authorizeKms', payload: appRequest });
      expect(app.ethereum.checkAuthorization).toHaveBeenLastCalledWith(appRequest, 'authorizeKms');
      await app.inject({ method: 'POST', url: '/authorizeApp', payload: { ...appRequest, requestedRootEpoch: 0 } });
      expect(app.ethereum.checkAuthorization).toHaveBeenLastCalledWith({ ...appRequest, requestedRootEpoch: 0 }, 'authorizeApp');
    });

    it('rejects invalid, malformed and oversized requests in the AuthorizationResult shape', async () => {
      jest.clearAllMocks();
      app.ethereum.checkAuthorization = jest.fn();
      const rejection = {
        authorized: false, rejectionReason: 'invalid authorization request', gatewayAppId: '',
        currentRootEpoch: 0, currentRootEpochHash: '0x' + '00'.repeat(32), currentAppEpoch: 0,
        latestRootEpoch: 0, latestRootEpochHash: '0x' + '00'.repeat(32),
      };
      const requests = [
        { status: 400, payload: JSON.stringify({ ...appRequest, operation: 'unknown' }) },
        { status: 400, payload: JSON.stringify({ ...appRequest, mrAggregated: 'not-hex' }) },
        { status: 400, payload: '{"appId":' },
        { status: 413, payload: JSON.stringify({ ...appRequest, padding: 'a'.repeat(2 * 1024 * 1024) }) },
      ];
      for (const url of ['/authorizeApp', '/authorizeKms']) {
        for (const { status, payload } of requests) {
          const response = await app.inject({
            method: 'POST', url, payload, headers: { 'content-type': 'application/json' },
          });
          expect(response.statusCode).toBe(status);
          expect(JSON.parse(response.payload)).toEqual(rejection);
        }
      }
      expect(app.ethereum.checkAuthorization).not.toHaveBeenCalled();
    });

    it('fails closed when the new contract method is unavailable', async () => {
      jest.clearAllMocks();
      app.ethereum.checkAuthorization = jest.fn().mockRejectedValue(new Error('missing contract method'));
      const response = await app.inject({ method: 'POST', url: '/authorizeApp', payload: appRequest });
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

      expect(rootEpochDenial(info({ rootEpoch: 1, rootEpochHash: hash.toUpperCase().replace('0X', '') }), current)).toBeUndefined();
      expect(rootEpochDenial(info({ rootEpoch: 0, rootEpochHash: hash }), current)).toMatch(/1 is current/);
      expect(rootEpochDenial(info({ rootEpoch: 1, rootEpochHash: '0x' + '22'.repeat(32) }), current)).toMatch(/not the registered/);
      // A KMS or app request predating root epochs is cut off once a rotation is current.
      expect(rootEpochDenial(info({}), current)).toMatch(/reports none/);
      expect(rootEpochDenial(info({}), { rootEpoch: 0, rootEpochHash: hash })).toBeUndefined();
      // Nothing registered: only epoch 0 serves.
      expect(rootEpochDenial(info({ rootEpoch: 0, rootEpochHash: hash }), {})).toBeUndefined();
      expect(rootEpochDenial(info({ rootEpoch: 1, rootEpochHash: hash }), {})).toMatch(/not registered/);
    });

    it('should list registered key epochs in the info response', async () => {
      const rootEpoch = { rootEpoch: 1, rootEpochHash: '0x' + '11'.repeat(32) };
      Object.assign(app.ethereum, {
        resolveBlock: jest.fn().mockResolvedValue(100),
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
  const getBlock = jest.fn();
  const call = jest.fn();
  let app: FastifyInstance;
  let count: bigint;
  let epoch: bigint;

  beforeAll(async () => {
    app = await build();
    app.ethereum = new EthereumBackend({
      getBlock, call, getNetwork: async () => ({ chainId: 1337n }),
    } as unknown as ethers.JsonRpcProvider,
      '0x' + '11'.repeat(20));
  });
  afterAll(async () => { await app.close(); });
  beforeEach(() => {
    jest.clearAllMocks();
    count = 2n;
    epoch = 1n;
    getBlock.mockResolvedValue({ number: 100 });
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

  it('serves an old KMS, and its apps, only while epoch 0 is current', async () => {
    count = 1n;
    epoch = 0n;
    expect((await boot('app')).isAllowed).toBe(true);
    expect((await boot('kms')).isAllowed).toBe(true);
    count = 2n;
    epoch = 1n;
    expect((await boot('app')).reason).toMatch(/reports none/);
    expect((await boot('kms')).reason).toMatch(/reports none/);
  });

  it.each(['app', 'info'])('pins every read to the resolved finalized block for %s', async (endpoint) => {
    if (endpoint === 'app') {
      expect((await boot('app', { rootEpoch: 1, rootEpochHash: hash })).isAllowed).toBe(true);
    } else {
      const response = await app.inject({ method: 'GET', url: '/' });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ rootEpoch: 1, rootEpochHash: hash });
    }
    expect(call.mock.calls.every(([tx]) => tx.blockTag === 100)).toBe(true);
    expect(registryCalls()).toEqual([
      { name: 'rootEpochCount', blockTag: 100 },
      { name: 'currentRootEpoch', blockTag: 100 },
    ]);
    expect(getBlock).toHaveBeenCalledTimes(1);
    expect(getBlock).toHaveBeenCalledWith('finalized');
  });

  it.each(['authorizeKms', 'authorizeApp'] as const)('reads %s and app epochs at the resolved block', async (method) => {
    const kms = new ethers.Interface(DSTACK_KMS_ABI);
    const normalCall = call.getMockImplementation()!;
    call.mockImplementation(async (tx: ethers.TransactionRequest) => {
      const fn = kms.getFunction(tx.data!.slice(0, 10));
      if (fn?.name === method) return kms.encodeFunctionResult(fn, [[true, '', 'gateway-app', 1n, hash, 0n, 1n, hash]]);
      if (fn?.name === 'currentAppEpoch') return kms.encodeFunctionResult(fn, [2n]);
      return normalCall(tx);
    });
    const response = await app.inject({
      method: 'POST', url: `/${method}`,
      payload: { ...bootInfo, operation: method === 'authorizeKms' ? 'kms_serve' : 'app_get_key' },
    });
    expect(response.statusCode).toBe(200);
    const epoch = await app.inject({ method: 'GET', url: `/app/0x${'33'.repeat(20)}` });
    expect(epoch.json()).toEqual({ currentAppEpoch: 2 });
    expect(call.mock.calls.map(([tx]) => tx.blockTag)).toEqual([100, 100]);
    expect(getBlock).toHaveBeenCalledTimes(2);
  });

  it.each([
    ['an unsupported tag', () => getBlock.mockRejectedValue(new Error('invalid block tag'))],
    ['a missing block', () => getBlock.mockResolvedValue(null)],
  ])('fails closed on %s', async (_, failure) => {
    failure();
    for (const path of ['app', 'kms']) {
      expect(await boot(path)).toEqual({
        isAllowed: false, reason: 'authorization backend unavailable', gatewayAppId: '',
      });
    }
    expect((await app.inject({ method: 'GET', url: '/' })).statusCode).toBe(500);
    expect(call).not.toHaveBeenCalled();
  });

  it('probes the block tag at startup and names the fix when the RPC cannot serve it', async () => {
    await expect(app.ethereum.probeBlockTag()).resolves.toBeUndefined();
    for (const failure of [
      () => getBlock.mockRejectedValue(new Error('invalid block tag')),
      () => getBlock.mockResolvedValue(null),
    ]) {
      failure();
      await expect(app.ethereum.probeBlockTag()).rejects.toThrow(
        /^ETH_BLOCK_TAG=finalized is not supported by the RPC \(.+\); OP-stack via Helios requires latest$/,
      );
    }
  });

  it('accepts only the supported block tags, defaulting to finalized', () => {
    expect(parseBlockTag(undefined)).toBe('finalized');
    expect(parseBlockTag('')).toBe('finalized');
    for (const tag of ['latest', 'safe', 'finalized']) expect(parseBlockTag(tag)).toBe(tag);
    expect(() => parseBlockTag('pending')).toThrow(/ETH_BLOCK_TAG/);
    expect(() => parseBlockTag('0x10')).toThrow(/ETH_BLOCK_TAG/);
  });

  it.each([
    ['authorizeKms', 'kms_import_keys', { requestedRootEpoch: 2 }],
    ['authorizeApp', 'app_get_key', { requestedRootEpoch: 1, requestedAppEpoch: 3 }],
    ['authorizeApp', 'app_get_cert', {}],
  ] as const)('forwards the operation and both epochs to %s (%s)', async (method, operation, epochs) => {
    const kms = new ethers.Interface(DSTACK_KMS_ABI);
    const normalCall = call.getMockImplementation()!;
    const forwarded: ethers.Result[] = [];
    call.mockImplementation(async (tx: ethers.TransactionRequest) => {
      const fn = kms.getFunction(tx.data!.slice(0, 10));
      if (fn?.name !== method) return normalCall(tx);
      forwarded.push(kms.decodeFunctionData(fn, tx.data!)[0]);
      return kms.encodeFunctionResult(fn, [[true, '', 'gateway-app', 1n, hash, 0n, 1n, hash]]);
    });
    const response = await app.inject({
      method: 'POST', url: `/${method}`, payload: { ...bootInfo, operation, ...epochs },
    });
    expect(response.statusCode).toBe(200);
    expect(forwarded).toHaveLength(1);
    const [request] = forwarded;
    expect(request.operation).toBe(ethers.id(operation));
    const selector = (value?: number) => [value !== undefined, BigInt(value ?? 0)];
    const { requestedRootEpoch, requestedAppEpoch } = epochs as { requestedRootEpoch?: number, requestedAppEpoch?: number };
    expect([...request.requestedRootEpoch]).toEqual(selector(requestedRootEpoch));
    expect([...request.requestedAppEpoch]).toEqual(selector(requestedAppEpoch));
  });

  it('reports an app epoch only when the contract can vouch for it', async () => {
    const kms = new ethers.Interface(DSTACK_KMS_ABI);
    const normalCall = call.getMockImplementation()!;
    let revert = true;
    call.mockImplementation(async (tx: ethers.TransactionRequest) => {
      const fn = kms.getFunction(tx.data!.slice(0, 10));
      if (fn?.name !== 'currentAppEpoch') return normalCall(tx);
      if (revert) {
        throw ethers.AbiCoder.getBuiltinCallException('call', { to: tx.to as string, data: tx.data! },
          ethers.id('Error(string)').slice(0, 10) + ethers.AbiCoder.defaultAbiCoder().encode(['string'], ['App not registered']).slice(2));
      }
      return kms.encodeFunctionResult(fn, [0n]);
    });
    const url = `/app/0x${'33'.repeat(20)}`;
    expect((await app.inject({ method: 'GET', url })).statusCode).not.toBe(200);
    revert = false;
    const legacy = await app.inject({ method: 'GET', url });
    expect(legacy.statusCode).toBe(200);
    expect(legacy.json()).toEqual({ currentAppEpoch: 0 });
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

describe('Ethereum authorization result decoding', () => {
  const { EthereumBackend, DSTACK_KMS_ABI } = jest.requireActual<typeof import('./ethereum')>('./ethereum');
  const abi = new ethers.Interface(DSTACK_KMS_ABI);
  const request = {
    mrAggregated: '11'.repeat(32), osImageHash: '22'.repeat(32),
    appId: '33'.repeat(20), composeHash: '44'.repeat(32),
    instanceId: '55'.repeat(20), deviceId: '66'.repeat(32),
    operation: 'kms_export_keys', requestedRootEpoch: 2,
  };

  it('reports the latest registered root epoch beside the current one', async () => {
    const app = await build();
    const call = jest.fn(async (tx: ethers.TransactionRequest) => {
      const fn = abi.getFunction(tx.data!.slice(0, 10))!;
      return abi.encodeFunctionResult(fn, [[
        true, '', 'gateway', 1n, '0x' + '11'.repeat(32), 0n, 2n, '0x' + '22'.repeat(32),
      ]]);
    });
    app.ethereum = new EthereumBackend(
      {
        call, getBlock: async () => ({ number: 100 }), getNetwork: async () => ({ chainId: 1337n }),
      } as unknown as ethers.JsonRpcProvider,
      '0x' + '11'.repeat(20),
    );
    try {
      const response = await app.inject({ method: 'POST', url: '/authorizeKms', payload: request });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        authorized: true, rejectionReason: '', gatewayAppId: 'gateway',
        currentRootEpoch: 1, currentRootEpochHash: '0x' + '11'.repeat(32), currentAppEpoch: 0,
        latestRootEpoch: 2, latestRootEpochHash: '0x' + '22'.repeat(32),
      });
    } finally {
      await app.close();
    }
  });
});
