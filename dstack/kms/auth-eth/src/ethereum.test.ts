// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// The finalized-snapshot suite auth-eth-bun already runs, replayed against the
// legacy ethers backend. Both backends serve the same `bootAuth` contract to
// the same KMS, so a decision that is reorg-safe and chain-pinned on one must
// be reorg-safe and chain-pinned on the other.
import { ethers } from 'ethers';
import { EthereumBackend } from './ethereum';
import { BootInfo } from './types';

const contractCalls: Array<{ functionName: string; overrides: any }> = [];
let isAppAllowed: jest.Mock;
let isKmsAllowed: jest.Mock;
let gatewayAppId: jest.Mock;

jest.mock('ethers', () => {
  const actual = jest.requireActual('ethers');
  return {
    ...actual,
    ethers: {
      ...actual.ethers,
      Contract: jest.fn().mockImplementation(() => ({
        isAppAllowed: (...args: any[]) => isAppAllowed(...args),
        isKmsAllowed: (...args: any[]) => isKmsAllowed(...args),
        gatewayAppId: (...args: any[]) => gatewayAppId(...args),
        appImplementation: jest.fn(),
      })),
    },
  };
});

const KMS_CONTRACT = '0x1234567890123456789012345678901234567890';
const CHAIN_ID = 1337;
const CONFIRMATIONS = 2n;

const bootInfo: BootInfo = {
  tcbStatus: 'UpToDate',
  advisoryIds: [],
  mrAggregated: '0x' + '11'.repeat(32),
  osImageHash: '0x' + '22'.repeat(32),
  mrSystem: '0x' + '33'.repeat(32),
  appId: '0x' + '44'.repeat(20),
  composeHash: '0x' + '55'.repeat(32),
  instanceId: '0x' + '66'.repeat(20),
  deviceId: '0x' + '77'.repeat(32),
};

let getNetwork: jest.Mock;
let getBlockNumber: jest.Mock;

const backend = () =>
  new EthereumBackend(
    { getNetwork, getBlockNumber } as unknown as ethers.JsonRpcProvider,
    KMS_CONTRACT,
    CHAIN_ID,
    CONFIRMATIONS,
  );

beforeEach(() => {
  contractCalls.length = 0;
  getNetwork = jest.fn().mockResolvedValue({ chainId: BigInt(CHAIN_ID) });
  getBlockNumber = jest.fn().mockResolvedValue(100);
  const record = (functionName: string, result: unknown) =>
    jest.fn((...args: any[]) => {
      contractCalls.push({ functionName, overrides: args[args.length - 1] });
      return Promise.resolve(result);
    });
  isAppAllowed = record('isAppAllowed', [true, 'allowed']);
  isKmsAllowed = record('isKmsAllowed', [true, 'allowed']);
  gatewayAppId = record('gatewayAppId', 'gateway-app');
});

describe('Ethereum finalized snapshot authorization', () => {
  it('reads the decision and gateway identity from one confirmation-depth snapshot', async () => {
    const response = await backend().checkBoot(bootInfo, false);

    expect(response).toEqual({ isAllowed: true, reason: 'allowed', gatewayAppId: 'gateway-app' });
    expect(getBlockNumber).toHaveBeenCalledTimes(1);
    expect(contractCalls.map((call) => call.functionName)).toEqual(['isAppAllowed', 'gatewayAppId']);
    for (const call of contractCalls) {
      expect(call.overrides).toEqual({ blockTag: 98n });
    }
  });

  it('re-evaluates the canonical finalized snapshot after a short reorg', async () => {
    getBlockNumber.mockResolvedValueOnce(100).mockResolvedValueOnce(101);
    const instance = backend();

    await instance.checkBoot(bootInfo, false);
    await instance.checkBoot(bootInfo, false);

    expect(
      contractCalls.filter((call) => call.functionName === 'isAppAllowed').map((call) => call.overrides.blockTag),
    ).toEqual([98n, 99n]);
  });

  it('pins the KMS route to the same snapshot', async () => {
    await backend().checkBoot(bootInfo, true);
    expect(contractCalls.map((call) => call.functionName)).toEqual(['isKmsAllowed', 'gatewayAppId']);
    for (const call of contractCalls) {
      expect(call.overrides).toEqual({ blockTag: 98n });
    }
  });

  it.each([
    ['wrong chain', () => getNetwork.mockResolvedValue({ chainId: 1n })],
    ['stale head', () => getBlockNumber.mockResolvedValue(1)],
    ['head timeout', () => getBlockNumber.mockRejectedValue(new Error('timeout'))],
  ])('fails closed for %s without reaching the contract', async (_name, inject) => {
    inject();
    await expect(backend().checkBoot(bootInfo, false)).rejects.toThrow();
    expect(contractCalls).toHaveLength(0);
  });

  it('recovers once the backend is healthy again', async () => {
    getNetwork.mockResolvedValueOnce({ chainId: 1n });
    const instance = backend();
    await expect(instance.checkBoot(bootInfo, false)).rejects.toThrow('chain ID mismatch');

    getBlockNumber.mockResolvedValue(102);
    const recovered = await instance.checkBoot(bootInfo, false);
    expect(recovered.isAllowed).toBe(true);
    expect(contractCalls[0].overrides).toEqual({ blockTag: 100n });
  });
});
