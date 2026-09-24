// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

import { ethers } from 'ethers';
import { EthereumBackend } from './ethereum';
import { BootInfo } from './types';

jest.mock('ethers', () => ({
  ethers: { ...jest.requireActual('ethers').ethers, Contract: jest.fn() },
}));

const bootInfo: BootInfo = {
  appId: '00'.repeat(20), instanceId: '00'.repeat(20),
  composeHash: '00'.repeat(32), deviceId: '00'.repeat(32),
  mrAggregated: '00'.repeat(32), mrSystem: '00'.repeat(32),
  osImageHash: '00'.repeat(32), tcbStatus: 'UpToDate', advisoryIds: [],
};

describe('verified authorization reads', () => {
  const contract = {
    isAppAllowed: jest.fn(), isKmsAllowed: jest.fn(), gatewayAppId: jest.fn(),
  };
  const provider = {
    getNetwork: jest.fn(), getBlockNumber: jest.fn(), getBlock: jest.fn(),
  };
  let backend: EthereumBackend;

  beforeEach(() => {
    jest.resetAllMocks();
    (ethers.Contract as unknown as jest.Mock).mockReturnValue(contract);
    provider.getNetwork.mockResolvedValue({ chainId: 2035n });
    provider.getBlockNumber.mockResolvedValue(100);
    provider.getBlock.mockResolvedValue({ number: 98, timestamp: Math.floor(Date.now() / 1000) - 20 });
    contract.isAppAllowed.mockResolvedValue([true, '']);
    contract.isKmsAllowed.mockResolvedValue([true, '']);
    contract.gatewayAppId.mockResolvedValue('gateway');
    backend = new EthereumBackend(provider as unknown as ethers.JsonRpcProvider,
      ethers.ZeroAddress, { chainId: 2035, blockLag: 2, maxAgeSeconds: 60 });
  });

  it.each([false, true])('pins all boot reads to the same fresh block (kms=%s)', async (isKms) => {
    await expect(backend.checkBoot(bootInfo, isKms)).resolves.toEqual({
      isAllowed: true, reason: '', gatewayAppId: 'gateway',
    });
    expect(provider.getBlock).toHaveBeenCalledWith(98);
    expect(isKms ? contract.isKmsAllowed : contract.isAppAllowed)
      .toHaveBeenCalledWith(expect.any(Object), { blockTag: 98 });
    expect(contract.gatewayAppId).toHaveBeenCalledWith({ blockTag: 98 });
  });

  it('rejects a different chain before contract execution', async () => {
    provider.getNetwork.mockResolvedValue({ chainId: 1n });
    await expect(backend.checkBoot(bootInfo, false)).rejects.toThrow('chain ID mismatch');
    expect(contract.isAppAllowed).not.toHaveBeenCalled();
  });

  it.each([null, { number: 98, timestamp: 0 }, { number: 98, timestamp: 9999999999 }])(
    'rejects unavailable, stale, or future state: %j', async (block) => {
      provider.getBlock.mockResolvedValue(block);
      await expect(backend.checkBoot(bootInfo, false)).rejects.toThrow('not fresh');
      expect(contract.isAppAllowed).not.toHaveBeenCalled();
    },
  );

  it('rejects state that expires while contract calls are in flight', async () => {
    const started = Date.now();
    const clock = jest.spyOn(Date, 'now').mockReturnValue(started);
    contract.gatewayAppId.mockImplementation(async () => {
      clock.mockReturnValue(started + 61_000);
      return 'gateway';
    });
    try {
      await expect(backend.checkBoot(bootInfo, true)).rejects.toThrow('not fresh');
    } finally {
      clock.mockRestore();
    }
  });

  it('does not fallback when proof execution fails', async () => {
    contract.isAppAllowed.mockRejectedValue(new Error('invalid proof'));
    await expect(backend.checkBoot(bootInfo, false)).rejects.toThrow('invalid proof');
    expect(contract.isAppAllowed).toHaveBeenCalledTimes(1);
    expect(contract.gatewayAppId).not.toHaveBeenCalled();
  });
});
