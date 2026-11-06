// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { ethers } from 'ethers';
import { BootInfo, BootResponse, RootEpoch } from './types';

// Minimal ABI for DstackKms contract
const DSTACK_KMS_ABI = [
  "function isAppAllowed((address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds) bootInfo) view returns (bool, string)",
  "function isKmsAllowed((address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds) bootInfo) view returns (bool, string)",
  "function gatewayAppId() view returns (string)",
  "function appImplementation() view returns (address)",
  "function latestRootEpoch() view returns (uint256)",
  "function rootEpoch(uint256 epoch) view returns (bytes caPubkey, bytes k256Pubkey, bytes attestation)"
];

// Contracts deployed before key epochs existed lack the registry getters.
function isMissingFunction(error: unknown): boolean {
  return ethers.isError(error, 'CALL_EXCEPTION') || ethers.isError(error, 'BAD_DATA');
}

export class EthereumBackend {
  private provider: ethers.JsonRpcProvider;
  private kmsContract: ethers.Contract;

  constructor(provider: ethers.JsonRpcProvider, kmsContractAddr: string) {
    this.provider = provider;
    this.kmsContract = new ethers.Contract(
      ethers.getAddress(kmsContractAddr),
      DSTACK_KMS_ABI,
      provider
    );
  }

  private decodeHex(hex: string, sz: number = 32): string {
    // Remove '0x' prefix if present
    hex = hex.startsWith('0x') ? hex.slice(2) : hex;

    // Pad hex string to 64 characters (32 bytes)
    hex = hex.padStart(sz * 2, '0');

    // Add '0x' prefix back
    return '0x' + hex;
  }

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    // Create boot info struct for contract call
    const bootInfoStruct = {
      appId: this.decodeHex(bootInfo.appId, 20),
      instanceId: this.decodeHex(bootInfo.instanceId, 20),
      composeHash: this.decodeHex(bootInfo.composeHash, 32),
      deviceId: this.decodeHex(bootInfo.deviceId, 32),
      mrSystem: this.decodeHex(bootInfo.mrSystem, 32),
      mrAggregated: this.decodeHex(bootInfo.mrAggregated, 32),
      osImageHash: this.decodeHex(bootInfo.osImageHash, 32),
      tcbStatus: bootInfo.tcbStatus,
      advisoryIds: bootInfo.advisoryIds
    };
    // Read the whole decision from one block.
    const blockTag = await this.provider.getBlockNumber();
    let response;
    if (isKms) {
      response = await this.kmsContract.isKmsAllowed(bootInfoStruct, { blockTag });
    } else {
      response = await this.kmsContract.isAppAllowed(bootInfoStruct, { blockTag });
    }
    const [isAllowed, reason] = response;
    const gatewayAppId = await this.kmsContract.gatewayAppId({ blockTag });
    const latestEpoch = await this.getLatestRootEpoch(blockTag);
    return {
      isAllowed,
      reason,
      gatewayAppId,
      ...(latestEpoch > 0 && { rootEpoch: latestEpoch }),
    }
  }

  private async getLatestRootEpoch(blockTag?: number): Promise<number> {
    try {
      return Number(await this.kmsContract.latestRootEpoch({ blockTag }));
    } catch (error) {
      if (isMissingFunction(error)) return 0;
      throw error;
    }
  }

  async getRootEpochs(): Promise<RootEpoch[]> {
    const blockTag = await this.provider.getBlockNumber();
    const latest = await this.getLatestRootEpoch(blockTag);
    return Promise.all(
      Array.from({ length: latest }, async (_, index) => {
        const [caPubkey, k256Pubkey] = await this.kmsContract.rootEpoch(index + 1, { blockTag });
        return { caPubkey, k256Pubkey };
      })
    );
  }

  async getGatewayAppId(): Promise<string> {
    return await this.kmsContract.gatewayAppId();
  }

  async getChainId(): Promise<number> {
    const chainId = await this.provider.getNetwork().then((network) => network.chainId);
    return Number(chainId);
  }

  async getAppImplementation(): Promise<string> {
    return await this.kmsContract.appImplementation();
  }
}
