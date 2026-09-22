// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { ethers } from 'ethers';
import { BootInfo, BootResponse } from './types';

// Minimal ABI for DstackKms contract
const DSTACK_KMS_ABI = [
  "function isAppAllowed((address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds) bootInfo) view returns (bool, string)",
  "function isKmsAllowed((address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds) bootInfo) view returns (bool, string)",
  "function gatewayAppId() view returns (string)",
  "function appImplementation() view returns (address)"
];

export interface VerifiedReadPolicy {
  chainId: number;
  blockLag: number;
  maxAgeSeconds: number;
}

export class EthereumBackend {
  private provider: ethers.JsonRpcProvider;
  private kmsContract: ethers.Contract;

  constructor(provider: ethers.JsonRpcProvider, kmsContractAddr: string, private readPolicy?: VerifiedReadPolicy) {
    this.provider = provider;
    this.kmsContract = new ethers.Contract(
      ethers.getAddress(kmsContractAddr),
      DSTACK_KMS_ABI,
      provider
    );
  }

  private async authorizationBlock(): Promise<{ blockTag: ethers.BlockTag; timestamp?: number }> {
    if (!this.readPolicy) return { blockTag: await this.provider.getBlockNumber() };
    const { chainId, blockLag } = this.readPolicy;
    if (Number((await this.provider.getNetwork()).chainId) !== chainId) {
      throw new Error('authorization chain ID mismatch');
    }
    const head = await this.provider.getBlockNumber();
    if (head < blockLag) throw new Error('authorization head unavailable');
    const block = await this.provider.getBlock(head - blockLag);
    if (!block) throw new Error('authorization block is not fresh');
    this.checkFreshness(block.timestamp);
    return { blockTag: block.number, timestamp: block.timestamp };
  }

  private checkFreshness(timestamp?: number): void {
    if (!this.readPolicy || timestamp === undefined) return;
    const now = Math.floor(Date.now() / 1000);
    if (now - timestamp > this.readPolicy.maxAgeSeconds || timestamp > now + 5) {
      throw new Error('authorization block is not fresh');
    }
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
    const { blockTag, timestamp } = await this.authorizationBlock();
    let response;
    if (isKms) {
      response = await this.kmsContract.isKmsAllowed(bootInfoStruct, { blockTag });
    } else {
      response = await this.kmsContract.isAppAllowed(bootInfoStruct, { blockTag });
    }
    const [isAllowed, reason] = response;
    const gatewayAppId = await this.kmsContract.gatewayAppId({ blockTag });
    this.checkFreshness(timestamp);
    return {
      isAllowed,
      reason,
      gatewayAppId,
    }
  }

  async getGatewayAppId(): Promise<string> {
    return await this.kmsContract.gatewayAppId({ blockTag: (await this.authorizationBlock()).blockTag });
  }

  async getChainId(): Promise<number> {
    const chainId = await this.provider.getNetwork().then((network) => network.chainId);
    return Number(chainId);
  }

  async getAppImplementation(): Promise<string> {
    return await this.kmsContract.appImplementation({ blockTag: (await this.authorizationBlock()).blockTag });
  }
}
