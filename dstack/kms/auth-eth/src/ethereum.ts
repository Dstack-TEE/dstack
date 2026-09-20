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

export class EthereumBackend {
  private provider: ethers.JsonRpcProvider;
  private kmsContract: ethers.Contract;
  private expectedChainId?: number;
  private finalityConfirmations: bigint;

  constructor(
    provider: ethers.JsonRpcProvider,
    kmsContractAddr: string,
    expectedChainId?: number,
    finalityConfirmations: bigint = 0n,
  ) {
    this.provider = provider;
    this.kmsContract = new ethers.Contract(
      ethers.getAddress(kmsContractAddr),
      DSTACK_KMS_ABI,
      provider
    );
    this.expectedChainId = expectedChainId;
    this.finalityConfirmations = finalityConfirmations;
  }

  // Resolve the one block every read in a single authorization decision is
  // answered from, and refuse to answer at all if the RPC is not the chain the
  // operator configured.
  //
  // Without this the backend read at `latest` as two independent calls, so the
  // decision and the gateway identity could come from different blocks, a
  // reorg could unwind an allow that has already released keys, and an RPC
  // endpoint that had been swapped for a different chain would be answered
  // from rather than rejected. `auth-eth-bun` pins both; this is the same rule.
  private async finalizedBlockNumber(): Promise<bigint> {
    const chainId = await this.getChainId();
    if (this.expectedChainId !== undefined && chainId !== this.expectedChainId) {
      throw new Error('authorization backend chain ID mismatch');
    }
    const head = BigInt(await this.provider.getBlockNumber());
    if (head < this.finalityConfirmations) {
      throw new Error('authorization backend has not reached configured finality');
    }
    return head - this.finalityConfirmations;
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
    const blockTag = await this.finalizedBlockNumber();
    let response;
    if (isKms) {
      response = await this.kmsContract.isKmsAllowed(bootInfoStruct, { blockTag });
    } else {
      response = await this.kmsContract.isAppAllowed(bootInfoStruct, { blockTag });
    }
    const [isAllowed, reason] = response;
    const gatewayAppId = await this.kmsContract.gatewayAppId({ blockTag });
    return {
      isAllowed,
      reason,
      gatewayAppId,
    }
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
