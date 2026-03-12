// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { ethers } from 'ethers';
import { BootInfo, BootResponse } from './types';
import { DstackKms__factory } from '../typechain-types/factories/contracts/DstackKms__factory';
import { DstackKms } from '../typechain-types/contracts/DstackKms';
import { IAppTcbPolicy__factory } from '../typechain-types/factories/contracts/IAppTcbPolicy__factory';
import { HardhatEthersProvider } from '@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider';

export class EthereumBackend {
  private provider: ethers.JsonRpcProvider | HardhatEthersProvider;
  private kmsContract: DstackKms;

  constructor(provider: ethers.JsonRpcProvider | HardhatEthersProvider, kmsContractAddr: string) {
    this.provider = provider;
    this.kmsContract = DstackKms__factory.connect(
      ethers.getAddress(kmsContractAddr),
      this.provider
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

  /**
   * Try to read tcbPolicy() from a contract address.
   * Returns empty string if the contract doesn't implement IAppTcbPolicy.
   */
  private async tryReadTcbPolicy(address: string): Promise<string> {
    try {
      const contract = IAppTcbPolicy__factory.connect(address, this.provider);
      return await contract.tcbPolicy();
    } catch {
      // Old contract without IAppTcbPolicy support
      return '';
    }
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
    let response;
    if (isKms) {
      response = await this.kmsContract.isKmsAllowed(bootInfoStruct);
    } else {
      response = await this.kmsContract.isAppAllowed(bootInfoStruct);
    }
    const [isAllowed, reason] = response;
    const gatewayAppId = await this.kmsContract.gatewayAppId();

    // Read TCB policy from the relevant contract
    let tcbPolicy = '';
    if (isAllowed) {
      if (isKms) {
        // KMS boot: read policy from KMS contract itself
        tcbPolicy = await this.tryReadTcbPolicy(await this.kmsContract.getAddress());
      } else {
        // App boot: read policy from the app contract
        tcbPolicy = await this.tryReadTcbPolicy(bootInfoStruct.appId);
      }
    }

    return {
      isAllowed,
      reason,
      gatewayAppId,
      tcbPolicy,
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
