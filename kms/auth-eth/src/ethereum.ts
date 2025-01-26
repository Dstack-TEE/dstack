import { ethers } from 'ethers';
import { BootInfo, BootResponse } from './types';
import { KmsAuth__factory } from '../typechain-types/factories/KmsAuth__factory';
import { KmsAuth } from '../typechain-types/KmsAuth';
import { HardhatEthersProvider } from '@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider';

export class EthereumBackend {
  private provider: ethers.JsonRpcProvider | HardhatEthersProvider;
  private kmsAuth: KmsAuth;

  constructor(provider: ethers.JsonRpcProvider | HardhatEthersProvider, kmsAuthAddr: string) {
    this.provider = provider;
    this.kmsAuth = KmsAuth__factory.connect(
      ethers.getAddress(kmsAuthAddr),
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

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    // Create boot info struct for contract call
    const bootInfoStruct = {
      appId: this.decodeHex(bootInfo.appId, 20),
      instanceId: this.decodeHex(bootInfo.instanceId, 20),
      composeHash: this.decodeHex(bootInfo.composeHash, 32),
      deviceId: this.decodeHex(bootInfo.deviceId, 32),
      mrAggregated: this.decodeHex(bootInfo.mrAggregated, 32),
      mrImage: this.decodeHex(bootInfo.mrImage, 32)
    };
    let response;
    if (isKms) {
      response = await this.kmsAuth.isKmsAllowed(bootInfoStruct);
    } else {
      response = await this.kmsAuth.isAppAllowed(bootInfoStruct);
    }
    const [isAllowed, reason] = response;
    const tproxyAppId = await this.kmsAuth.tproxyAppId();
    return {
      isAllowed,
      reason,
      tproxyAppId
    }
  }
}
