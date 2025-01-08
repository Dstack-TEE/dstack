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
      appId: bootInfo.appId,
      composeHash: this.decodeHex(bootInfo.composeHash),
      instanceId: bootInfo.instanceId,
      deviceId: this.decodeHex(bootInfo.deviceId),
      mrEnclave: this.decodeHex(bootInfo.mrEnclave),
      mrImage: this.decodeHex(bootInfo.mrImage)
    };

    if (isKms) {
      return await this.kmsAuth.isKmsAllowed(bootInfoStruct);
    } else {
      return await this.kmsAuth.isAppAllowed(bootInfoStruct);
    }
  }
}