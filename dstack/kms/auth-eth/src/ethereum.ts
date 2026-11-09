// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { ethers } from 'ethers';
import { BootInfo, BootResponse, RootEpochInfo, AuthorizationResult, AuthorizationRequest } from './types';

// Minimal ABI for DstackKms contract
export const DSTACK_KMS_ABI = [
  "function currentAppEpoch(address appId) view returns (uint256)",
  "function authorizeKms(((address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds) appInfo,bytes32 operation,(bool isSet,uint256 value) requestedAppEpoch,(bool isSet,uint256 value) requestedRootEpoch) request) view returns ((bool isAllowed,string rejectionReason,string gatewayAppId,uint256 currentRootEpoch,bytes32 currentRootEpochHash,uint256 currentAppEpoch))",
  "function authorizeApp(((address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds) appInfo,bytes32 operation,(bool isSet,uint256 value) requestedAppEpoch,(bool isSet,uint256 value) requestedRootEpoch) request) view returns ((bool isAllowed,string rejectionReason,string gatewayAppId,uint256 currentRootEpoch,bytes32 currentRootEpochHash,uint256 currentAppEpoch))",
  "function isAppAllowed((address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds) bootInfo) view returns (bool, string)",
  "function isKmsAllowed((address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds) bootInfo) view returns (bool, string)",
  "function gatewayAppId() view returns (string)",
  "function appImplementation() view returns (address)",
  "function rootEpochCount() view returns (uint256)",
  "function currentRootEpoch() view returns (uint256 epoch, bytes32 chainHash)"
];

const normHash = (hash?: string) => hash?.toLowerCase().replace(/^0x/, '');

// Only a KMS serving the current root epoch, with the registered keys up to it,
// may authorize. A KMS that predates root epochs reports none and holds only
// epoch 0, so it is served only until another epoch is activated.
export function rootEpochDenial(bootInfo: BootInfo, current: RootEpochInfo): string | undefined {
  const currentEpoch = current.rootEpoch ?? 0;
  if (bootInfo.rootEpoch === undefined) {
    return currentEpoch === 0 ? undefined : `root epoch ${currentEpoch} is current, but the KMS reports none`;
  }
  if (current.rootEpoch === undefined) {
    return bootInfo.rootEpoch === 0 ? undefined : `root epoch ${bootInfo.rootEpoch} is not registered`;
  }
  if (bootInfo.rootEpoch !== currentEpoch) {
    return `the KMS serves root epoch ${bootInfo.rootEpoch}, but ${currentEpoch} is current`;
  }
  if (normHash(bootInfo.rootEpochHash) !== normHash(current.rootEpochHash)) {
    return `the KMS root keys up to epoch ${currentEpoch} are not the registered ones`;
  }
  return undefined;
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

  private contractAppInfo(bootInfo: BootInfo) {
    // Create boot info struct for contract call
    return {
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
  }

  async checkAuthorization(appInfo: AuthorizationRequest, method: 'authorizeKms' | 'authorizeApp'): Promise<AuthorizationResult> {
    const result = await this.kmsContract[method]({
      appInfo: this.contractAppInfo(appInfo),
      operation: ethers.id(appInfo.operation),
      requestedAppEpoch: { isSet: appInfo.requestedAppEpoch !== undefined, value: appInfo.requestedAppEpoch ?? 0 },
      requestedRootEpoch: { isSet: appInfo.requestedRootEpoch !== undefined, value: appInfo.requestedRootEpoch ?? 0 },
    });
    return {
      isAllowed: result.isAllowed,
      rejectionReason: result.rejectionReason,
      gatewayAppId: result.gatewayAppId,
      currentRootEpoch: ethers.toNumber(result.currentRootEpoch),
      currentRootEpochHash: result.currentRootEpochHash,
      currentAppEpoch: ethers.toNumber(result.currentAppEpoch),
    };
  }

  async checkBoot(bootInfo: BootInfo, isKms: boolean): Promise<BootResponse> {
    const bootInfoStruct = this.contractAppInfo(bootInfo);
    // Read the whole decision from one block.
    const blockTag = await this.provider.getBlockNumber();
    let response;
    if (isKms) {
      response = await this.kmsContract.isKmsAllowed(bootInfoStruct, { blockTag });
    } else {
      response = await this.kmsContract.isAppAllowed(bootInfoStruct, { blockTag });
    }
    const [allowed, contractReason] = response;
    const gatewayAppId = await this.kmsContract.gatewayAppId({ blockTag });
    const epochDenial = allowed
      ? rootEpochDenial(bootInfo, await this.getRootEpoch(blockTag))
      : undefined;
    return {
      isAllowed: allowed && !epochDenial,
      reason: epochDenial ?? contractReason,
      gatewayAppId,
    }
  }

  // The current root epoch and its chain hash; empty only when no epoch is registered.
  async getRootEpoch(blockTag?: number): Promise<RootEpochInfo> {
    blockTag ??= await this.provider.getBlockNumber();
    const count = await this.kmsContract.rootEpochCount({ blockTag });
    if (count === 0n) return {};
    const [epoch, chainHash] = await this.kmsContract.currentRootEpoch({ blockTag });
    return { rootEpoch: Number(epoch), rootEpochHash: chainHash };
  }

  async getAppEpoch(appId: string): Promise<number> {
    return ethers.toNumber(await this.kmsContract.currentAppEpoch(this.decodeHex(appId, 20)));
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
