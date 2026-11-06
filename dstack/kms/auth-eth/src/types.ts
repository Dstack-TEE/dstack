// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

export interface BootInfo {
  tcbStatus: string;
  advisoryIds: string[];
  mrAggregated: string;
  mrSystem: string;
  osImageHash: string;
  appId: string;
  composeHash: string;
  instanceId: string;
  deviceId: string;
}

export interface BootResponse {
  isAllowed: boolean;
  gatewayAppId: string;
  reason: string;
  rootEpoch?: number;
  rootEpochHash?: string;
}

// The KMS root epoch currently served and its chain hash, which commits to the
// root public keys of epochs 0..=rootEpoch. Both absent when none is registered.
export interface RootEpochInfo {
  rootEpoch?: number;
  rootEpochHash?: string;
}

// Removed KMS_CONTRACT_ABI and APP_CONTRACT_ABI since we're using typechain types now
