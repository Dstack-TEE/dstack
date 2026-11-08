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
  // The root epoch the asking KMS serves and its chain hash; absent from a KMS
  // that predates root epochs, and from KMS checks made while onboarding.
  rootEpoch?: number;
  rootEpochHash?: string;
}

export interface BootResponse {
  isAllowed: boolean;
  gatewayAppId: string;
  reason: string;
}

// The current KMS root epoch and its chain hash, which commits to the root
// public keys of epochs 0..=rootEpoch. Both absent when none is registered.
export interface RootEpochInfo {
  rootEpoch?: number;
  rootEpochHash?: string;
}

// Removed KMS_CONTRACT_ABI and APP_CONTRACT_ABI since we're using typechain types now

export interface AuthorizationResult {
  isAllowed: boolean;
  rejectionReason: string;
  gatewayAppId: string;
  currentRootEpoch: number;
  currentRootEpochHash: string;
  currentAppEpoch: number;
}

export interface AuthorizationRequest extends Omit<BootInfo, 'rootEpoch' | 'rootEpochHash'> {
  operation: 'bootstrap' | 'serve' | 'export_kms_keys' | 'import_kms_keys' | 'get_app_key' | 'get_app_cert';
  requestedAppEpoch?: number;
  requestedRootEpoch?: number;
}
