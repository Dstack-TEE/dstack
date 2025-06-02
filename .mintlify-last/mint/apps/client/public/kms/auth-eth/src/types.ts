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
}

// Removed KMS_CONTRACT_ABI and APP_CONTRACT_ABI since we're using typechain types now
