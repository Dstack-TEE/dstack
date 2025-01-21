import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers } from "hardhat";
import { EthereumBackend } from '../src/ethereum';
import { BootInfo } from '../src/types';
import { KmsAuth } from "../typechain-types/KmsAuth";
import { AppAuth } from "../typechain-types/AppAuth";

// Declare global test contracts
declare global {
  var testContracts: {
    kmsAuth: KmsAuth;
    appAuth: AppAuth;
    appId: string;
    owner: SignerWithAddress;
  };
}

describe('EthereumBackend', () => {
  let kmsAuth: KmsAuth;
  let owner: SignerWithAddress;
  let backend: EthereumBackend;
  let mockBootInfo: BootInfo;
  let appId: string;
  let appAuth: AppAuth;

  beforeEach(async () => {
    // Get test contracts from global setup
    ({ kmsAuth, owner, appAuth, appId } = global.testContracts);

    // Initialize backend with KmsAuth contract address
    backend = new EthereumBackend(
      owner.provider,
      await kmsAuth.getAddress()
    );

    // Create mock boot info with valid addresses
    mockBootInfo = {
      appId,
      composeHash: ethers.encodeBytes32String('0x1234567890abcdef'),
      instanceId: ethers.Wallet.createRandom().address,
      deviceId: ethers.encodeBytes32String('0x123'),
      mrAggregated: ethers.encodeBytes32String('0x1234'),
      mrImage: ethers.encodeBytes32String('0x5678')
    };

    // Set up KMS info
    await kmsAuth.setKmsInfo({
      k256Pubkey: "0x" + "1234".padEnd(66, '0'),
      caPubkey: "0x" + "5678".padEnd(192, '0'),
      quote: "0x" + "9012".padEnd(8192, '0'),
      eventlog: "0x" + "9012".padEnd(8192, '0')
    });

    // Register enclave and image
    await kmsAuth.registerAggregatedMr(mockBootInfo.mrAggregated);
    await kmsAuth.registerImage(mockBootInfo.mrImage);
    await appAuth.addComposeHash(mockBootInfo.composeHash);
  });

  describe('checkBoot', () => {
    it('should return true when all checks pass', async () => {
      const result = await backend.checkBoot(mockBootInfo, false);
      expect(result.reason).toBe('');
      expect(result.isAllowed).toBe(true);
    });

    it('should return true when enclave is not allowed but image is allowed', async () => {
      const badBootInfo = {
        ...mockBootInfo,
        mrAggregated: ethers.encodeBytes32String('0x9999'),
      };
      const result = await backend.checkBoot(badBootInfo, false);
      expect(result.reason).toBe('');
      expect(result.isAllowed).toBe(true);
    });

    it('should return true when image is not allowed but enclave is allowed', async () => {
      const badBootInfo = {
        ...mockBootInfo,
        mrImage: ethers.encodeBytes32String('0x9999')
      };
      const result = await backend.checkBoot(badBootInfo, false);
      expect(result.reason).toBe('');
      expect(result.isAllowed).toBe(true);
    });

    it('should return false when enclave and image are not registered', async () => {
      const badMrAggregated = ethers.encodeBytes32String('9999');
      const badMrImage = ethers.encodeBytes32String('9999');
      const badBootInfo = {
        ...mockBootInfo,
        mrAggregated: badMrAggregated,
        mrImage: badMrImage
      };
      const result = await backend.checkBoot(badBootInfo, false);
      expect(result.reason).toBe('Neither aggregated MR nor image is allowed');
      expect(result.isAllowed).toBe(false);
    });

    it('should return false when app is not registered', async () => {
      const badBootInfo = {
        ...mockBootInfo,
        appId: ethers.Wallet.createRandom().address
      };
      const result = await backend.checkBoot(badBootInfo, false);
      expect(result.reason).toBe('App not registered');
      expect(result.isAllowed).toBe(false);
    });
  });
});
