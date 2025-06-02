import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers } from "hardhat";
import { EthereumBackend } from '../src/ethereum';
import { BootInfo } from '../src/types';
import { KmsAuth } from "../typechain-types/contracts/KmsAuth";
import { AppAuth } from "../typechain-types/contracts/AppAuth";

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
      tcbStatus: "UpToDate",
      advisoryIds: [],
      appId,
      composeHash: ethers.encodeBytes32String('0x1234567890abcdef'),
      instanceId: ethers.Wallet.createRandom().address,
      deviceId: ethers.encodeBytes32String('0x1234'),
      mrAggregated: ethers.encodeBytes32String('22'),
      mrSystem: ethers.encodeBytes32String('44'),
      osImageHash: ethers.encodeBytes32String('33'),
    };

    // Set up KMS info
    await kmsAuth.setKmsInfo({
      k256Pubkey: "0x" + "1234".padEnd(66, '0'),
      caPubkey: "0x" + "5678".padEnd(192, '0'),
      quote: "0x" + "9012".padEnd(8192, '0'),
      eventlog: "0x" + "9012".padEnd(8192, '0')
    });

    // Register enclave and image
    await kmsAuth.addKmsAggregatedMr(mockBootInfo.mrAggregated);
    await kmsAuth.addOsImageHash(mockBootInfo.osImageHash);
    await appAuth.addComposeHash(mockBootInfo.composeHash);
  });

  describe('checkBoot', () => {
    it('should return true when all checks pass', async () => {
      const result = await backend.checkBoot(mockBootInfo, false);
      expect(result.reason).toBe('');
      expect(result.isAllowed).toBe(true);
    });

    it('should return false when image is not registered', async () => {
      const badBootInfo = {
        ...mockBootInfo,
        osImageHash: ethers.encodeBytes32String('9999')
      };
      const result = await backend.checkBoot(badBootInfo, false);
      expect(result.reason).toBe('OS image is not allowed');
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
