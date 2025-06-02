import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers } from "hardhat";
import { EthereumBackend } from '../src/ethereum';
import { BootInfo } from '../src/types';
import { KmsAuth } from "../typechain-types/contracts/KmsAuth";
import { IAppAuth } from "../typechain-types/contracts/IAppAuth";
import { expect } from "chai";

describe('Integration Tests', () => {
  let kmsAuth: KmsAuth;
  let owner: SignerWithAddress;
  let backend: EthereumBackend;
  let appId: string;

  beforeAll(async () => {
    owner = global.testContracts.owner;
    kmsAuth = global.testContracts.kmsAuth;
    appId = global.testContracts.appId;

    // Initialize backend with the same provider
    const provider = owner.provider;
    if (!provider) {
      throw new Error('Provider not found');
    }
    const contractAddress = await kmsAuth.getAddress();
    backend = new EthereumBackend(provider, contractAddress);
  });

  describe('KmsAuth Contract', () => {
    let mockBootInfo: IAppAuth.AppBootInfoStruct;

    beforeEach(async () => {
      mockBootInfo = {
        appId,
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.encodeBytes32String('123'),
        mrAggregated: ethers.encodeBytes32String('11'),
        osImageHash: ethers.encodeBytes32String('22'),
        composeHash: ethers.encodeBytes32String('33'),
        mrSystem: ethers.encodeBytes32String('44'),
        tcbStatus: "UpToDate",
        advisoryIds: []
      };
    });

    it('should return true when all checks pass', async () => {
      const [isAllowed, reason] = await kmsAuth.isAppAllowed(mockBootInfo);
      expect(reason).to.equal('');
      expect(isAllowed).to.equal(true);
    });

    it('should return false when image is not registered', async () => {
      const badImage = ethers.encodeBytes32String('9999');
      const [isAllowed, reason] = await kmsAuth.isAppAllowed({
        ...mockBootInfo,
        osImageHash: badImage
      });
      expect(reason).to.equal('OS image is not allowed');
      expect(isAllowed).to.equal(false);
    });
  });

  describe('EthereumBackend', () => {
    let appId: string;
    let mockBootInfo: BootInfo;

    beforeEach(async () => {
      appId = global.testContracts.appId;
      mockBootInfo = {
        tcbStatus: "UpToDate",
        advisoryIds: [],
        appId,
        composeHash: ethers.encodeBytes32String("33"),
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.encodeBytes32String("123"),
        mrSystem: ethers.encodeBytes32String("44"),
        mrAggregated: ethers.encodeBytes32String("11"),
        osImageHash: ethers.encodeBytes32String("22")
      };
    });

    describe('checkBoot', () => {
      it('should return true when all checks pass', async () => {
        const result = await backend.checkBoot(mockBootInfo, false);
        expect(result.reason).to.equal('');
        expect(result.isAllowed).to.equal(true);
      });

      it('should return false when image is not registered', async () => {
        const badBootInfo = {
          ...mockBootInfo,
          osImageHash: ethers.encodeBytes32String('9999')
        };
        const result = await backend.checkBoot(badBootInfo, false);
        expect(result.reason).to.equal('OS image is not allowed');
        expect(result.isAllowed).to.equal(false);
      });

      it('should return false when app is not registered', async () => {
        const badBootInfo = {
          ...mockBootInfo,
          appId: ethers.Wallet.createRandom().address
        };
        const result = await backend.checkBoot(badBootInfo, false);
        expect(result.reason).to.equal('App not registered');
        expect(result.isAllowed).to.equal(false);
      });
    });
  });
});
