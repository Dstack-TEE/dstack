import { expect } from "chai";
import { ethers } from "hardhat";
import { AppAuth } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { deployContract } from "../scripts/deploy";
import hre from "hardhat";

describe("AppAuth", function () {
  let appAuth: AppAuth;
  let owner: SignerWithAddress;
  let user: SignerWithAddress;
  let appId: string;

  beforeEach(async function () {
    [owner, user] = await ethers.getSigners();
    appId = ethers.Wallet.createRandom().address;
    appAuth = await deployContract(hre, "AppAuth", [owner.address, appId, false, true], true) as AppAuth;
  });

  describe("Basic functionality", function () {
    it("Should set the correct owner", async function () {
      expect(await appAuth.owner()).to.equal(owner.address);
    });

    it("Should set the correct app ID", async function () {
      expect(await appAuth.appId()).to.equal(appId);
    });
  });

  describe("Compose hash management", function () {
    const testHash = ethers.randomBytes(32);

    it("Should allow adding compose hash", async function () {
      await appAuth.addComposeHash(testHash);
      expect(await appAuth.allowedComposeHashes(testHash)).to.be.true;
    });

    it("Should allow removing compose hash", async function () {
      await appAuth.addComposeHash(testHash);
      await appAuth.removeComposeHash(testHash);
      expect(await appAuth.allowedComposeHashes(testHash)).to.be.false;
    });

    it("Should emit event when adding compose hash", async function () {
      await expect(appAuth.addComposeHash(testHash))
        .to.emit(appAuth, "ComposeHashAdded")
        .withArgs(testHash);
    });

    it("Should emit event when removing compose hash", async function () {
      await appAuth.addComposeHash(testHash);
      await expect(appAuth.removeComposeHash(testHash))
        .to.emit(appAuth, "ComposeHashRemoved")
        .withArgs(testHash);
    });
  });

  describe("isAppAllowed", function () {
    const composeHash = ethers.randomBytes(32);
    const deviceId = ethers.randomBytes(32);
    const mrAggregated = ethers.randomBytes(32);
    const osImageHash = ethers.randomBytes(32);
    const mrSystem = ethers.randomBytes(32);
    const instanceId = ethers.Wallet.createRandom().address;

    beforeEach(async function () {
      await appAuth.addComposeHash(composeHash);
    });

    it("Should allow valid boot info", async function () {
      const bootInfo = {
        appId: appId,
        composeHash,
        instanceId,
        deviceId,
        mrAggregated,
        mrSystem,
        osImageHash,
        tcbStatus: "UpToDate",
        advisoryIds: []
      };

      const [isAllowed, reason] = await appAuth.isAppAllowed(bootInfo);
      expect(reason).to.equal("");
      expect(isAllowed).to.be.true;
    });

    it("Should reject invalid app ID", async function () {
      const bootInfo = {
        tcbStatus: "UpToDate",
        advisoryIds: [],
        appId: ethers.Wallet.createRandom().address,
        composeHash,
        instanceId,
        deviceId,
        mrAggregated,
        osImageHash,
        mrSystem
      };

      const [isAllowed, reason] = await appAuth.isAppAllowed(bootInfo);
      expect(isAllowed).to.be.false;
      expect(reason).to.equal("Wrong app controller");
    });

    it("Should reject unallowed compose hash", async function () {
      const bootInfo = {
        tcbStatus: "UpToDate",
        advisoryIds: [],
        appId: appId,
        composeHash: ethers.randomBytes(32),
        instanceId,
        deviceId,
        mrAggregated,
        osImageHash,
        mrSystem,
      };

      const [isAllowed, reason] = await appAuth.isAppAllowed(bootInfo);
      expect(isAllowed).to.be.false;
      expect(reason).to.equal("Compose hash not allowed");
    });
  });

  describe("Access control", function () {
    const testHash = ethers.randomBytes(32);

    it("Should prevent non-owners from adding compose hash", async function () {
      await expect(
        appAuth.connect(user).addComposeHash(testHash)
      ).to.be.revertedWithCustomError(appAuth, "OwnableUnauthorizedAccount");
    });

    it("Should prevent non-owners from removing compose hash", async function () {
      await appAuth.addComposeHash(testHash);
      await expect(
        appAuth.connect(user).removeComposeHash(testHash)
      ).to.be.revertedWithCustomError(appAuth, "OwnableUnauthorizedAccount");
    });
  });

  describe("Initialize with device and hash", function () {
    let appAuthWithData: AppAuth;
    const testDevice = ethers.randomBytes(32);
    const testHash = ethers.randomBytes(32);
    let appIdWithData: string;

    beforeEach(async function () {
      appIdWithData = ethers.Wallet.createRandom().address;
      
      // Deploy using the new initializer
      const contractFactory = await ethers.getContractFactory("AppAuth");
      appAuthWithData = await hre.upgrades.deployProxy(
        contractFactory,
        [owner.address, appIdWithData, false, false, testDevice, testHash],
        { 
          kind: 'uups',
          initializer: 'initializeWithData'
        }
      ) as AppAuth;
      
      await appAuthWithData.waitForDeployment();
    });

    it("Should set basic properties correctly", async function () {
      expect(await appAuthWithData.owner()).to.equal(owner.address);
      expect(await appAuthWithData.appId()).to.equal(appIdWithData);
      expect(await appAuthWithData.allowAnyDevice()).to.be.false;
    });

    it("Should initialize device correctly", async function () {
      expect(await appAuthWithData.allowedDeviceIds(testDevice)).to.be.true;
    });

    it("Should initialize compose hash correctly", async function () {
      expect(await appAuthWithData.allowedComposeHashes(testHash)).to.be.true;
    });

    it("Should emit events for initial device and hash", async function () {
      // Check that events were emitted during initialization
      const deploymentTx = await appAuthWithData.deploymentTransaction();
      const receipt = await deploymentTx?.wait();
      
      // Count DeviceAdded and ComposeHashAdded events
      const deviceEvents = receipt?.logs.filter(log => {
        try {
          const parsed = appAuthWithData.interface.parseLog({
            topics: log.topics as string[],
            data: log.data
          });
          return parsed?.name === 'DeviceAdded';
        } catch {
          return false;
        }
      }) || [];
      
      const hashEvents = receipt?.logs.filter(log => {
        try {
          const parsed = appAuthWithData.interface.parseLog({
            topics: log.topics as string[],
            data: log.data
          });
          return parsed?.name === 'ComposeHashAdded';
        } catch {
          return false;
        }
      }) || [];
      
      expect(deviceEvents.length).to.equal(1);
      expect(hashEvents.length).to.equal(1);
    });

    it("Should work correctly with isAppAllowed", async function () {
      const bootInfo = {
        appId: appIdWithData,
        composeHash: testHash,
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: testDevice,
        mrAggregated: ethers.randomBytes(32),
        mrSystem: ethers.randomBytes(32),
        osImageHash: ethers.randomBytes(32),
        tcbStatus: "UpToDate",
        advisoryIds: []
      };

      const [isAllowed, reason] = await appAuthWithData.isAppAllowed(bootInfo);
      expect(isAllowed).to.be.true;
      expect(reason).to.equal("");
    });

    it("Should reject unauthorized device when allowAnyDevice is false", async function () {
      const unauthorizedDevice = ethers.randomBytes(32);
      
      const bootInfo = {
        appId: appIdWithData,
        composeHash: testHash,
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: unauthorizedDevice,
        mrAggregated: ethers.randomBytes(32),
        mrSystem: ethers.randomBytes(32),
        osImageHash: ethers.randomBytes(32),
        tcbStatus: "UpToDate",
        advisoryIds: []
      };

      const [isAllowed, reason] = await appAuthWithData.isAppAllowed(bootInfo);
      expect(isAllowed).to.be.false;
      expect(reason).to.equal("Device not allowed");
    });

    it("Should handle empty initialization (no device, no hash)", async function () {
      const contractFactory = await ethers.getContractFactory("AppAuth");
      const appAuthEmpty = await hre.upgrades.deployProxy(
        contractFactory,
        [owner.address, appIdWithData, false, false, ethers.ZeroHash, ethers.ZeroHash],
        { 
          kind: 'uups',
          initializer: 'initializeWithData'
        }
      ) as AppAuth;
      
      await appAuthEmpty.waitForDeployment();
      
      // Should not have any devices or hashes set
      expect(await appAuthEmpty.allowedDeviceIds(testDevice)).to.be.false;
      expect(await appAuthEmpty.allowedComposeHashes(testHash)).to.be.false;
    });
  });
});
