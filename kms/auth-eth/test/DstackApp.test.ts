// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expect } from "chai";
import { ethers } from "hardhat";
import { DstackApp } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { deployContract } from "../scripts/deploy";
import hre from "hardhat";

describe("DstackApp", function () {
  let appAuth: DstackApp;
  let owner: SignerWithAddress;
  let user: SignerWithAddress;
  let appId: string;

  beforeEach(async function () {
    [owner, user] = await ethers.getSigners();
    appAuth = await deployContract(hre, "DstackApp", [
      owner.address,
      false,  // _disableUpgrades
      false,  // _requireTcbUpToDate
      true,   // _allowAnyDevice
      ethers.ZeroHash,  // initialDeviceId (empty)
      ethers.ZeroHash   // initialComposeHash (empty)
    ], true, "initialize(address,bool,bool,bool,bytes32,bytes32)") as DstackApp;
    appId = await appAuth.getAddress();
  });

  describe("Basic functionality", function () {
    it("Should set the correct owner", async function () {
      expect(await appAuth.owner()).to.equal(owner.address);
    });

    it("Should return version 2", async function () {
      expect(await appAuth.version()).to.equal(2);
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

  describe("TCB requirement via initialize", function () {
    it("Should reject outdated TCB when initialized with requireTcbUpToDate=true", async function () {
      const tcbApp = await deployContract(hre, "DstackApp", [
        owner.address,
        false,  // _disableUpgrades
        true,   // _requireTcbUpToDate
        true,   // _allowAnyDevice
        ethers.ZeroHash,
        ethers.ZeroHash
      ], true, "initialize(address,bool,bool,bool,bytes32,bytes32)") as DstackApp;

      const composeHash = ethers.randomBytes(32);
      await tcbApp.addComposeHash(composeHash);

      const bootInfo = {
        appId: await tcbApp.getAddress(),
        composeHash,
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.randomBytes(32),
        mrAggregated: ethers.randomBytes(32),
        mrSystem: ethers.randomBytes(32),
        osImageHash: ethers.randomBytes(32),
        tcbStatus: "OutOfDate",
        advisoryIds: []
      };

      const [isAllowed, reason] = await tcbApp.isAppAllowed(bootInfo);
      expect(isAllowed).to.be.false;
      expect(reason).to.equal("TCB status is not up to date");
    });

    it("Should allow UpToDate TCB when initialized with requireTcbUpToDate=true", async function () {
      const tcbApp = await deployContract(hre, "DstackApp", [
        owner.address,
        false,
        true,   // _requireTcbUpToDate
        true,   // _allowAnyDevice
        ethers.ZeroHash,
        ethers.ZeroHash
      ], true, "initialize(address,bool,bool,bool,bytes32,bytes32)") as DstackApp;

      const composeHash = ethers.randomBytes(32);
      await tcbApp.addComposeHash(composeHash);

      const bootInfo = {
        appId: await tcbApp.getAddress(),
        composeHash,
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.randomBytes(32),
        mrAggregated: ethers.randomBytes(32),
        mrSystem: ethers.randomBytes(32),
        osImageHash: ethers.randomBytes(32),
        tcbStatus: "UpToDate",
        advisoryIds: []
      };

      const [isAllowed, reason] = await tcbApp.isAppAllowed(bootInfo);
      expect(isAllowed).to.be.true;
      expect(reason).to.equal("");
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

    it("Should reject outdated TCB when required", async function () {
      await appAuth.setRequireTcbUpToDate(true);

      const bootInfo = {
        appId: appId,
        composeHash,
        instanceId,
        deviceId,
        mrAggregated,
        mrSystem,
        osImageHash,
        tcbStatus: "OutOfDate",
        advisoryIds: []
      };

      const [isAllowed, reason] = await appAuth.isAppAllowed(bootInfo);
      expect(isAllowed).to.be.false;
      expect(reason).to.equal("TCB status is not up to date");
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
    let appAuthWithData: DstackApp;
    const testDevice = ethers.randomBytes(32);
    const testHash = ethers.randomBytes(32);
    let appIdWithData: string;

    beforeEach(async function () {
      // Deploy using the new initializer
      const contractFactory = await ethers.getContractFactory("DstackApp");
      appAuthWithData = await hre.upgrades.deployProxy(
        contractFactory,
        [owner.address, false, false, false, testDevice, testHash],
        {
          kind: 'uups',
          initializer: 'initialize(address,bool,bool,bool,bytes32,bytes32)'
        }
      ) as DstackApp;
      
      await appAuthWithData.waitForDeployment();
      appIdWithData = await appAuthWithData.getAddress();
    });

    it("Should set basic properties correctly", async function () {
      expect(await appAuthWithData.owner()).to.equal(owner.address);
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
      const contractFactory = await ethers.getContractFactory("DstackApp");
      const appAuthEmpty = await hre.upgrades.deployProxy(
        contractFactory,
        [owner.address, false, false, false, ethers.ZeroHash, ethers.ZeroHash],
        {
          kind: 'uups',
          initializer: 'initialize(address,bool,bool,bool,bytes32,bytes32)'
        }
      ) as DstackApp;

      await appAuthEmpty.waitForDeployment();

      // Should not have any devices or hashes set
      expect(await appAuthEmpty.allowedDeviceIds(testDevice)).to.be.false;
      expect(await appAuthEmpty.allowedComposeHashes(testHash)).to.be.false;
    });
  });
});
