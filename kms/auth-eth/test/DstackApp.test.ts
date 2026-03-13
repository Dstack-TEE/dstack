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
      true,   // _allowAnyDevice
      ethers.ZeroHash,  // initialDeviceId (empty)
      ethers.ZeroHash   // initialComposeHash (empty)
    ], true) as DstackApp;
    appId = await appAuth.getAddress();
  });

  describe("Basic functionality", function () {
    it("Should set the correct owner", async function () {
      expect(await appAuth.owner()).to.equal(owner.address);
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

  describe("TCB policy (IAppTcbPolicy)", function () {
    const testPolicy = '{"version":1,"intel_qal":["policy1"]}';

    it("Should return empty string by default", async function () {
      expect(await appAuth.tcbPolicy()).to.equal("");
    });

    it("Should allow owner to set TCB policy", async function () {
      await appAuth.setTcbPolicy(testPolicy);
      expect(await appAuth.tcbPolicy()).to.equal(testPolicy);
    });

    it("Should emit TcbPolicySet event", async function () {
      await expect(appAuth.setTcbPolicy(testPolicy))
        .to.emit(appAuth, "TcbPolicySet")
        .withArgs(testPolicy);
    });

    it("Should allow clearing TCB policy with empty string", async function () {
      await appAuth.setTcbPolicy(testPolicy);
      await appAuth.setTcbPolicy("");
      expect(await appAuth.tcbPolicy()).to.equal("");
    });

    it("Should prevent non-owners from setting TCB policy", async function () {
      await expect(
        appAuth.connect(user).setTcbPolicy(testPolicy)
      ).to.be.revertedWithCustomError(appAuth, "OwnableUnauthorizedAccount");
    });

    it("Should support IAppTcbPolicy interface (ERC-165)", async function () {
      // IAppTcbPolicy interfaceId = tcbPolicy() ^ setTcbPolicy(string)
      // We verify via supportsInterface
      const iface = new ethers.Interface([
        "function tcbPolicy() view returns (string)",
        "function setTcbPolicy(string)",
      ]);
      const interfaceId =
        BigInt(iface.getFunction("tcbPolicy")!.selector) ^
        BigInt(iface.getFunction("setTcbPolicy")!.selector);
      const id = "0x" + (interfaceId & BigInt("0xffffffff")).toString(16).padStart(8, "0");
      expect(await appAuth.supportsInterface(id)).to.be.true;
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
        [owner.address, false, false, testDevice, testHash],
        { 
          kind: 'uups'
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
        [owner.address, false, false, ethers.ZeroHash, ethers.ZeroHash],
        {
          kind: 'uups'
        }
      ) as DstackApp;

      await appAuthEmpty.waitForDeployment();

      // Should not have any devices or hashes set
      expect(await appAuthEmpty.allowedDeviceIds(testDevice)).to.be.false;
      expect(await appAuthEmpty.allowedComposeHashes(testHash)).to.be.false;
    });
  });
});

describe("DstackKms TCB policy", function () {
  let kmsContract: any;
  let owner: SignerWithAddress;
  let user: SignerWithAddress;

  beforeEach(async function () {
    [owner, user] = await ethers.getSigners();
    kmsContract = await deployContract(hre, "DstackKms", [
      owner.address,
      ethers.ZeroAddress,
    ], true);
  });

  it("Should return empty string by default", async function () {
    expect(await kmsContract.tcbPolicy()).to.equal("");
  });

  it("Should allow owner to set TCB policy", async function () {
    const policy = '{"version":1,"intel_qal":[]}';
    await kmsContract.setTcbPolicy(policy);
    expect(await kmsContract.tcbPolicy()).to.equal(policy);
  });

  it("Should emit TcbPolicySet event", async function () {
    const policy = '{"version":1}';
    await expect(kmsContract.setTcbPolicy(policy))
      .to.emit(kmsContract, "TcbPolicySet")
      .withArgs(policy);
  });

  it("Should prevent non-owners from setting TCB policy", async function () {
    await expect(
      kmsContract.connect(user).setTcbPolicy("test")
    ).to.be.revertedWithCustomError(kmsContract, "OwnableUnauthorizedAccount");
  });

  it("Should support IAppTcbPolicy interface (ERC-165)", async function () {
    const iface = new ethers.Interface([
      "function tcbPolicy() view returns (string)",
      "function setTcbPolicy(string)",
    ]);
    const interfaceId =
      BigInt(iface.getFunction("tcbPolicy")!.selector) ^
      BigInt(iface.getFunction("setTcbPolicy")!.selector);
    const id = "0x" + (interfaceId & BigInt("0xffffffff")).toString(16).padStart(8, "0");
    expect(await kmsContract.supportsInterface(id)).to.be.true;
  });
});
