// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expect } from "chai";
import { ethers } from "hardhat";
import { DstackApp, DstackKms } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import hre from "hardhat";

describe("DstackApp upgrade", function () {
  let owner: SignerWithAddress;
  let other: SignerWithAddress;

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();
  });

  // Deploy a proxy using the old 5-param initialize to simulate a pre-upgrade deployment.
  async function deployOldApp(
    allowAnyDevice: boolean,
    initialDeviceId: string,
    initialComposeHash: string
  ): Promise<DstackApp> {
    const factory = await ethers.getContractFactory("DstackApp");
    const proxy = await hre.upgrades.deployProxy(
      factory,
      [owner.address, false, allowAnyDevice, initialDeviceId, initialComposeHash],
      {
        kind: "uups",
        initializer: "initialize(address,bool,bool,bytes32,bytes32)",
      }
    ) as DstackApp;
    await proxy.waitForDeployment();
    return proxy;
  }

  // Upgrade an existing proxy to the (same, current) DstackApp implementation.
  // In a real scenario the new bytecode would differ; hardhat-upgrades still validates
  // storage layout compatibility and swaps the implementation slot.
  async function upgradeApp(proxy: DstackApp): Promise<DstackApp> {
    const factory = await ethers.getContractFactory("DstackApp");
    const upgraded = await hre.upgrades.upgradeProxy(
      await proxy.getAddress(),
      factory,
      { kind: "uups" }
    ) as DstackApp;
    return upgraded;
  }

  describe("Upgrade from old 5-param initialize", function () {
    let app: DstackApp;
    const composeHash = ethers.encodeBytes32String("upgrade-test-hash");
    const deviceId = ethers.encodeBytes32String("upgrade-test-dev");

    beforeEach(async function () {
      // Deploy with old initializer (no requireTcbUpToDate param)
      app = await deployOldApp(false, deviceId, composeHash);
    });

    it("should preserve existing storage after upgrade", async function () {
      // Verify pre-upgrade state
      expect(await app.owner()).to.equal(owner.address);
      expect(await app.allowAnyDevice()).to.be.false;
      expect(await app.allowedDeviceIds(deviceId)).to.be.true;
      expect(await app.allowedComposeHashes(composeHash)).to.be.true;

      // Upgrade
      const upgraded = await upgradeApp(app);

      // Storage must be preserved
      expect(await upgraded.owner()).to.equal(owner.address);
      expect(await upgraded.allowAnyDevice()).to.be.false;
      expect(await upgraded.allowedDeviceIds(deviceId)).to.be.true;
      expect(await upgraded.allowedComposeHashes(composeHash)).to.be.true;
    });

    it("should expose version() = 2 after upgrade", async function () {
      const upgraded = await upgradeApp(app);
      expect(await upgraded.version()).to.equal(2);
    });

    it("should default requireTcbUpToDate to false after upgrade", async function () {
      const upgraded = await upgradeApp(app);
      // Old proxy never set this slot — it should be zero (false)
      expect(await upgraded.requireTcbUpToDate()).to.be.false;
    });

    it("should allow setting requireTcbUpToDate after upgrade", async function () {
      const upgraded = await upgradeApp(app);

      await expect(upgraded.setRequireTcbUpToDate(true))
        .to.emit(upgraded, "RequireTcbUpToDateSet")
        .withArgs(true);
      expect(await upgraded.requireTcbUpToDate()).to.be.true;

      await upgraded.setRequireTcbUpToDate(false);
      expect(await upgraded.requireTcbUpToDate()).to.be.false;
    });

    it("should allow outdated TCB by default after upgrade (no silent behavior change)", async function () {
      const upgraded = await upgradeApp(app);

      const bootInfo = {
        appId: await upgraded.getAddress(),
        composeHash,
        instanceId: ethers.Wallet.createRandom().address,
        deviceId,
        mrAggregated: ethers.randomBytes(32),
        mrSystem: ethers.randomBytes(32),
        osImageHash: ethers.randomBytes(32),
        tcbStatus: "OutOfDate",
        advisoryIds: [],
      };

      const [isAllowed, reason] = await upgraded.isAppAllowed(bootInfo);
      expect(isAllowed).to.be.true;
      expect(reason).to.equal("");
    });

    it("should enforce TCB check after owner opts in post-upgrade", async function () {
      const upgraded = await upgradeApp(app);
      await upgraded.setRequireTcbUpToDate(true);

      const bootInfoBad = {
        appId: await upgraded.getAddress(),
        composeHash,
        instanceId: ethers.Wallet.createRandom().address,
        deviceId,
        mrAggregated: ethers.randomBytes(32),
        mrSystem: ethers.randomBytes(32),
        osImageHash: ethers.randomBytes(32),
        tcbStatus: "OutOfDate",
        advisoryIds: [],
      };

      const [rejected, rejectReason] = await upgraded.isAppAllowed(bootInfoBad);
      expect(rejected).to.be.false;
      expect(rejectReason).to.equal("TCB status is not up to date");

      const bootInfoGood = { ...bootInfoBad, tcbStatus: "UpToDate" };
      const [allowed, allowReason] = await upgraded.isAppAllowed(bootInfoGood);
      expect(allowed).to.be.true;
      expect(allowReason).to.equal("");
    });

    it("should reject non-owner calling setRequireTcbUpToDate after upgrade", async function () {
      const upgraded = await upgradeApp(app);
      await expect(
        upgraded.connect(other).setRequireTcbUpToDate(true)
      ).to.be.revertedWithCustomError(upgraded, "OwnableUnauthorizedAccount");
    });
  });

  describe("KMS factory after upgrade", function () {
    it("should deploy new apps with TCB flag via factory", async function () {
      // Deploy DstackApp implementation
      const appFactory = await ethers.getContractFactory("DstackApp");
      const appImpl = await appFactory.deploy();
      await appImpl.waitForDeployment();
      const appImplAddr = await appImpl.getAddress();

      // Deploy KMS with app implementation
      const kmsFactory = await ethers.getContractFactory("DstackKms");
      const kms = await hre.upgrades.deployProxy(
        kmsFactory,
        [owner.address, appImplAddr],
        { kind: "uups" }
      ) as DstackKms;
      await kms.waitForDeployment();

      // Add an OS image hash (required by KMS.isAppAllowed)
      const osImageHash = ethers.encodeBytes32String("os-img");
      await kms.addOsImageHash(osImageHash);

      const composeHash = ethers.encodeBytes32String("factory-hash");

      // Deploy app with requireTcbUpToDate = true via factory
      const tx = await kms.deployAndRegisterApp(
        owner.address,
        false,          // disableUpgrades
        true,           // requireTcbUpToDate
        true,           // allowAnyDevice
        ethers.ZeroHash,
        composeHash
      );
      const receipt = await tx.wait();

      // Extract app address from AppDeployedViaFactory event
      let appAddr: string | undefined;
      for (const log of receipt!.logs) {
        try {
          const parsed = kms.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          if (parsed?.name === "AppDeployedViaFactory") {
            appAddr = parsed.args.appId;
          }
        } catch {
          continue;
        }
      }
      expect(appAddr).to.not.be.undefined;

      const factoryApp = await ethers.getContractAt("DstackApp", appAddr!) as DstackApp;

      expect(await factoryApp.version()).to.equal(2);
      expect(await factoryApp.requireTcbUpToDate()).to.be.true;
      expect(await factoryApp.allowAnyDevice()).to.be.true;
      expect(await factoryApp.allowedComposeHashes(composeHash)).to.be.true;

      // Verify TCB enforcement
      const bootInfo = {
        appId: appAddr!,
        composeHash,
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.randomBytes(32),
        mrAggregated: ethers.randomBytes(32),
        mrSystem: ethers.randomBytes(32),
        osImageHash,
        tcbStatus: "OutOfDate",
        advisoryIds: [],
      };

      // KMS-level isAppAllowed should delegate to DstackApp and reject
      const [rejected, reason] = await kms.isAppAllowed(bootInfo);
      expect(rejected).to.be.false;
      expect(reason).to.equal("TCB status is not up to date");

      // Same boot info with UpToDate should pass
      const [allowed, allowReason] = await kms.isAppAllowed({
        ...bootInfo,
        tcbStatus: "UpToDate",
      });
      expect(allowed).to.be.true;
      expect(allowReason).to.equal("");
    });

    it("should deploy new apps without TCB flag via factory", async function () {
      const appFactory = await ethers.getContractFactory("DstackApp");
      const appImpl = await appFactory.deploy();
      await appImpl.waitForDeployment();

      const kmsFactory = await ethers.getContractFactory("DstackKms");
      const kms = await hre.upgrades.deployProxy(
        kmsFactory,
        [owner.address, await appImpl.getAddress()],
        { kind: "uups" }
      ) as DstackKms;
      await kms.waitForDeployment();

      const osImageHash = ethers.encodeBytes32String("os-img-2");
      await kms.addOsImageHash(osImageHash);

      const composeHash = ethers.encodeBytes32String("no-tcb-hash");

      const tx = await kms.deployAndRegisterApp(
        owner.address,
        false,          // disableUpgrades
        false,          // requireTcbUpToDate = false
        true,           // allowAnyDevice
        ethers.ZeroHash,
        composeHash
      );
      const receipt = await tx.wait();

      let appAddr: string | undefined;
      for (const log of receipt!.logs) {
        try {
          const parsed = kms.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          if (parsed?.name === "AppDeployedViaFactory") {
            appAddr = parsed.args.appId;
          }
        } catch {
          continue;
        }
      }

      const factoryApp = await ethers.getContractAt("DstackApp", appAddr!) as DstackApp;
      expect(await factoryApp.requireTcbUpToDate()).to.be.false;

      // OutOfDate TCB should be allowed when flag is off
      const bootInfo = {
        appId: appAddr!,
        composeHash,
        instanceId: ethers.Wallet.createRandom().address,
        deviceId: ethers.randomBytes(32),
        mrAggregated: ethers.randomBytes(32),
        mrSystem: ethers.randomBytes(32),
        osImageHash,
        tcbStatus: "OutOfDate",
        advisoryIds: [],
      };

      const [allowed, reason] = await kms.isAppAllowed(bootInfo);
      expect(allowed).to.be.true;
      expect(reason).to.equal("");
    });
  });
});
