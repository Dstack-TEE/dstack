// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import hre from "hardhat";
import { ethers } from "hardhat";
import { DstackKms } from "../typechain-types/contracts/DstackKms";
import { DstackApp } from "../typechain-types/contracts/DstackApp";
import { deployContract } from "../scripts/deploy";
import { BootInfo } from "src/types";

declare global {
  var testContracts: {
    kmsContract: DstackKms;
    appAuth: DstackApp;
    appId: string;
    owner: SignerWithAddress;
  };
}

beforeAll(async () => {

  // Get signers
  const [owner] = await ethers.getSigners();

  // Deploy contracts
  const kmsContract = await deployContract(hre, "DstackKms", [
    owner.address, 
    ethers.ZeroAddress  // _appImplementation (can be set to zero for tests)
  ], true) as DstackKms;

  const appAuth = await deployContract(hre, "DstackApp", [
    owner.address, 
    false,  // _disableUpgrades
    true,   // _allowAnyDevice
    ethers.ZeroHash,  // initialDeviceId (empty)
    ethers.ZeroHash   // initialComposeHash (empty)
  ], true) as DstackApp;

  const appId = await appAuth.getAddress();
  await kmsContract.registerApp(appId);

  // Set up KMS info with the generated app ID
  await kmsContract.setKmsInfo({
    quote: ethers.encodeBytes32String("1234"),
    caPubkey: ethers.encodeBytes32String("test-ca-pubkey"),
    k256Pubkey: ethers.encodeBytes32String("test-k256-pubkey"),
    eventlog: ethers.encodeBytes32String("test-eventlog")
  });

  const mockBootInfo: BootInfo = {
    appId,
    instanceId: ethers.encodeBytes32String("test-instance-id"),
    composeHash: ethers.encodeBytes32String("test-compose-hash"),
    deviceId: ethers.encodeBytes32String("test-device-id"),
    mrSystem: ethers.encodeBytes32String("test-mr-system"),
    mrAggregated: ethers.encodeBytes32String("test-mr-aggregated"),
    osImageHash: ethers.encodeBytes32String("test-os-image-hash"),
    tcbStatus: "UpToDate",
    advisoryIds: []
  };
  // Register some test enclaves and images
  await kmsContract.addKmsAggregatedMr(ethers.encodeBytes32String("11"));
  await kmsContract.addOsImageHash(ethers.encodeBytes32String("22"));
  await appAuth.addComposeHash(ethers.encodeBytes32String("33"));

  // Set up global test contracts
  global.testContracts = {
    kmsContract,
    appAuth,
    appId,
    owner
  };
});
