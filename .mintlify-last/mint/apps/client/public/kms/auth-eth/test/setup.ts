import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import hre from "hardhat";
import { ethers } from "hardhat";
import { KmsAuth } from "../typechain-types/contracts/KmsAuth";
import { AppAuth } from "../typechain-types/contracts/AppAuth";
import { deployContract } from "../scripts/deploy";
import { BootInfo } from "src/types";

declare global {
  var testContracts: {
    kmsAuth: KmsAuth;
    appAuth: AppAuth;
    appId: string;
    owner: SignerWithAddress;
  };
}

beforeAll(async () => {

  // Get signers
  const [owner] = await ethers.getSigners();

  // Deploy contracts
  const kmsAuth = await deployContract(hre, "KmsAuth", [owner.address], true) as KmsAuth;

  // Initialize the contract with an app and KMS info
  const appId = await kmsAuth.nextAppId();

  const appAuth = await deployContract(hre, "AppAuth", [owner.address, appId, false, true], true) as AppAuth;

  await kmsAuth.registerApp(await appAuth.getAddress());

  // Set up KMS info with the generated app ID
  await kmsAuth.setKmsInfo({
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
  await kmsAuth.addKmsAggregatedMr(ethers.encodeBytes32String("11"));
  await kmsAuth.addOsImageHash(ethers.encodeBytes32String("22"));
  await appAuth.addComposeHash(ethers.encodeBytes32String("33"));

  // Set up global test contracts
  global.testContracts = {
    kmsAuth,
    appAuth,
    appId,
    owner
  };
});
