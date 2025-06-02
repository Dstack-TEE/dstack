import "@openzeppelin/hardhat-upgrades";
import { HardhatUserConfig, task, types } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-ethers";
import fs from 'fs';
import { deployContract } from "./scripts/deploy";
import { upgradeContract } from "./scripts/upgrade";
import { accountBalance } from "./lib/deployment-helpers";

const PRIVATE_KEY = process.env.PRIVATE_KEY || "0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.22",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  defaultNetwork: "hardhat",
  networks: {
    hardhat: {
      chainId: 1337
    },
    phala: {
      url: 'https://rpc.phala.network',
      accounts: [PRIVATE_KEY],
    },
    sepolia: {
      url: `https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`,
      accounts: [PRIVATE_KEY],
    },
    test: {
      url: 'http://127.0.0.1:8545/',
      accounts: [PRIVATE_KEY],
    }
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },
  etherscan: {
    apiKey: {
      'phala': 'empty',
      default: process.env.ETHERSCAN_API_KEY || ""
    },
    customChains: [
      {
        network: "phala",
        chainId: 2035,
        urls: {
          apiURL: "https://explorer-phala-mainnet-0.t.conduit.xyz/api",
          browserURL: "https://explorer-phala-mainnet-0.t.conduit.xyz:443"
        }
      }
    ]
  }
};

export default config;

// Contract addresses from environment
const KMS_CONTRACT_ADDRESS = process.env.KMS_CONTRACT_ADDRESS || "0x59E4a36B01a87fD9D1A4C12377253FE9a7b018Ba";

async function waitTx(tx: any) {
  console.log(`Waiting for transaction ${tx.hash} to be confirmed...`);
  return await tx.wait();
}

async function getKmsAuth(ethers: any) {
  return await ethers.getContractAt("KmsAuth", KMS_CONTRACT_ADDRESS);
}

async function getAppAuth(ethers: any, appId: string) {
  const kmsAuth = await getKmsAuth(ethers);
  const controller = (await kmsAuth.apps(appId)).controller;
  if (controller === ethers.ZeroAddress) {
    throw new Error("AppAuth contract not found");
  }
  console.log("AppAuth address:", controller);
  return await ethers.getContractAt("AppAuth", controller);
}

// KMS Contract Tasks
task("kms:deploy", "Deploy the KmsAuth contract")
  .setAction(async (_, hre) => {
    const { ethers } = hre;
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();
    console.log("Deploying with account:", deployerAddress);
    console.log("Account balance:", await accountBalance(ethers, deployerAddress));
    await deployContract(hre, "KmsAuth", [deployerAddress]);
  });

task("kms:upgrade", "Upgrade the KmsAuth contract")
  .addParam("address", "The address of the contract to upgrade", undefined, types.string, false)
  .addFlag("dryRun", "Simulate the upgrade without executing it")
  .setAction(async (taskArgs, hre) => {
    await upgradeContract(hre, "KmsAuth", taskArgs.address, taskArgs.dryRun);
  });

task("kms:set-info", "Set KMS information from file")
  .addPositionalParam("file", "File path")
  .setAction(async ({ file }, { ethers }) => {
    const contract = await getKmsAuth(ethers);
    const fileContent = fs.readFileSync(file, 'utf8');
    const tx = await contract.setKmsInfo(JSON.parse(fileContent));
    await waitTx(tx);
    console.log("KMS info set successfully");
  });

task("kms:set-gateway", "Set the allowed Gateway App ID")
  .addPositionalParam("appId", "Gateway App ID")
  .setAction(async ({ appId }, { ethers }) => {
    const contract = await getKmsAuth(ethers);
    const tx = await contract.setGatewayAppId(appId);
    await waitTx(tx);
    console.log("Gateway App ID set successfully");
  });

task("kms:add", "Add a Aggregated MR of an KMS instance")
  .addPositionalParam("mr", "Aggregated MR to add")
  .setAction(async ({ mr }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.addKmsAggregatedMr(mr);
    await waitTx(tx);
    console.log("KMS aggregated MR added successfully");
  });

task("kms:remove", "Remove a Aggregated MR of an KMS instance")
  .addPositionalParam("mr", "Aggregated MR to remove")
  .setAction(async ({ mr }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.removeKmsAggregatedMr(mr);
    await waitTx(tx);
    console.log("KMS aggregated MR removed successfully");
  });

// Image Management Tasks
task("kms:add-image", "Add an image measurement")
  .addPositionalParam("osImageHash", "Image measurement")
  .setAction(async ({ osImageHash }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.addOsImageHash(osImageHash);
    await waitTx(tx);
    console.log("Image added successfully");
  });

task("kms:remove-image", "Remove an image measurement")
  .addPositionalParam("osImageHash", "Image measurement")
  .setAction(async ({ osImageHash }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.removeOsImageHash(osImageHash);
    await waitTx(tx);
    console.log("Image removed successfully");
  });

task("kms:add-device", "Add a device ID of an KMS instance")
  .addPositionalParam("deviceId", "Device ID")
  .setAction(async ({ deviceId }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.addKmsDevice(deviceId);
    await waitTx(tx);
    console.log("Device compose hash added successfully");
  });

task("kms:remove-device", "Remove a device ID")
  .addPositionalParam("deviceId", "Device ID to remove")
  .setAction(async ({ deviceId }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const tx = await kmsAuth.removeKmsDevice(deviceId);
    await waitTx(tx);
    console.log("Device ID removed successfully");
  });

task("info:kms", "Get current KMS information")
  .setAction(async (_, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const kmsInfo = await kmsAuth.kmsInfo();
    console.log("KMS Info:", {
      k256Pubkey: kmsInfo.k256Pubkey,
      caPubkey: kmsInfo.caPubkey,
      quote: kmsInfo.quote
    });
  });

task("info:gateway", "Get current Gateway App ID")
  .setAction(async (_, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const appId = await kmsAuth.gatewayAppId();
    console.log("Gateway App ID:", appId);
  });

task("app:show-controller", "Show the controller of an AppAuth contract")
  .addPositionalParam("appId", "App ID")
  .setAction(async ({ appId }, { ethers }) => {
    const kmsAuth = await getKmsAuth(ethers);
    const controller = await kmsAuth.apps(appId).then((app: any) => app.controller);
    console.log("AppAuth controller:", controller);
  });

task("app:deploy", "Deploy AppAuth with a UUPS proxy")
  .addFlag("allowAnyDevice", "Allow any device to boot this app")
  .setAction(async (taskArgs, hre) => {
    const { ethers } = hre;
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();
    console.log("Deploying with account:", deployerAddress);
    console.log("Account balance:", await accountBalance(ethers, deployerAddress));

    const kmsContract = await getKmsAuth(ethers);
    const appId = await kmsContract.nextAppId();
    console.log("App ID:", appId);
    const appAuth = await deployContract(hre, "AppAuth", [deployerAddress, appId, false, taskArgs.allowAnyDevice]);
    if (!appAuth) {
      return;
    }
    const proxyAddress = await appAuth.getAddress();
    const tx = await kmsContract.registerApp(proxyAddress);
    const receipt = await waitTx(tx);
    // Parse the AppRegistered event from the logs
    const appRegisteredEvent = receipt.logs
      .filter((log: any) => log.fragment?.name === 'AppRegistered')
      .map((log: any) => {
        const { appId } = log.args;
        return { appId };
      })[0];

    if (appRegisteredEvent) {
      console.log("App registered in KMS successfully");
      console.log("Registered AppId:", appRegisteredEvent.appId);
    } else {
      console.log("App registered in KMS successfully (event not found)");
    }
  });

task("app:upgrade", "Upgrade the AppAuth contract")
  .addParam("address", "The address of the contract to upgrade", undefined, types.string, false)
  .addFlag("dryRun", "Simulate the upgrade without executing it")
  .setAction(async (taskArgs, hre) => {
    await upgradeContract(hre, "AppAuth", taskArgs.address, taskArgs.dryRun);
  });

task("app:add-hash", "Add a compose hash to the AppAuth contract")
  .addParam("appId", "App ID")
  .addPositionalParam("hash", "Compose hash to add")
  .setAction(async ({ appId, hash }, { ethers }) => {
    const appAuth = await getAppAuth(ethers, appId);
    const tx = await appAuth.addComposeHash(hash);
    await waitTx(tx);
    console.log("Compose hash added successfully");
  });

task("app:remove-hash", "Remove a compose hash from the AppAuth contract")
  .addParam("appId", "App ID")
  .addPositionalParam("hash", "Compose hash to remove")
  .setAction(async ({ appId, hash }, { ethers }) => {
    const appAuth = await getAppAuth(ethers, appId);
    const tx = await appAuth.removeComposeHash(hash);
    await waitTx(tx);
    console.log("Compose hash removed successfully");
  });

task("app:add-device", "Add a device ID to the AppAuth contract")
  .addParam("appId", "App ID")
  .addPositionalParam("deviceId", "Device ID to add")
  .setAction(async ({ appId, deviceId }, { ethers }) => {
    const appAuth = await getAppAuth(ethers, appId);
    const tx = await appAuth.addDevice(deviceId);
    await waitTx(tx);
    console.log("Device ID added successfully");
  });

task("app:remove-device", "Remove a device ID from the AppAuth contract")
  .addParam("appId", "App ID")
  .addPositionalParam("deviceId", "Device ID to remove")
  .setAction(async ({ appId, deviceId }, { ethers }) => {
    const appAuth = await getAppAuth(ethers, appId);
    const tx = await appAuth.removeDevice(deviceId);
    await waitTx(tx);
    console.log("Device ID removed successfully");
  });

task("app:set-allow-any-device", "Set whether any device is allowed to boot this app")
  .addParam("appId", "App ID")
  .addFlag("allowAnyDevice", "Allow any device to boot this app")
  .setAction(async ({ appId, allowAnyDevice }, { ethers }) => {
    const appAuth = await getAppAuth(ethers, appId);
    const tx = await appAuth.setAllowAnyDevice(allowAnyDevice);
    await waitTx(tx);
    console.log("Allow any device set successfully");
  });
