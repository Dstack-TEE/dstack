// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

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
    base: {
      url: 'https://mainnet.base.org',
      accounts: [PRIVATE_KEY],
    },
    test: {
      url: process.env.RPC_URL || 'http://127.0.0.1:8545/',
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

async function getKmsContract(ethers: any) {
  return await ethers.getContractAt("DstackKms", KMS_CONTRACT_ADDRESS);
}

async function getAppContract(ethers: any, appId: string) {
  return await ethers.getContractAt("DstackApp", appId);
}

// KMS Contract Tasks
task("kms:deploy", "Deploy the DstackKms contract")
  .addOptionalParam("appImplementation", "DstackApp implementation address to set during initialization", "", types.string)
  .addFlag("withAppImpl", "Deploy DstackApp implementation first and set it during DstackKms initialization")
  .setAction(async (taskArgs, hre) => {
    const { ethers } = hre;
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();
    console.log("Deploying with account:", deployerAddress);
    console.log("Account balance:", await accountBalance(ethers, deployerAddress));
    
    let appImplementation = taskArgs.appImplementation || ethers.ZeroAddress;
    
    if (taskArgs.withAppImpl && appImplementation === ethers.ZeroAddress) {
      // Deploy DstackApp implementation first
      console.log("Step 1: Deploying DstackApp implementation...");
      const DstackApp = await ethers.getContractFactory("DstackApp");
      const appContractImpl = await DstackApp.deploy();
      await appContractImpl.waitForDeployment();
      appImplementation = await appContractImpl.getAddress();
      console.log("✅ DstackApp implementation deployed to:", appImplementation);
    }
    
    if (appImplementation !== ethers.ZeroAddress) {
      console.log("Setting DstackApp implementation during initialization:", appImplementation);
    }
    
    console.log("Step 2: Deploying DstackKms...");
    const kmsContract = await deployContract(hre, "DstackKms", [deployerAddress, appImplementation]);
    
    if (kmsContract && taskArgs.withAppImpl) {
      console.log("✅ Complete KMS setup deployed successfully!");
      console.log("- DstackApp implementation:", appImplementation);
      console.log("- DstackKms proxy:", await kmsContract.getAddress());
      console.log("🚀 Ready for factory app deployments!");
    }
  });



task("kms:upgrade", "Upgrade the DstackKms contract")
  .addParam("address", "The address of the contract to upgrade", undefined, types.string, false)
  .addFlag("dryRun", "Simulate the upgrade without executing it")
  .setAction(async (taskArgs, hre) => {
    await upgradeContract(hre, "DstackKms", taskArgs.address, taskArgs.dryRun);
  });

task("kms:set-info", "Set KMS information from file")
  .addPositionalParam("file", "File path")
  .setAction(async ({ file }, { ethers }) => {
    const contract = await getKmsContract(ethers);
    const fileContent = fs.readFileSync(file, 'utf8');
    const tx = await contract.setKmsInfo(JSON.parse(fileContent));
    await waitTx(tx);
    console.log("KMS info set successfully");
  });

task("kms:set-gateway", "Set the allowed Gateway App ID")
  .addPositionalParam("appId", "Gateway App ID")
  .setAction(async ({ appId }, { ethers }) => {
    const contract = await getKmsContract(ethers);
    const tx = await contract.setGatewayAppId(appId);
    await waitTx(tx);
    console.log("Gateway App ID set successfully");
  });

task("kms:add", "Add a Aggregated MR of an KMS instance")
  .addPositionalParam("mr", "Aggregated MR to add")
  .setAction(async ({ mr }, { ethers }) => {
    const kmsContract = await getKmsContract(ethers);
    const tx = await kmsContract.addKmsAggregatedMr(mr);
    await waitTx(tx);
    console.log("KMS aggregated MR added successfully");
  });

task("kms:remove", "Remove a Aggregated MR of an KMS instance")
  .addPositionalParam("mr", "Aggregated MR to remove")
  .setAction(async ({ mr }, { ethers }) => {
    const kmsContract = await getKmsContract(ethers);
    const tx = await kmsContract.removeKmsAggregatedMr(mr);
    await waitTx(tx);
    console.log("KMS aggregated MR removed successfully");
  });

// Image Management Tasks
task("kms:add-image", "Add an image measurement")
  .addPositionalParam("osImageHash", "Image measurement")
  .setAction(async ({ osImageHash }, { ethers }) => {
    const kmsContract = await getKmsContract(ethers);
    const tx = await kmsContract.addOsImageHash(osImageHash);
    await waitTx(tx);
    console.log("Image added successfully");
  });

task("kms:remove-image", "Remove an image measurement")
  .addPositionalParam("osImageHash", "Image measurement")
  .setAction(async ({ osImageHash }, { ethers }) => {
    const kmsContract = await getKmsContract(ethers);
    const tx = await kmsContract.removeOsImageHash(osImageHash);
    await waitTx(tx);
    console.log("Image removed successfully");
  });

task("kms:add-device", "Add a device ID of an KMS instance")
  .addPositionalParam("deviceId", "Device ID")
  .setAction(async ({ deviceId }, { ethers }) => {
    const kmsContract = await getKmsContract(ethers);
    const tx = await kmsContract.addKmsDevice(deviceId);
    await waitTx(tx);
    console.log("Device compose hash added successfully");
  });

task("kms:remove-device", "Remove a device ID")
  .addPositionalParam("deviceId", "Device ID to remove")
  .setAction(async ({ deviceId }, { ethers }) => {
    const kmsContract = await getKmsContract(ethers);
    const tx = await kmsContract.removeKmsDevice(deviceId);
    await waitTx(tx);
    console.log("Device ID removed successfully");
  });

task("info:kms", "Get current KMS information")
  .setAction(async (_, { ethers }) => {
    const kmsContract = await getKmsContract(ethers);
    const kmsInfo = await kmsContract.kmsInfo();
    console.log("KMS Info:", {
      k256Pubkey: kmsInfo.k256Pubkey,
      caPubkey: kmsInfo.caPubkey,
      quote: kmsInfo.quote
    });
  });

task("info:gateway", "Get current Gateway App ID")
  .setAction(async (_, { ethers }) => {
    const kmsContract = await getKmsContract(ethers);
    const appId = await kmsContract.gatewayAppId();
    console.log("Gateway App ID:", appId);
  });

task("kms:set-app-implementation", "Set DstackApp implementation for factory deployment")
  .addPositionalParam("implementation", "DstackApp implementation address")
  .setAction(async ({ implementation }, { ethers }) => {
    const kmsContract = await getKmsContract(ethers);
    const tx = await kmsContract.setAppImplementation(implementation);
    await waitTx(tx);
    console.log("DstackApp implementation set successfully");
  });

task("kms:get-app-implementation", "Get current DstackApp implementation address")
  .setAction(async (_, { ethers }) => {
    const kmsContract = await getKmsContract(ethers);
    const impl = await kmsContract.appImplementation();
    console.log("DstackApp implementation:", impl);
  });

task("app:deploy", "Deploy DstackApp with a UUPS proxy")
  .addFlag("allowAnyDevice", "Allow any device to boot this app")
  .addOptionalParam("device", "Initial device ID", "", types.string)
  .addOptionalParam("hash", "Initial compose hash", "", types.string)
  .setAction(async (taskArgs, hre) => {
    const { ethers } = hre;
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();
    console.log("Deploying with account:", deployerAddress);
    console.log("Account balance:", await accountBalance(ethers, deployerAddress));

    const kmsContract = await getKmsContract(ethers);

    // Parse device and hash (convert to bytes32, use 0x0 if empty)
    const deviceId = taskArgs.device ? taskArgs.device.trim() : "0x0000000000000000000000000000000000000000000000000000000000000000";
    const composeHash = taskArgs.hash ? taskArgs.hash.trim() : "0x0000000000000000000000000000000000000000000000000000000000000000";
    
    const hasInitialData = deviceId !== "0x0000000000000000000000000000000000000000000000000000000000000000" || 
                          composeHash !== "0x0000000000000000000000000000000000000000000000000000000000000000";

    if (hasInitialData) {
      console.log("Initial device:", deviceId === "0x0000000000000000000000000000000000000000000000000000000000000000" ? "none" : deviceId);
      console.log("Initial compose hash:", composeHash === "0x0000000000000000000000000000000000000000000000000000000000000000" ? "none" : composeHash);
    }

    // Use standard deployment - all cases use the same 6-parameter initializer
    const appContract = await deployContract(hre, "DstackApp", [
      deployerAddress, 
      false, 
      taskArgs.allowAnyDevice,
      deviceId,
      composeHash
    ]);
    
    if (!appContract) {
      return;
    }
    
    await appContract.waitForDeployment();
    const proxyAddress = await appContract.getAddress();
    console.log("DstackApp deployed to:", proxyAddress);

    const tx = await kmsContract.registerApp(proxyAddress);
    const receipt = await waitTx(tx);
    
    // Parse the AppRegistered event from the logs
    let appRegisteredEvent = null;
    for (const log of receipt.logs) {
      try {
        const parsedLog = kmsContract.interface.parseLog({
          topics: log.topics,
          data: log.data
        });
        
        if (parsedLog?.name === 'AppRegistered') {
          appRegisteredEvent = parsedLog.args;
          break;
        }
      } catch (e) {
        continue;
      }
    }

    if (appRegisteredEvent) {
      console.log("✅ App deployed and registered successfully!");
      console.log("App ID:", appRegisteredEvent.appId);
      console.log("Proxy Address:", proxyAddress);
      console.log("Owner:", deployerAddress);
      console.log("Transaction hash:", tx.hash);
      
      if (hasInitialData) {
        const hasDevice = deviceId !== "0x0000000000000000000000000000000000000000000000000000000000000000";
        const hasHash = composeHash !== "0x0000000000000000000000000000000000000000000000000000000000000000";
        console.log(`Deployed with ${hasDevice ? "1" : "0"} initial device and ${hasHash ? "1" : "0"} initial compose hash`);
      }
    } else {
      console.log("✅ App deployed and registered successfully!");
      console.log("Proxy Address:", proxyAddress);
      console.log("Transaction hash:", tx.hash);
      
      if (hasInitialData) {
        const hasDevice = deviceId !== "0x0000000000000000000000000000000000000000000000000000000000000000";
        const hasHash = composeHash !== "0x0000000000000000000000000000000000000000000000000000000000000000";
        console.log(`Deployed with ${hasDevice ? "1" : "0"} initial device and ${hasHash ? "1" : "0"} initial compose hash`);
      }
    }
  });


task("kms:create-app", "Create DstackApp via KMS factory method (single transaction)")
  .addFlag("allowAnyDevice", "Allow any device to boot this app")
  .addFlag("requireTcbUpToDate", "Require TCB status to be UpToDate")
  .addOptionalParam("device", "Initial device ID", "", types.string)
  .addOptionalParam("hash", "Initial compose hash", "", types.string)
  .setAction(async (taskArgs, hre) => {
    const { ethers } = hre;
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();
    console.log("Deploying with account:", deployerAddress);
    console.log("Account balance:", await accountBalance(ethers, deployerAddress));

    const kmsContract = await getKmsContract(ethers);
    
    const deviceId = taskArgs.device ? taskArgs.device.trim() : "0x0000000000000000000000000000000000000000000000000000000000000000";
    const composeHash = taskArgs.hash ? taskArgs.hash.trim() : "0x0000000000000000000000000000000000000000000000000000000000000000";
    
    console.log("Initial device:", deviceId === "0x0000000000000000000000000000000000000000000000000000000000000000" ? "none" : deviceId);
    console.log("Initial compose hash:", composeHash === "0x0000000000000000000000000000000000000000000000000000000000000000" ? "none" : composeHash);
    console.log("Using factory method for single-transaction deployment...");
    
    // Single transaction deployment via factory
    const tx = await kmsContract.deployAndRegisterApp(
      deployerAddress,  // deployer owns the contract
      false,           // disableUpgrades
      taskArgs.requireTcbUpToDate,
      taskArgs.allowAnyDevice,
      deviceId,
      composeHash
    );
    
    const receipt = await waitTx(tx);
    
    // Parse events using contract interface
    let factoryEvent = null;
    let registeredEvent = null;
    
    for (const log of receipt.logs) {
      try {
        const parsedLog = kmsContract.interface.parseLog({
          topics: log.topics,
          data: log.data
        });
        
        if (parsedLog?.name === 'AppDeployedViaFactory') {
          factoryEvent = parsedLog.args;
        } else if (parsedLog?.name === 'AppRegistered') {
          registeredEvent = parsedLog.args;
        }
      } catch (e) {
        // Skip logs that can't be parsed by this contract
        continue;
      }
    }
    
    if (factoryEvent && registeredEvent) {
      console.log("✅ App deployed and registered successfully!");
      console.log("Proxy Address (App Id):", factoryEvent.appId);
      console.log("Owner:", factoryEvent.deployer);
      console.log("Transaction hash:", tx.hash);
      
      const hasDevice = deviceId !== "0x0000000000000000000000000000000000000000000000000000000000000000";
      const hasHash = composeHash !== "0x0000000000000000000000000000000000000000000000000000000000000000";
      console.log(`Deployed with ${hasDevice ? "1" : "0"} initial device and ${hasHash ? "1" : "0"} initial compose hash`);
    } else {
      console.log("✅ App deployed and registered successfully!");
      console.log("Transaction hash:", tx.hash);
      
      const hasDevice = deviceId !== "0x0000000000000000000000000000000000000000000000000000000000000000";
      const hasHash = composeHash !== "0x0000000000000000000000000000000000000000000000000000000000000000";
      console.log(`Deployed with ${hasDevice ? "1" : "0"} initial device and ${hasHash ? "1" : "0"} initial compose hash`);
      
      // If we can't parse events, suggest manual verification
      console.log("💡 To verify deployment, use:");
      console.log(`cast call ${KMS_CONTRACT_ADDRESS} "nextAppSequence(address)" "${deployerAddress}" --rpc-url \${RPC_URL}`);
    }
  });

task("app:upgrade", "Upgrade the DstackApp contract")
  .addParam("address", "The address of the contract to upgrade", undefined, types.string, false)
  .addFlag("dryRun", "Simulate the upgrade without executing it")
  .setAction(async (taskArgs, hre) => {
    await upgradeContract(hre, "DstackApp", taskArgs.address, taskArgs.dryRun);
  });

task("app:add-hash", "Add a compose hash to the DstackApp contract")
  .addParam("appId", "App ID")
  .addPositionalParam("hash", "Compose hash to add")
  .setAction(async ({ appId, hash }, { ethers }) => {
    const appContract = await getAppContract(ethers, appId);
    const tx = await appContract.addComposeHash(hash);
    await waitTx(tx);
    console.log("Compose hash added successfully");
  });

task("app:remove-hash", "Remove a compose hash from the DstackApp contract")
  .addParam("appId", "App ID")
  .addPositionalParam("hash", "Compose hash to remove")
  .setAction(async ({ appId, hash }, { ethers }) => {
    const appContract = await getAppContract(ethers, appId);
    const tx = await appContract.removeComposeHash(hash);
    await waitTx(tx);
    console.log("Compose hash removed successfully");
  });

task("app:add-device", "Add a device ID to the DstackApp contract")
  .addParam("appId", "App ID")
  .addPositionalParam("deviceId", "Device ID to add")
  .setAction(async ({ appId, deviceId }, { ethers }) => {
    const appContract = await getAppContract(ethers, appId);
    const tx = await appContract.addDevice(deviceId);
    await waitTx(tx);
    console.log("Device ID added successfully");
  });

task("app:remove-device", "Remove a device ID from the DstackApp contract")
  .addParam("appId", "App ID")
  .addPositionalParam("deviceId", "Device ID to remove")
  .setAction(async ({ appId, deviceId }, { ethers }) => {
    const appContract = await getAppContract(ethers, appId);
    const tx = await appContract.removeDevice(deviceId);
    await waitTx(tx);
    console.log("Device ID removed successfully");
  });

task("app:set-allow-any-device", "Set whether any device is allowed to boot this app")
  .addParam("appId", "App ID")
  .addFlag("allowAnyDevice", "Allow any device to boot this app")
  .setAction(async ({ appId, allowAnyDevice }, { ethers }) => {
    const appContract = await getAppContract(ethers, appId);
    const tx = await appContract.setAllowAnyDevice(allowAnyDevice);
    await waitTx(tx);
    console.log("Allow any device set successfully");
  });

task("kms:deploy-impl", "Deploy DstackKms implementation contract")
  .setAction(async (_, hre) => {
    const { ethers } = hre;
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();
    console.log("deploying DstackKms implementation with account:", deployerAddress);
    console.log("account balance:", await accountBalance(ethers, deployerAddress));

    const DstackKms = await ethers.getContractFactory("DstackKms");
    console.log("deploying DstackKms implementation...");
    const kmsContractImpl = await DstackKms.deploy();
    await kmsContractImpl.waitForDeployment();
    
    const address = await kmsContractImpl.getAddress();
    console.log("✅ DstackKms implementation deployed to:", address);
    return address;
  });

task("app:deploy-impl", "Deploy DstackApp implementation contract")
  .setAction(async (_, hre) => {
    const { ethers } = hre;
    const [deployer] = await ethers.getSigners();
    const deployerAddress = await deployer.getAddress();
    console.log("deploying DstackApp implementation with account:", deployerAddress);
    console.log("account balance:", await accountBalance(ethers, deployerAddress));

    const DstackApp = await ethers.getContractFactory("DstackApp");
    console.log("deploying DstackApp implementation...");
    const appContractImpl = await DstackApp.deploy();
    await appContractImpl.waitForDeployment();
    
    const address = await appContractImpl.getAddress();
    console.log("✅ DstackApp implementation deployed to:", address);
    return address;
  });
