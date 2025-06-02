import { HardhatRuntimeEnvironment } from "hardhat/types";
import * as helpers from "../lib/deployment-helpers";

// This function can be called directly by Hardhat tasks
export async function upgradeContract(
  hre: HardhatRuntimeEnvironment,
  contractName: string,
  proxyAddress?: string,
  dryRun: boolean = false
) {
  try {
    if (!proxyAddress) {
      throw new Error("Proxy address is required but was not provided");
    }

    console.log(`Preparing to upgrade ${contractName} at ${proxyAddress}...`);
    console.log(`Mode: ${dryRun ? "Dry Run (simulation only)" : "Live Upgrade"}`);

    // Get network info to confirm we're on the right network
    await helpers.logNetworkInfo(hre);

    // Prepare the upgrade
    const {
      newImplementationAddress,
      upgradeTx
    } = await helpers.prepareContractUpgrade(hre, proxyAddress, contractName, "uups");

    if (dryRun) {
      console.log("Upgrade transaction data:", upgradeTx);
      return {
        proxyAddress,
        newImplementationAddress,
        upgradeTx
      };
    } else {
      // Estimate the gas cost
      await helpers.estimateUpgradeCost(hre, proxyAddress, upgradeTx);

      // Confirm the upgrade
      const confirmed = await helpers.confirmAction(`Are you sure you want to upgrade ${contractName}?`);
      if (!confirmed) {
        console.log("Upgrade cancelled");
        return;
      }

      console.log("Executing upgrade...");
      // Execute the upgrade
      const upgraded = await helpers.executeContractUpgrade(
        hre,
        proxyAddress,
        contractName,
        "uups"
      );

      return upgraded;
    }
  } catch (error) {
    console.error("Error during upgrade:", error);
    throw error;
  }
}

// For backward compatibility when running the script directly
async function main() {
  const hre = require("hardhat");
  try {
    const proxyAddress = process.env.PROXY_ADDRESS;
    const dryRun = process.env.DRY_RUN === "true";
    const contractName = process.env.CONTRACT_NAME || "KmsAuth";
    await upgradeContract(hre, contractName, proxyAddress, dryRun);
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}

// Only execute if directly run
if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
} 