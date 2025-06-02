import { HardhatRuntimeEnvironment } from "hardhat/types";
import * as helpers from "../lib/deployment-helpers";

// This function should be called directly by Hardhat tasks
export async function deployContract(hre: HardhatRuntimeEnvironment, contractName: string, initializerArgs: any[] = [], quiet: boolean = false) {
  try {
    function log(...msgs: any[]) {
      if (!quiet) {
        console.log(...msgs);
      }
    }

    log(`Starting ${contractName} deployment process...`);

    if (!quiet) {
      // Get network info
      await helpers.logNetworkInfo(hre);
    }

    log("Getting contract factory...");
    const contractFactory = await hre.ethers.getContractFactory(contractName);

    if (!quiet) {
      // Estimate gas for deployment
      await helpers.estimateDeploymentCost(
        hre,
        contractName,
        initializerArgs
      );

      // Prompt for confirmation
      if (!(await helpers.confirmAction('Do you want to proceed with deployment?'))) {
        log('Deployment cancelled');
        return;
      }
    }

    // Deploy using proxy pattern
    log("Deploying proxy...");
    const contract = await hre.upgrades.deployProxy(contractFactory,
      initializerArgs,
      { kind: 'uups' }
    );
    log("Waiting for deployment...");
    await contract.waitForDeployment();

    const address = await contract.getAddress();
    log(`${contractName} Proxy deployed to:`, address);

    // Verify deployment
    await helpers.verifyDeployment(hre, address, quiet);

    const tx = await contract.deploymentTransaction();
    log("Deployment completed successfully");
    log("Transaction hash:", tx?.hash);

    return contract;
  } catch (error) {
    console.error("Error during deployment:", error);
    throw error;
  }
}

// For backward compatibility when running the script directly
async function main() {
  const hre = require("hardhat");
  const deployer = await helpers.getSigner(hre);
  const address = await deployer.getAddress();
  console.log("Deploying with account:", address);
  console.log("Account balance:", await helpers.accountBalance(hre.ethers, address));
  await deployContract(hre, "KmsAuth", [address]);
}

// Only execute if directly run
if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}