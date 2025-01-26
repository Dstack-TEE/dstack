import { ethers } from "hardhat";
import { network as hardhatNetwork } from "hardhat";

async function main() {
  try {
    console.log("Starting deployment process...");

    // Get network info
    const network = await ethers.provider.getNetwork();
    console.log("Network:", network);
    console.log("Network:", {
      name: network.name,
      chainId: network.chainId.toString(),
      rpcUrl: hardhatNetwork.config.url || "default hardhat network"
    });

    // Get signer info
    const [deployer] = await ethers.getSigners();
    console.log("Deploying with account:", await deployer.getAddress());
    console.log("Account balance:", ethers.formatEther(await deployer.provider.getBalance(await deployer.getAddress())));

    console.log("Getting contract factory...");
    const KmsAuth = await ethers.getContractFactory("KmsAuth");

    // Estimate gas for deployment
    console.log("Estimating deployment costs...");
    const deploymentGas = await ethers.provider.estimateGas(
      await KmsAuth.getDeployTransaction()
    );
    const feeData = await ethers.provider.getFeeData();
    const gasPrice = feeData.gasPrice;
    const estimatedCost = deploymentGas * gasPrice;

    console.log("Deployment details:", {
      estimatedGas: deploymentGas.toString(),
      gasPrice: ethers.formatUnits(gasPrice, "gwei") + " gwei",
      estimatedCost: ethers.formatEther(estimatedCost) + " ETH"
    });

    // Convert to ETH for better readability
    const estimatedEth = ethers.formatEther(estimatedCost);
    console.log(`Estimated deployment cost: ${estimatedEth} ETH`);

    // Prompt for confirmation
    const readline = require('readline').createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const confirm = await new Promise(resolve => {
      readline.question('Do you want to proceed with deployment? (y/N): ', answer => {
        readline.close();
        resolve(answer.toLowerCase() === 'y');
      });
    });

    if (!confirm) {
      console.log('Deployment cancelled');
      return;
    }

    const kmsAuth = await KmsAuth.deploy();
    await kmsAuth.waitForDeployment();

    const address = await kmsAuth.getAddress();
    console.log("KmsAuth deployed to:", address);

    // Wait for a few block confirmations to ensure the contract is deployed
    await kmsAuth.deploymentTransaction()?.wait(5);
  } catch (error) {
    console.error("Error during deployment:", error);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});