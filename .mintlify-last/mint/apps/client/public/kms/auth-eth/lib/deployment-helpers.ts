import { HardhatRuntimeEnvironment } from "hardhat/types";
import * as readline from 'readline';

/**
 * Helper function to prompt for user confirmation
 */
export async function confirmAction(question: string): Promise<boolean> {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    return new Promise((resolve) => {
        rl.question(`${question} (y/N) `, (answer) => {
            rl.close();
            resolve(answer.toLowerCase() === 'y');
        });
    });
}

/**
 * Get and display network information
 */
export async function logNetworkInfo(hre: HardhatRuntimeEnvironment) {
    const network = await hre.ethers.provider.getNetwork();
    console.log("Network:", {
        name: network.name,
        chainId: network.chainId.toString(),
        // @ts-ignore - different network configs might have different properties
        rpcUrl: hre.network.config.rpcUrls?.[0] ||
            // @ts-ignore - different network configs might have different properties
            hre.network.config.url ||
            "default hardhat network"
    });
    return network;
}

/**
 * Get the signer
 */
export async function getSigner(hre: HardhatRuntimeEnvironment) {
    const [deployer] = await hre.ethers.getSigners();
    return deployer;
}

/**
 * Get and display account information
 */
export async function accountBalance(ethers: any, address: string) {
    return ethers.formatEther(
        await ethers.provider.getBalance(address)
    );
}

/**
 * Estimate and display deployment costs
 */
export async function estimateDeploymentCost(
    hre: HardhatRuntimeEnvironment,
    contractName: string,
    initializerArgs: any[] = []
) {
    console.log("Estimating deployment costs...");
    const factory = await hre.ethers.getContractFactory(contractName);

    // Get the data for initialize function
    const initData = factory.interface.encodeFunctionData(
        "initialize",
        initializerArgs
    );

    // Estimate gas for deployment transaction
    const deploymentGas = await hre.ethers.provider.estimateGas({
        data: factory.bytecode
    });

    // Estimate gas for initialization
    const initGas = await hre.ethers.provider.estimateGas({
        to: hre.ethers.ZeroAddress, // This is just a placeholder
        data: initData
    });

    // Add some buffer for proxy deployment
    const totalEstimatedGas = deploymentGas + initGas + BigInt(206053); // Buffer for proxy overhead

    const feeData = await hre.ethers.provider.getFeeData();
    const gasPrice = feeData.gasPrice || BigInt(0);
    const estimatedCost = totalEstimatedGas * gasPrice;

    console.log("Deployment details:", {
        estimatedGas: deploymentGas.toString(),
        gasPrice: gasPrice ? hre.ethers.formatUnits(gasPrice, "gwei") + " gwei" : "unknown",
        estimatedCost: hre.ethers.formatEther(estimatedCost) + " ETH"
    });

    // Convert to ETH for better readability
    const estimatedEth = hre.ethers.formatEther(estimatedCost);
    console.log(`Estimated deployment cost: ${estimatedEth} ETH`);

    return {
        estimatedGas: totalEstimatedGas,
        gasPrice,
        estimatedCost,
        estimatedEth
    };
}

/**
 * Verify contract deployment
 */
export async function verifyDeployment(
    hre: HardhatRuntimeEnvironment,
    contractAddress: string,
    quiet: boolean = false
) {
    // Verify that contract was deployed successfully
    const code = await hre.ethers.provider.getCode(contractAddress);
    if (code === '0x') {
        throw new Error('Contract deployment failed - no code at address');
    }

    // Get implementation contract address
    const implementationAddress = await hre.upgrades.erc1967.getImplementationAddress(
        contractAddress
    );
    if (!quiet) {
        console.log("Implementation deployed to:", implementationAddress);
    }

    return {
        contractAddress,
        implementationAddress
    };
}

/**
 * Prepare an upgrade and get information about the new implementation
 */
export async function prepareContractUpgrade(
    hre: HardhatRuntimeEnvironment,
    proxyAddress: string,
    contractName: string,
    kind: 'uups' | 'transparent' | 'beacon' = 'uups'
) {
    // Get current implementation address
    const currentImplementationAddress = await hre.upgrades.erc1967.getImplementationAddress(proxyAddress);
    console.log("Current implementation address:", currentImplementationAddress);

    // Get the new implementation contract factory
    const ContractFactory = await hre.ethers.getContractFactory(contractName);

    // Get the new implementation address
    const newImplementationAddress = await hre.upgrades.prepareUpgrade(
        proxyAddress,
        ContractFactory,
        { kind }
    );
    console.log("New implementation address:", newImplementationAddress);

    // Get the proxy contract instance
    const proxyContract = await hre.ethers.getContractAt(contractName, proxyAddress);

    // Create the upgrade transaction data (for UUPS proxies)
    const upgradeTx = await proxyContract.interface.encodeFunctionData(
        "upgradeToAndCall",
        [newImplementationAddress, "0x"]
    );

    return {
        currentImplementationAddress,
        newImplementationAddress,
        proxyContract,
        upgradeTx
    };
}

/**
 * Estimate the gas cost for a contract upgrade
 */
export async function estimateUpgradeCost(
    hre: HardhatRuntimeEnvironment,
    proxyAddress: string,
    upgradeTx: string
) {
    const provider = hre.ethers.provider;
    const feeData = await provider.getFeeData();
    const gasPrice = feeData.gasPrice || BigInt(0);

    // Estimate gas for the upgrade transaction
    const gasLimit = await provider.estimateGas({
        to: proxyAddress,
        data: upgradeTx
    });

    const gasCost = gasPrice * gasLimit;
    const gasCostInEth = hre.ethers.formatEther(gasCost);
    console.log("Estimated gas cost for upgrade:", gasCostInEth, "ETH");

    return {
        gasLimit,
        gasPrice,
        gasCost,
        gasCostInEth
    };
}

/**
 * Execute a contract upgrade
 */
export async function executeContractUpgrade(
    hre: HardhatRuntimeEnvironment,
    proxyAddress: string,
    contractName: string,
    kind: 'uups' | 'transparent' | 'beacon' = 'uups'
) {
    // Get the contract factory
    const ContractFactory = await hre.ethers.getContractFactory(contractName);

    // Upgrade the proxy to the new implementation
    console.log(`Upgrading ${contractName} at ${proxyAddress}...`);
    const upgraded = await hre.upgrades.upgradeProxy(proxyAddress, ContractFactory, {
        kind
    });

    await upgraded.waitForDeployment();
    console.log(`${contractName} upgraded at proxy address:`, await upgraded.getAddress());

    return upgraded;
} 