/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying with account:", deployer);
        console.log("Account balance:", deployer.balance);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy DstackApp implementation
        DstackApp appImpl = new DstackApp();
        console.log("DstackApp implementation deployed to:", address(appImpl));

        // Deploy DstackKms implementation
        DstackKms kmsImpl = new DstackKms();
        console.log("DstackKms implementation deployed to:", address(kmsImpl));

        // Deploy DstackKms proxy
        bytes memory initData = abi.encodeCall(DstackKms.initialize, (deployer, address(appImpl)));
        ERC1967Proxy kmsProxy = new ERC1967Proxy(address(kmsImpl), initData);
        console.log("DstackKms proxy deployed to:", address(kmsProxy));

        vm.stopBroadcast();

        console.log("Deployment complete!");
        console.log("- DstackApp implementation:", address(appImpl));
        console.log("- DstackKms implementation:", address(kmsImpl));
        console.log("- DstackKms proxy:", address(kmsProxy));
    }
}

contract DeployKmsOnly is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address appImplementation = vm.envAddress("APP_IMPLEMENTATION");

        console.log("Deploying DstackKms with account:", deployer);
        console.log("Account balance:", deployer.balance);
        console.log("Using DstackApp implementation:", appImplementation);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy DstackKms implementation
        DstackKms kmsImpl = new DstackKms();
        console.log("DstackKms implementation deployed to:", address(kmsImpl));

        // Deploy DstackKms proxy
        bytes memory initData = abi.encodeCall(DstackKms.initialize, (deployer, appImplementation));
        ERC1967Proxy kmsProxy = new ERC1967Proxy(address(kmsImpl), initData);
        console.log("DstackKms proxy deployed to:", address(kmsProxy));

        vm.stopBroadcast();

        console.log("KMS deployment complete!");
        console.log("- DstackKms implementation:", address(kmsImpl));
        console.log("- DstackKms proxy:", address(kmsProxy));
    }
}

contract DeployAppOnly is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying DstackApp implementation with account:", deployer);
        console.log("Account balance:", deployer.balance);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy DstackApp implementation
        DstackApp appImpl = new DstackApp();
        console.log("DstackApp implementation deployed to:", address(appImpl));

        vm.stopBroadcast();

        console.log("App implementation deployment complete!");
        console.log("- DstackApp implementation:", address(appImpl));
    }
}
