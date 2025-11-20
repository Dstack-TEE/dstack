/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import "openzeppelin-foundry-upgrades/Upgrades.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";

// Upgrade to a specific version (e.g., V2)
contract UpgradeKmsToV2 is Script {
    function run() external {
        address kmsProxy = vm.envAddress("KMS_CONTRACT_ADDR");

        console.log("=== Upgrading DstackKms to V2 ===");
        console.log("Proxy address:", kmsProxy);

        vm.startBroadcast();

        // Upgrade to a specific contract version
        Upgrades.upgradeProxy(kmsProxy, "contracts/test-utils/DstackKmsV2.sol:DstackKmsV2", "");

        vm.stopBroadcast();

        console.log("Success: DstackKms upgraded to V2!");
    }
}

contract UpgradeAppToV2 is Script {
    function run() external {
        address appProxy = vm.envAddress("APP_CONTRACT_ADDR");

        console.log("=== Upgrading DstackApp to V2 ===");
        console.log("Proxy address:", appProxy);

        vm.startBroadcast();

        // Upgrade to a specific contract version
        Upgrades.upgradeProxy(appProxy, "contracts/test-utils/DstackAppV2.sol:DstackAppV2", "");

        vm.stopBroadcast();

        console.log("Success: DstackApp upgraded to V2!");
    }
}
