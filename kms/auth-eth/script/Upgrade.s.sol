/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "openzeppelin-foundry-upgrades/Upgrades.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";

// Production upgrade path: upgrade the live DstackKms proxy to the current
// `contracts/DstackKms.sol` implementation. Use this for routine upgrades.
contract UpgradeKms is Script {
    function run() external {
        address kmsProxy = vm.envAddress("KMS_CONTRACT_ADDR");

        console.log("=== Upgrading DstackKms (production) ===");
        console.log("Proxy address:", kmsProxy);

        vm.startBroadcast();
        Upgrades.upgradeProxy(kmsProxy, "DstackKms.sol", "");
        vm.stopBroadcast();

        console.log("Success: DstackKms upgraded.");
    }
}

// Production upgrade path: upgrade a live DstackApp proxy to the current
// `contracts/DstackApp.sol` implementation.
contract UpgradeApp is Script {
    function run() external {
        address appProxy = vm.envAddress("APP_CONTRACT_ADDR");

        console.log("=== Upgrading DstackApp (production) ===");
        console.log("Proxy address:", appProxy);

        vm.startBroadcast();
        Upgrades.upgradeProxy(appProxy, "DstackApp.sol", "");
        vm.stopBroadcast();

        console.log("Success: DstackApp upgraded.");
    }
}

// Test-only: upgrade to a specific version (e.g., V2 mock). The V2 contracts
// in contracts/test-utils/ are scaffolding for the upgrade-flow tests — do
// NOT run these against live proxies.
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
