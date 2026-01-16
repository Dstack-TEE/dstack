/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";

// Base contract with common functionality
abstract contract BaseScript is Script {
    DstackKms public kms;
    DstackApp public app;

    function setUp() public virtual {
        address kmsAddr = vm.envOr("KMS_CONTRACT_ADDR", address(0));
        require(kmsAddr != address(0), "KMS_CONTRACT_ADDR not set");
        kms = DstackKms(kmsAddr);

        address appAddr = vm.envOr("APP_CONTRACT_ADDR", address(0));
        if (appAddr != address(0)) {
            app = DstackApp(appAddr);
        }
    }
}

// KMS Management Scripts
contract AddKmsAggregatedMr is BaseScript {
    function run() external {
        bytes32 mrAggregated = vm.envBytes32("MR_AGGREGATED");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.addKmsAggregatedMr(mrAggregated);
        vm.stopBroadcast();

        console.log("Added KMS aggregated MR:", vm.toString(mrAggregated));
    }
}

contract RemoveKmsAggregatedMr is BaseScript {
    function run() external {
        bytes32 mrAggregated = vm.envBytes32("MR_AGGREGATED");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.removeKmsAggregatedMr(mrAggregated);
        vm.stopBroadcast();

        console.log("Removed KMS aggregated MR:", vm.toString(mrAggregated));
    }
}

contract AddOsImage is BaseScript {
    function run() external {
        bytes32 imageHash = vm.envBytes32("OS_IMAGE_HASH");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.addOsImageHash(imageHash);
        vm.stopBroadcast();

        console.log("Added OS image hash:", vm.toString(imageHash));
    }
}

contract AddKmsDevice is BaseScript {
    function run() external {
        bytes32 deviceId = vm.envBytes32("DEVICE_ID");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.addKmsDevice(deviceId);
        vm.stopBroadcast();

        console.log("Added KMS device:", vm.toString(deviceId));
    }
}

contract SetGatewayAppId is BaseScript {
    function run() external {
        string memory gatewayId = vm.envString("GATEWAY_APP_ID");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.setGatewayAppId(gatewayId);
        vm.stopBroadcast();

        console.log("Set gateway app ID:", gatewayId);
    }
}

contract SetKmsInfo is BaseScript {
    function run() external {
        bytes memory k256Pubkey = vm.envBytes("K256_PUBKEY");
        bytes memory caPubkey = vm.envBytes("CA_PUBKEY");
        bytes memory quote = vm.envBytes("QUOTE");
        bytes memory eventlog = vm.envBytes("EVENTLOG");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.setKmsInfo(
            DstackKms.KmsInfo({ k256Pubkey: k256Pubkey, caPubkey: caPubkey, quote: quote, eventlog: eventlog })
        );
        vm.stopBroadcast();

        console.log("KMS info set successfully");
        console.log("  K256 Pubkey length:", k256Pubkey.length);
        console.log("  CA Pubkey length:", caPubkey.length);
        console.log("  Quote length:", quote.length);
        console.log("  Eventlog length:", eventlog.length);
    }
}

// App Management Scripts
contract AddComposeHash is BaseScript {
    function run() external {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        bytes32 composeHash = vm.envBytes32("COMPOSE_HASH");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        app.addComposeHash(composeHash);
        vm.stopBroadcast();

        console.log("Added compose hash:", vm.toString(composeHash));
    }
}

contract AddDevice is BaseScript {
    function run() external {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        bytes32 deviceId = vm.envBytes32("DEVICE_ID");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        app.addDevice(deviceId);
        vm.stopBroadcast();

        console.log("Added device:", vm.toString(deviceId));
    }
}

contract SetAllowAnyDevice is BaseScript {
    function run() external {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        bool allow = vm.envBool("ALLOW_ANY_DEVICE");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        app.setAllowAnyDevice(allow);
        vm.stopBroadcast();

        console.log("Set allowAnyDevice to:", allow);
    }
}

// Factory Deployment
contract DeployApp is BaseScript {
    function run() external returns (address) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address owner = vm.envOr("APP_OWNER", vm.addr(pk));
        bool disableUpgrades = vm.envOr("DISABLE_UPGRADES", false);
        bool allowAnyDevice = vm.envOr("ALLOW_ANY_DEVICE", true);
        bytes32 deviceId = vm.envOr("INITIAL_DEVICE_ID", bytes32(0));
        bytes32 composeHash = vm.envOr("INITIAL_COMPOSE_HASH", bytes32(0));

        vm.startBroadcast(pk);
        address appAddr = kms.deployAndRegisterApp(owner, disableUpgrades, allowAnyDevice, deviceId, composeHash);
        vm.stopBroadcast();

        console.log("Deployed new app at:", appAddr);
        console.log("  Owner:", owner);
        console.log("  Disable upgrades:", disableUpgrades);
        console.log("  Allow any device:", allowAnyDevice);
        if (deviceId != bytes32(0)) {
            console.log("  Initial device ID:", vm.toString(deviceId));
        }
        if (composeHash != bytes32(0)) {
            console.log("  Initial compose hash:", vm.toString(composeHash));
        }

        return appAddr;
    }
}

contract ShowAppInfo is BaseScript {
    function run() external view {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");

        console.log("=== App Information ===");
        console.log("App Contract:", address(app));
        console.log("Owner:", app.owner());
        console.log("Allow Any Device:", app.allowAnyDevice());
    }
}

// Batch Operations Script
contract BatchKmsSetup is BaseScript {
    function run() external {
        // Load multiple values from environment
        string memory gatewayId = vm.envOr("GATEWAY_APP_ID", string(""));
        bytes32[] memory mrAggregated = vm.envOr("MR_AGGREGATED_LIST", ",", new bytes32[](0));
        bytes32[] memory osImages = vm.envOr("OS_IMAGE_LIST", ",", new bytes32[](0));
        bytes32[] memory devices = vm.envOr("DEVICE_LIST", ",", new bytes32[](0));

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));

        // Set gateway ID if provided
        if (bytes(gatewayId).length > 0) {
            kms.setGatewayAppId(gatewayId);
            console.log("Set gateway app ID:", gatewayId);
        }

        // Add aggregated MRs
        for (uint256 i = 0; i < mrAggregated.length; i++) {
            kms.addKmsAggregatedMr(mrAggregated[i]);
            console.log("Added MR aggregated:", vm.toString(mrAggregated[i]));
        }

        // Add OS images
        for (uint256 i = 0; i < osImages.length; i++) {
            kms.addOsImageHash(osImages[i]);
            console.log("Added OS image:", vm.toString(osImages[i]));
        }

        // Add devices
        for (uint256 i = 0; i < devices.length; i++) {
            kms.addKmsDevice(devices[i]);
            console.log("Added device:", vm.toString(devices[i]));
        }

        vm.stopBroadcast();

        console.log("\nBatch KMS setup completed!");
    }
}

// Remove operations for KMS management

contract RemoveOsImage is BaseScript {
    function run() external {
        bytes32 imageHash = vm.envBytes32("OS_IMAGE_HASH");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.removeOsImageHash(imageHash);
        vm.stopBroadcast();

        console.log("Removed OS image hash:", vm.toString(imageHash));
    }
}

contract RemoveKmsDevice is BaseScript {
    function run() external {
        bytes32 deviceId = vm.envBytes32("DEVICE_ID");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.removeKmsDevice(deviceId);
        vm.stopBroadcast();

        console.log("Removed KMS device:", vm.toString(deviceId));
    }
}

// Remove operations for App management
contract RemoveComposeHash is BaseScript {
    function run() external {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        bytes32 composeHash = vm.envBytes32("COMPOSE_HASH");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        app.removeComposeHash(composeHash);
        vm.stopBroadcast();

        console.log("Removed compose hash:", vm.toString(composeHash));
    }
}

contract RemoveDevice is BaseScript {
    function run() external {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        bytes32 deviceId = vm.envBytes32("DEVICE_ID");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        app.removeDevice(deviceId);
        vm.stopBroadcast();

        console.log("Removed device:", vm.toString(deviceId));
    }
}

// Register existing app
contract RegisterApp is BaseScript {
    function run() external {
        address appAddress = vm.envAddress("APP_ADDRESS");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.registerApp(appAddress);
        vm.stopBroadcast();

        console.log("Registered app:", appAddress);
    }
}

// Set app implementation in KMS
contract SetAppImplementation is BaseScript {
    function run() external {
        address appImpl = vm.envAddress("APP_IMPLEMENTATION");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.setAppImplementation(appImpl);
        vm.stopBroadcast();

        console.log("Set app implementation:", appImpl);
    }
}

// Disable upgrades on app
contract DisableAppUpgrades is BaseScript {
    function run() external {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        app.disableUpgrades();
        vm.stopBroadcast();

        console.log("Disabled upgrades for app:", address(app));
    }
}

// Note: For upgrades, use the dedicated Upgrade.s.sol scripts which include safety validation
