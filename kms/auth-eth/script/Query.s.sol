/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";
import "../contracts/IAppAuth.sol";

/**
 * @title Query Scripts for Read-Only Operations
 * @notice These scripts provide read-only access to contract state
 */

// Base contract with common functionality
abstract contract BaseQueryScript is Script {
    DstackKms public kms;
    DstackApp public app;

    function setUp() public virtual {
        address kmsAddr = vm.envOr("KMS_CONTRACT_ADDR", address(0));
        if (kmsAddr != address(0)) {
            kms = DstackKms(kmsAddr);
        }

        address appAddr = vm.envOr("APP_CONTRACT_ADDR", address(0));
        if (appAddr != address(0)) {
            app = DstackApp(appAddr);
        }
    }
}

// Check if KMS aggregated MR is allowed
contract CheckKmsAggregatedMr is BaseQueryScript {
    function run() external view {
        require(address(kms) != address(0), "KMS_CONTRACT_ADDR not set");
        bytes32 mrAggregated = vm.envBytes32("MR_AGGREGATED");

        bool isAllowed = kms.kmsAllowedAggregatedMrs(mrAggregated);

        console.log("=== KMS Aggregated MR Check ===");
        console.log("MR Aggregated:", vm.toString(mrAggregated));
        console.log("Is Allowed:", isAllowed);
    }
}

// Check if KMS device is allowed
contract CheckKmsDevice is BaseQueryScript {
    function run() external view {
        require(address(kms) != address(0), "KMS_CONTRACT_ADDR not set");
        bytes32 deviceId = vm.envBytes32("DEVICE_ID");

        bool isAllowed = kms.kmsAllowedDeviceIds(deviceId);

        console.log("=== KMS Device Check ===");
        console.log("Device ID:", vm.toString(deviceId));
        console.log("Is Allowed:", isAllowed);
    }
}

// Check if OS image is allowed
contract CheckOsImage is BaseQueryScript {
    function run() external view {
        require(address(kms) != address(0), "KMS_CONTRACT_ADDR not set");
        bytes32 imageHash = vm.envBytes32("OS_IMAGE_HASH");

        bool isAllowed = kms.allowedOsImages(imageHash);

        console.log("=== OS Image Check ===");
        console.log("Image Hash:", vm.toString(imageHash));
        console.log("Is Allowed:", isAllowed);
    }
}

// Check if app is registered
contract CheckAppRegistration is BaseQueryScript {
    function run() external view {
        require(address(kms) != address(0), "KMS_CONTRACT_ADDR not set");
        address appAddress = vm.envAddress("APP_ADDRESS");

        bool isRegistered = kms.registeredApps(appAddress);

        console.log("=== App Registration Check ===");
        console.log("App Address:", appAddress);
        console.log("Is Registered:", isRegistered);
    }
}

// Check if compose hash is allowed in app
contract CheckComposeHash is BaseQueryScript {
    function run() external view {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        bytes32 composeHash = vm.envBytes32("COMPOSE_HASH");

        bool isAllowed = app.allowedComposeHashes(composeHash);

        console.log("=== Compose Hash Check ===");
        console.log("Compose Hash:", vm.toString(composeHash));
        console.log("Is Allowed:", isAllowed);
    }
}

// Check if device is allowed in app
contract CheckAppDevice is BaseQueryScript {
    function run() external view {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        bytes32 deviceId = vm.envBytes32("DEVICE_ID");

        bool isAllowed = app.allowedDeviceIds(deviceId);

        console.log("=== App Device Check ===");
        console.log("Device ID:", vm.toString(deviceId));
        console.log("Is Allowed:", isAllowed);
    }
}

// Check if KMS is allowed to boot
contract CheckKmsAllowed is BaseQueryScript {
    function run() external view {
        require(address(kms) != address(0), "KMS_CONTRACT_ADDR not set");

        // Read boot info from environment
        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: vm.envAddress("APP_ID"),
            composeHash: vm.envBytes32("COMPOSE_HASH"),
            instanceId: vm.envOr("INSTANCE_ID", address(0)),
            deviceId: vm.envBytes32("DEVICE_ID"),
            mrAggregated: vm.envBytes32("MR_AGGREGATED"),
            mrSystem: vm.envOr("MR_SYSTEM", bytes32(0)),
            osImageHash: vm.envBytes32("OS_IMAGE_HASH"),
            tcbStatus: vm.envString("TCB_STATUS"),
            advisoryIds: new string[](0)
        });

        (bool isAllowed, string memory reason) = kms.isKmsAllowed(bootInfo);

        console.log("=== KMS Boot Check ===");
        console.log("Is Allowed:", isAllowed);
        console.log("Reason:", reason);
    }
}

// Check if App is allowed to boot
contract CheckAppAllowed is BaseQueryScript {
    function run() external view {
        require(address(kms) != address(0), "KMS_CONTRACT_ADDR not set");

        // Read boot info from environment
        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: vm.envAddress("APP_ID"),
            composeHash: vm.envBytes32("COMPOSE_HASH"),
            instanceId: vm.envOr("INSTANCE_ID", address(0)),
            deviceId: vm.envBytes32("DEVICE_ID"),
            mrAggregated: vm.envBytes32("MR_AGGREGATED"),
            mrSystem: vm.envOr("MR_SYSTEM", bytes32(0)),
            osImageHash: vm.envBytes32("OS_IMAGE_HASH"),
            tcbStatus: vm.envString("TCB_STATUS"),
            advisoryIds: new string[](0)
        });

        (bool isAllowed, string memory reason) = kms.isAppAllowed(bootInfo);

        console.log("=== App Boot Check ===");
        console.log("Is Allowed:", isAllowed);
        console.log("Reason:", reason);
        console.log("Gateway App ID:", kms.gatewayAppId());
    }
}

// Get storage slot value (useful for proxy verification)
contract GetStorageSlot is Script {
    function run() external view {
        address target = vm.envAddress("TARGET_ADDRESS");
        bytes32 slot = vm.envBytes32("STORAGE_SLOT");

        bytes32 value = vm.load(target, slot);

        console.log("=== Storage Slot Value ===");
        console.log("Address:", target);
        console.log("Slot:", vm.toString(slot));
        console.log("Value:", vm.toString(value));

        // If it's the implementation slot, decode as address
        if (slot == 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc) {
            address impl = address(uint160(uint256(value)));
            console.log("Implementation Address:", impl);
        }
    }
}

// Get all KMS settings in one call
contract GetKmsSettings is BaseQueryScript {
    function run() external view {
        require(address(kms) != address(0), "KMS_CONTRACT_ADDR not set");

        console.log("=== KMS Settings ===");
        console.log("Contract Address:", address(kms));
        console.log("Owner:", kms.owner());
        console.log("Gateway App ID:", kms.gatewayAppId());
        console.log("App Implementation:", kms.appImplementation());

        // Get KMS info
        (bytes memory k256Pubkey, bytes memory caPubkey, bytes memory quote, bytes memory eventlog) = kms.kmsInfo();
        console.log("\nKMS Info:");
        console.log("  K256 Pubkey length:", k256Pubkey.length);
        console.log("  CA Pubkey length:", caPubkey.length);
        console.log("  Quote length:", quote.length);
        console.log("  Eventlog length:", eventlog.length);

        // Check implementation via storage
        bytes32 implSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        address implementation = address(uint160(uint256(vm.load(address(kms), implSlot))));
        console.log("\nProxy Implementation:", implementation);
    }
}

// Get all App settings in one call
contract GetAppSettings is BaseQueryScript {
    function run() external view {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");

        console.log("=== App Settings ===");
        console.log("Contract Address:", address(app));
        console.log("Owner:", app.owner());
        console.log("Allow Any Device:", app.allowAnyDevice());

        // Check implementation via storage
        bytes32 implSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        address implementation = address(uint160(uint256(vm.load(address(app), implSlot))));
        console.log("\nProxy Implementation:", implementation);
    }
}
