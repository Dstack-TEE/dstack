/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

// The epoch-less setters of app policies predating app epochs (v0.5.x,
// v0.6.0), which report IAppAuthBasicManagement instead of IAppEpochManagement.
interface ILegacyAppManagement {
    function addComposeHash(bytes32 composeHash) external;
    function removeComposeHash(bytes32 composeHash) external;
    function addDevice(bytes32 deviceId) external;
    function removeDevice(bytes32 deviceId) external;
}

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

    // The rows a policy change applies to: `single` names one epoch, `from` and
    // `to` a range. There is no default, so a change never misses a row
    // silently.
    function epochRange(
        string memory single,
        string memory from,
        string memory to
    )
        internal
        view
        returns (uint256, uint256)
    {
        if (vm.envExists(single)) {
            uint256 epoch = vm.envUint(single);
            return (epoch, epoch);
        }
        require(vm.envExists(from) && vm.envExists(to), string.concat("set ", single, ", or ", from, " and ", to));
        return (vm.envUint(from), vm.envUint(to));
    }

    // TEE_VARIANTS: `any`, or the comma-separated platform names, as the KMS
    // reports them, that alone are allowed.
    function teeVariants() internal view returns (bool any, string[] memory names) {
        names = vm.envString("TEE_VARIANTS", ",");
        require(names.length > 0 && bytes(names[0]).length > 0, "set TEE_VARIANTS to any or platform names");
        any = names.length == 1 && keccak256(bytes(names[0])) == keccak256("any");
    }

    function rootEpochs() internal view returns (uint256, uint256) {
        return epochRange("ROOT_EPOCH", "FROM_ROOT_EPOCH", "TO_ROOT_EPOCH");
    }

    function appEpochs() internal view returns (uint256, uint256) {
        return epochRange("APP_EPOCH", "FROM_APP_EPOCH", "TO_APP_EPOCH");
    }

    // The legacy setters of an app without IAppEpochManagement, or none. Such
    // an app has only app epoch 0, so only APP_EPOCH=0, or no epoch, applies.
    function legacyApp() internal view returns (ILegacyAppManagement legacy) {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        if (ERC165Checker.supportsInterface(address(app), type(IAppEpochManagement).interfaceId)) {
            return ILegacyAppManagement(address(0));
        }
        require(
            !vm.envExists("FROM_APP_EPOCH") && !vm.envExists("TO_APP_EPOCH") && vm.envOr("APP_EPOCH", uint256(0)) == 0,
            "this app predates app epochs: only APP_EPOCH=0 applies"
        );
        return ILegacyAppManagement(address(app));
    }
}

// KMS Management Scripts
contract AddKmsAggregatedMr is BaseScript {
    function run() external {
        bytes32 mrAggregated = vm.envBytes32("MR_AGGREGATED");

        (uint256 from, uint256 to) = rootEpochs();
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.addKmsAggregatedMrAtEpochs(from, to, mrAggregated);
        vm.stopBroadcast();

        console.log("Added KMS aggregated MR:", vm.toString(mrAggregated));
    }
}

contract RemoveKmsAggregatedMr is BaseScript {
    function run() external {
        bytes32 mrAggregated = vm.envBytes32("MR_AGGREGATED");

        (uint256 from, uint256 to) = rootEpochs();
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.removeKmsAggregatedMrAtEpochs(from, to, mrAggregated);
        vm.stopBroadcast();

        console.log("Removed KMS aggregated MR:", vm.toString(mrAggregated));
    }
}

contract AddOsImage is BaseScript {
    function run() external {
        bytes32 imageHash = vm.envBytes32("OS_IMAGE_HASH");

        (uint256 from, uint256 to) = rootEpochs();
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.addOsImageHashAtEpochs(from, to, imageHash);
        vm.stopBroadcast();

        console.log("Added OS image hash:", vm.toString(imageHash));
    }
}

contract AddKmsDevice is BaseScript {
    function run() external {
        bytes32 deviceId = vm.envBytes32("DEVICE_ID");

        (uint256 from, uint256 to) = rootEpochs();
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.addKmsDeviceAtEpochs(from, to, deviceId);
        vm.stopBroadcast();

        console.log("Added KMS device:", vm.toString(deviceId));
    }
}

contract SetKmsTeeVariants is BaseScript {
    function run() external {
        (bool any, string[] memory names) = teeVariants();

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        // Write the list before restricting, so the restriction never applies to a stale one.
        if (!any) kms.setAllowedTeeVariants(names);
        kms.setAllowAnyTeeVariant(any);
        vm.stopBroadcast();

        console.log("Set KMS TEE variants to:", vm.envString("TEE_VARIANTS"));
    }
}

contract RequireKmsLaunchTicket is BaseScript {
    function run() external {
        bool required = vm.envBool("REQUIRE_LAUNCH_TICKET");
        vm.broadcast(vm.envUint("PRIVATE_KEY"));
        kms.setRequireKmsLaunchTicket(required);
        console.log("Set requireKmsLaunchTicket to:", required);
    }
}

contract AddKmsLaunchTicket is BaseScript {
    function run() external {
        bytes32 ticketHash = vm.envBytes32("LAUNCH_TICKET_HASH");
        vm.broadcast(vm.envUint("PRIVATE_KEY"));
        kms.addKmsLaunchTicket(ticketHash, vm.envString("LAUNCH_TICKET_LABEL"));
        console.log("Added KMS launch ticket:", vm.toString(ticketHash));
    }
}

contract RemoveKmsLaunchTicket is BaseScript {
    function run() external {
        bytes32 ticketHash = vm.envBytes32("LAUNCH_TICKET_HASH");
        vm.broadcast(vm.envUint("PRIVATE_KEY"));
        kms.removeKmsLaunchTicket(ticketHash);
        console.log("Removed KMS launch ticket:", vm.toString(ticketHash));
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

contract RegisterRootEpoch is BaseScript {
    function run() external {
        bytes memory caPubkey = vm.envBytes("CA_PUBKEY");
        bytes memory k256Pubkey = vm.envBytes("K256_PUBKEY");
        string memory evidenceUrl = vm.envString("EVIDENCE_URL");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        uint256 epoch = kms.registerRootEpoch(caPubkey, k256Pubkey, evidenceUrl);
        vm.stopBroadcast();

        console.log("Registered KMS root epoch", epoch);
    }
}

contract ActivateRootEpoch is BaseScript {
    function run() external {
        uint256 epoch = vm.envUint("ROOT_EPOCH");
        bytes32 chainHash = vm.envBytes32("CHAIN_HASH");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.activateRootEpoch(epoch, chainHash);
        vm.stopBroadcast();

        console.log("Activated KMS root epoch", epoch);
    }
}

contract SetRootEpochEvidenceUrl is BaseScript {
    function run() external {
        uint256 epoch = vm.envUint("ROOT_EPOCH");
        string memory evidenceUrl = vm.envString("EVIDENCE_URL");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.setRootEpochEvidenceUrl(epoch, evidenceUrl);
        vm.stopBroadcast();

        console.log("Updated the evidence URL of KMS root epoch", epoch);
    }
}

contract PopRootEpoch is BaseScript {
    function run() external {
        uint256 epoch = vm.envUint("ROOT_EPOCH");
        bytes32 chainHash = vm.envBytes32("CHAIN_HASH");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.popRootEpoch(epoch, chainHash);
        vm.stopBroadcast();

        console.log("Popped pending KMS root epoch", epoch);
    }
}

// App Management Scripts
contract AddComposeHash is BaseScript {
    function run() external {
        bytes32 composeHash = vm.envBytes32("COMPOSE_HASH");

        ILegacyAppManagement legacy = legacyApp();
        if (address(legacy) != address(0)) {
            vm.broadcast(vm.envUint("PRIVATE_KEY"));
            legacy.addComposeHash(composeHash);
        } else {
            (uint256 from, uint256 to) = appEpochs();
            vm.broadcast(vm.envUint("PRIVATE_KEY"));
            app.addComposeHashAtEpochs(from, to, composeHash);
        }

        console.log("Added compose hash:", vm.toString(composeHash));
    }
}

contract AddDevice is BaseScript {
    function run() external {
        bytes32 deviceId = vm.envBytes32("DEVICE_ID");

        ILegacyAppManagement legacy = legacyApp();
        if (address(legacy) != address(0)) {
            vm.broadcast(vm.envUint("PRIVATE_KEY"));
            legacy.addDevice(deviceId);
        } else {
            (uint256 from, uint256 to) = appEpochs();
            vm.broadcast(vm.envUint("PRIVATE_KEY"));
            app.addDeviceAtEpochs(from, to, deviceId);
        }

        console.log("Added device:", vm.toString(deviceId));
    }
}

contract SetAllowAnyDevice is BaseScript {
    function run() external {
        bool allow = vm.envBool("ALLOW_ANY_DEVICE");
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        require(
            !vm.envExists("APP_EPOCH") && !vm.envExists("FROM_APP_EPOCH") && !vm.envExists("TO_APP_EPOCH"),
            "allowAnyDevice covers every app epoch: unset APP_EPOCH, FROM_APP_EPOCH and TO_APP_EPOCH"
        );

        // Apps with and without app epochs share this setter.
        vm.broadcast(vm.envUint("PRIVATE_KEY"));
        app.setAllowAnyDevice(allow);

        console.log("Set allowAnyDevice to:", allow);
    }
}

contract SetTeeVariants is BaseScript {
    function run() external {
        (bool any, string[] memory names) = teeVariants();
        require(address(legacyApp()) == address(0), "this app predates TEE variant policies");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        // Write the list before restricting, so the restriction never applies to a stale one.
        if (!any) app.setAllowedTeeVariants(names);
        app.setAllowAnyTeeVariant(any);
        vm.stopBroadcast();

        console.log("Set TEE variants to:", vm.envString("TEE_VARIANTS"));
    }
}

contract RequireLaunchTicket is BaseScript {
    function run() external {
        bool required = vm.envBool("REQUIRE_LAUNCH_TICKET");
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        vm.broadcast(vm.envUint("PRIVATE_KEY"));
        app.setRequireLaunchTicket(required);
        console.log("Set requireLaunchTicket to:", required);
    }
}

contract AddLaunchTicket is BaseScript {
    function run() external {
        bytes32 ticketHash = vm.envBytes32("LAUNCH_TICKET_HASH");
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        vm.broadcast(vm.envUint("PRIVATE_KEY"));
        app.addLaunchTicket(ticketHash, vm.envString("LAUNCH_TICKET_LABEL"));
        console.log("Added launch ticket:", vm.toString(ticketHash));
    }
}

contract RemoveLaunchTicket is BaseScript {
    function run() external {
        bytes32 ticketHash = vm.envBytes32("LAUNCH_TICKET_HASH");
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        vm.broadcast(vm.envUint("PRIVATE_KEY"));
        app.removeLaunchTicket(ticketHash);
        console.log("Removed launch ticket:", vm.toString(ticketHash));
    }
}

// Factory Deployment
contract DeployApp is BaseScript {
    function run() external returns (address) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address owner = vm.envOr("APP_OWNER", vm.addr(pk));
        bool disableUpgrades = vm.envOr("DISABLE_UPGRADES", false);
        bool requireTcbUpToDate = vm.envOr("REQUIRE_TCB_UP_TO_DATE", false);
        bool allowAnyDevice = vm.envOr("ALLOW_ANY_DEVICE", true);
        bytes32 deviceId = vm.envOr("INITIAL_DEVICE_ID", bytes32(0));
        bytes32 composeHash = vm.envOr("INITIAL_COMPOSE_HASH", bytes32(0));

        vm.startBroadcast(pk);
        address appAddr = kms.deployAndRegisterApp(
            owner, disableUpgrades, requireTcbUpToDate, allowAnyDevice, deviceId, composeHash
        );
        vm.stopBroadcast();

        console.log("Deployed new app at:", appAddr);
        console.log("  Owner:", owner);
        console.log("  Disable upgrades:", disableUpgrades);
        console.log("  Require TCB up-to-date:", requireTcbUpToDate);
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

        (uint256 from, uint256 to) = rootEpochs();
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));

        // Set gateway ID if provided
        if (bytes(gatewayId).length > 0) {
            kms.setGatewayAppId(gatewayId);
            console.log("Set gateway app ID:", gatewayId);
        }

        // Add aggregated MRs
        for (uint256 i = 0; i < mrAggregated.length; i++) {
            kms.addKmsAggregatedMrAtEpochs(from, to, mrAggregated[i]);
            console.log("Added MR aggregated:", vm.toString(mrAggregated[i]));
        }

        // Add OS images
        for (uint256 i = 0; i < osImages.length; i++) {
            kms.addOsImageHashAtEpochs(from, to, osImages[i]);
            console.log("Added OS image:", vm.toString(osImages[i]));
        }

        // Add devices
        for (uint256 i = 0; i < devices.length; i++) {
            kms.addKmsDeviceAtEpochs(from, to, devices[i]);
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

        (uint256 from, uint256 to) = rootEpochs();
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.removeOsImageHashAtEpochs(from, to, imageHash);
        vm.stopBroadcast();

        console.log("Removed OS image hash:", vm.toString(imageHash));
    }
}

contract RemoveKmsDevice is BaseScript {
    function run() external {
        bytes32 deviceId = vm.envBytes32("DEVICE_ID");

        (uint256 from, uint256 to) = rootEpochs();
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        kms.removeKmsDeviceAtEpochs(from, to, deviceId);
        vm.stopBroadcast();

        console.log("Removed KMS device:", vm.toString(deviceId));
    }
}

// Remove operations for App management
contract RemoveComposeHash is BaseScript {
    function run() external {
        bytes32 composeHash = vm.envBytes32("COMPOSE_HASH");

        ILegacyAppManagement legacy = legacyApp();
        if (address(legacy) != address(0)) {
            vm.broadcast(vm.envUint("PRIVATE_KEY"));
            legacy.removeComposeHash(composeHash);
        } else {
            (uint256 from, uint256 to) = appEpochs();
            vm.broadcast(vm.envUint("PRIVATE_KEY"));
            app.removeComposeHashAtEpochs(from, to, composeHash);
        }

        console.log("Removed compose hash:", vm.toString(composeHash));
    }
}

contract RemoveDevice is BaseScript {
    function run() external {
        bytes32 deviceId = vm.envBytes32("DEVICE_ID");

        ILegacyAppManagement legacy = legacyApp();
        if (address(legacy) != address(0)) {
            vm.broadcast(vm.envUint("PRIVATE_KEY"));
            legacy.removeDevice(deviceId);
        } else {
            (uint256 from, uint256 to) = appEpochs();
            vm.broadcast(vm.envUint("PRIVATE_KEY"));
            app.removeDeviceAtEpochs(from, to, deviceId);
        }

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

// Note: For upgrades, use the dedicated Upgrade.s.sol scripts which include
// storage-layout safety validation. Use `UpgradeKms` / `UpgradeApp` to upgrade
// a live proxy to the current `contracts/DstackKms.sol` / `contracts/DstackApp.sol`
// source. The `UpgradeKmsToV2` / `UpgradeAppToV2` variants target the V2 test
// mocks under `contracts/test-utils/` and are for upgrade-flow tests only.

contract AdvanceAppEpoch is BaseScript {
    function run() external {
        require(address(app) != address(0), "APP_CONTRACT_ADDR not set");
        uint256 expected = vm.envUint("EXPECTED_APP_EPOCH");
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        app.advanceAppEpoch(expected);
        vm.stopBroadcast();
        console.log("Current app epoch:", app.currentAppEpoch());
    }
}
