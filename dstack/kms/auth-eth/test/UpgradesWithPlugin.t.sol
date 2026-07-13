/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "openzeppelin-foundry-upgrades/Upgrades.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";
import "../contracts/IAppAuth.sol";
import "../contracts/test-utils/DstackKmsV2.sol";
import "../contracts/test-utils/DstackAppV2.sol";

contract UpgradesWithPluginTest is Test {
    address public owner;
    address public user;

    event RequireTcbUpToDateSet(bool requireUpToDate);

    function attemptUpgrade(address proxy) external {
        Upgrades.upgradeProxy(proxy, "contracts/test-utils/DstackAppV2.sol:DstackAppV2", "");
    }

    function attemptKmsUpgrade(address proxy) external {
        Upgrades.upgradeProxy(proxy, "contracts/test-utils/DstackKmsV2.sol:DstackKmsV2", "");
    }

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
    }

    function test_DeployUUPSProxy() public {
        vm.startPrank(owner);

        // Deploy DstackApp implementation first
        DstackApp appImpl = new DstackApp();

        // Deploy KMS proxy using OpenZeppelin plugin
        address kmsProxy =
            Upgrades.deployUUPSProxy("DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(appImpl))));

        DstackKms kms = DstackKms(kmsProxy);

        // Verify initialization worked
        assertEq(kms.owner(), owner);
        assertEq(kms.appImplementation(), address(appImpl));

        vm.stopPrank();
    }

    function test_DeployAppUUPSProxy() public {
        vm.startPrank(owner);

        // Deploy App proxy using OpenZeppelin plugin
        address appProxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol",
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bytes32,bytes32)", owner, false, false, bytes32(0), bytes32(0)
            )
        );

        DstackApp app = DstackApp(appProxy);

        // Verify initialization worked
        assertEq(app.owner(), owner);
        assertFalse(app.allowAnyDevice());

        vm.stopPrank();
    }

    function test_UpgradeKmsProxy() public {
        vm.startPrank(owner);

        // Deploy initial proxy
        DstackApp appImpl = new DstackApp();
        address kmsProxy =
            Upgrades.deployUUPSProxy("DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(appImpl))));

        DstackKms kms = DstackKms(kmsProxy);

        // Set some state to verify it's preserved
        kms.setGatewayAppId("original-gateway");
        bytes32 mrAggregated = bytes32(uint256(123));
        kms.addKmsAggregatedMr(mrAggregated);

        // Upgrade to new implementation using plugin
        Upgrades.upgradeProxy(kmsProxy, "DstackKmsV2.sol", "");

        // Verify state is preserved after upgrade
        assertEq(kms.owner(), owner);
        assertEq(kms.gatewayAppId(), "original-gateway");
        assertTrue(kms.kmsAllowedAggregatedMrs(mrAggregated));

        vm.stopPrank();
    }

    function test_UpgradeAppProxy() public {
        vm.startPrank(owner);

        // Deploy initial proxy
        address appProxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol",
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bytes32,bytes32)", owner, false, false, bytes32(0), bytes32(0)
            )
        );

        DstackApp app = DstackApp(appProxy);

        // Set some state to verify it's preserved
        bytes32 deviceId = bytes32(uint256(456));
        bytes32 composeHash = bytes32(uint256(789));
        app.addDevice(deviceId);
        app.addComposeHash(composeHash);
        app.setAllowAnyDevice(true);

        // Upgrade to new implementation using plugin
        Upgrades.upgradeProxy(appProxy, "DstackAppV2.sol", "");

        // Verify state is preserved after upgrade
        assertEq(app.owner(), owner);
        assertTrue(app.allowedDeviceIds(deviceId));
        assertTrue(app.allowedComposeHashes(composeHash));
        assertTrue(app.allowAnyDevice());

        vm.stopPrank();
    }

    function test_UpgradeWithInitialization() public {
        vm.startPrank(owner);

        // Deploy initial proxy
        DstackApp appImpl = new DstackApp();
        address kmsProxy =
            Upgrades.deployUUPSProxy("DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(appImpl))));

        DstackKms kms = DstackKms(kmsProxy);

        // Upgrade with initialization data
        bytes memory initData = abi.encodeCall(DstackKms.setGatewayAppId, ("upgraded-gateway-id"));

        Upgrades.upgradeProxy(kmsProxy, "DstackKmsV2.sol", initData);

        // Verify the initialization happened during upgrade
        assertEq(kms.gatewayAppId(), "upgraded-gateway-id");
        assertEq(kms.owner(), owner);

        vm.stopPrank();
    }

    function test_ValidationChecks() public {
        vm.startPrank(owner);

        // Deploy initial proxy
        DstackApp appImpl = new DstackApp();
        address kmsProxy =
            Upgrades.deployUUPSProxy("DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(appImpl))));

        // The OpenZeppelin plugin automatically validates:
        // - Storage layout compatibility
        // - Implementation contract safety
        // - Proxy upgrade safety

        // This should work fine since DstackKms is upgrade-safe
        Upgrades.upgradeProxy(kmsProxy, "DstackKmsV2.sol", "");

        vm.stopPrank();
    }

    function test_CannotUpgradeWhenDisabled() public {
        vm.startPrank(owner);

        // Deploy app proxy
        address appProxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol",
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bytes32,bytes32)", owner, false, false, bytes32(0), bytes32(0)
            )
        );

        DstackApp app = DstackApp(appProxy);

        // Disable upgrades
        app.disableUpgrades();

        // Try to upgrade - should fail due to our custom _authorizeUpgrade logic
        // Note: OpenZeppelin plugin may bypass UUPS authorization, so we test via try/catch
        try this.attemptUpgrade(appProxy) {
            assertTrue(false, "Upgrade should have failed when disabled");
        } catch {
            // Expected - upgrade should fail
        }

        vm.stopPrank();
    }

    function test_OnlyOwnerCanUpgrade() public {
        vm.startPrank(owner);

        // Deploy initial proxy
        DstackApp appImpl = new DstackApp();
        address kmsProxy =
            Upgrades.deployUUPSProxy("DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(appImpl))));

        vm.stopPrank();

        // Try to upgrade as non-owner
        vm.startPrank(user);
        try this.attemptKmsUpgrade(kmsProxy) {
            assertTrue(false, "Upgrade should have failed for non-owner");
        } catch {
            // Expected - upgrade should fail for non-owner
        }
        vm.stopPrank();
    }

    // Simulates a proxy deployed before the TCB-toggle feature: 5-arg initializer
    // leaves the new `requireTcbUpToDate` slot at zero. After upgrade, the flag
    // must read false (no silent behavior change) and the owner must be able to
    // opt in via setRequireTcbUpToDate.
    function test_UpgradeFromOldInit_TcbDefaultsFalseAndCanBeEnabled() public {
        vm.startPrank(owner);

        address appProxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol",
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bytes32,bytes32)", owner, false, false, bytes32(0), bytes32(0)
            )
        );
        DstackApp app = DstackApp(appProxy);

        // Pre-upgrade: slot is zero
        assertFalse(app.requireTcbUpToDate());

        Upgrades.upgradeProxy(appProxy, "DstackAppV2.sol", "");

        // Post-upgrade: still zero — no silent behavior change for existing proxies
        assertFalse(app.requireTcbUpToDate());

        // Owner can opt in
        vm.expectEmit(true, true, true, true);
        emit RequireTcbUpToDateSet(true);
        app.setRequireTcbUpToDate(true);
        assertTrue(app.requireTcbUpToDate());

        // And opt back out
        app.setRequireTcbUpToDate(false);
        assertFalse(app.requireTcbUpToDate());

        vm.stopPrank();
    }

    // KMS factory: 6-arg overload propagates the TCB flag through to the deployed app.
    function test_FactoryDeploysAppWith6ArgInit_TcbEnforced() public {
        vm.startPrank(owner);

        DstackApp appImpl = new DstackApp();
        address kmsProxy =
            Upgrades.deployUUPSProxy("DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(appImpl))));
        DstackKms kms = DstackKms(kmsProxy);

        bytes32 osImageHash = bytes32(uint256(0xA1));
        bytes32 composeHash = bytes32(uint256(0xA2));
        bytes32 mrAggregated = bytes32(uint256(0xA3));
        kms.addOsImageHash(osImageHash);
        kms.addKmsAggregatedMr(mrAggregated);

        address appId = kms.deployAndRegisterApp(
            owner,
            false, // disableUpgrades
            true, // requireTcbUpToDate
            true, // allowAnyDevice
            bytes32(0),
            composeHash
        );
        DstackApp app = DstackApp(appId);

        assertEq(app.version(), 2);
        assertTrue(app.requireTcbUpToDate());
        assertTrue(app.allowAnyDevice());
        assertTrue(app.allowedComposeHashes(composeHash));

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: appId,
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: bytes32(0),
            mrAggregated: mrAggregated,
            mrSystem: bytes32(0),
            osImageHash: osImageHash,
            tcbStatus: "OutOfDate",
            advisoryIds: new string[](0)
        });
        (bool allowed, string memory reason) = kms.isAppAllowed(bootInfo);
        assertFalse(allowed);
        assertEq(reason, "TCB status is not up to date");

        bootInfo.tcbStatus = "UpToDate";
        (allowed, reason) = kms.isAppAllowed(bootInfo);
        assertTrue(allowed);
        assertEq(reason, "");

        vm.stopPrank();
    }

    // KMS factory: legacy 5-arg overload defaults the TCB flag to false so old
    // SDK callers (e.g. phala-cloud viem clients) keep working unchanged.
    function test_FactoryDeploysAppWith5ArgInit_TcbDefaultsFalse() public {
        vm.startPrank(owner);

        DstackApp appImpl = new DstackApp();
        address kmsProxy =
            Upgrades.deployUUPSProxy("DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(appImpl))));
        DstackKms kms = DstackKms(kmsProxy);

        bytes32 osImageHash = bytes32(uint256(0xB1));
        bytes32 composeHash = bytes32(uint256(0xB2));
        bytes32 mrAggregated = bytes32(uint256(0xB3));
        kms.addOsImageHash(osImageHash);
        kms.addKmsAggregatedMr(mrAggregated);

        address appId = kms.deployAndRegisterApp(
            owner,
            false, // disableUpgrades
            true, // allowAnyDevice
            bytes32(0),
            composeHash
        );
        DstackApp app = DstackApp(appId);

        assertFalse(app.requireTcbUpToDate());

        // Outdated TCB still allowed when flag is off
        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: appId,
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: bytes32(0),
            mrAggregated: mrAggregated,
            mrSystem: bytes32(0),
            osImageHash: osImageHash,
            tcbStatus: "OutOfDate",
            advisoryIds: new string[](0)
        });
        (bool allowed, string memory reason) = kms.isAppAllowed(bootInfo);
        assertTrue(allowed);
        assertEq(reason, "");

        vm.stopPrank();
    }

    function test_ComplexUpgradeScenario() public {
        vm.startPrank(owner);

        // Deploy KMS with app implementation
        DstackApp appImpl = new DstackApp();
        address kmsProxy =
            Upgrades.deployUUPSProxy("DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(appImpl))));

        DstackKms kms = DstackKms(kmsProxy);

        // Deploy an app via the factory
        bytes32 deviceId = bytes32(uint256(123));
        bytes32 composeHash = bytes32(uint256(456));
        address appId = kms.deployAndRegisterApp(
            owner,
            false, // Don't disable upgrades
            false, // Don't allow any device
            deviceId,
            composeHash
        );

        DstackApp app = DstackApp(appId);

        // Set up some complex state
        bytes32 osImageHash = bytes32(uint256(789));
        bytes32 mrAggregated = bytes32(uint256(101_112));

        kms.addOsImageHash(osImageHash);
        kms.addKmsAggregatedMr(mrAggregated);
        kms.setGatewayAppId("complex-test-gateway");

        // Upgrade both contracts
        Upgrades.upgradeProxy(kmsProxy, "DstackKmsV2.sol", "");
        Upgrades.upgradeProxy(appId, "DstackAppV2.sol", "");

        // Verify everything still works after upgrades
        assertTrue(kms.allowedOsImages(osImageHash));
        assertTrue(kms.kmsAllowedAggregatedMrs(mrAggregated));
        assertEq(kms.gatewayAppId(), "complex-test-gateway");
        assertTrue(kms.registeredApps(appId));

        assertTrue(app.allowedDeviceIds(deviceId));
        assertTrue(app.allowedComposeHashes(composeHash));
        assertEq(app.owner(), owner);

        // Test the full flow still works
        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: appId,
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: mrAggregated,
            mrSystem: bytes32(0),
            osImageHash: osImageHash,
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });

        (bool allowed, string memory reason) = kms.isAppAllowed(bootInfo);
        assertTrue(allowed);
        assertEq(reason, "");

        vm.stopPrank();
    }
}
