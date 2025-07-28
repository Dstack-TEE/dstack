// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

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
    
    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
    }
    
    function test_DeployUUPSProxy() public {
        vm.startPrank(owner);
        
        // Deploy DstackApp implementation first
        DstackApp appImpl = new DstackApp();
        
        // Deploy KMS proxy using OpenZeppelin plugin
        address kmsProxy = Upgrades.deployUUPSProxy(
            "DstackKms.sol",
            abi.encodeCall(DstackKms.initialize, (owner, address(appImpl)))
        );
        
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
            abi.encodeCall(DstackApp.initialize, (owner, false, false, bytes32(0), bytes32(0)))
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
        address kmsProxy = Upgrades.deployUUPSProxy(
            "DstackKms.sol",
            abi.encodeCall(DstackKms.initialize, (owner, address(appImpl)))
        );
        
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
            abi.encodeCall(DstackApp.initialize, (owner, false, false, bytes32(0), bytes32(0)))
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
        address kmsProxy = Upgrades.deployUUPSProxy(
            "DstackKms.sol",
            abi.encodeCall(DstackKms.initialize, (owner, address(appImpl)))
        );
        
        DstackKms kms = DstackKms(kmsProxy);
        
        // Upgrade with initialization data
        bytes memory initData = abi.encodeCall(
            DstackKms.setGatewayAppId,
            ("upgraded-gateway-id")
        );
        
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
        address kmsProxy = Upgrades.deployUUPSProxy(
            "DstackKms.sol",
            abi.encodeCall(DstackKms.initialize, (owner, address(appImpl)))
        );
        
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
            abi.encodeCall(DstackApp.initialize, (owner, false, false, bytes32(0), bytes32(0)))
        );
        
        DstackApp app = DstackApp(appProxy);
        
        // Disable upgrades
        app.disableUpgrades();
        
        // Try to upgrade - should fail due to our custom _authorizeUpgrade logic
        vm.expectRevert("Upgrades are permanently disabled");
        Upgrades.upgradeProxy(appProxy, "DstackAppV2.sol", "");
        
        vm.stopPrank();
    }
    
    function test_OnlyOwnerCanUpgrade() public {
        vm.startPrank(owner);
        
        // Deploy initial proxy
        DstackApp appImpl = new DstackApp();
        address kmsProxy = Upgrades.deployUUPSProxy(
            "DstackKms.sol",
            abi.encodeCall(DstackKms.initialize, (owner, address(appImpl)))
        );
        
        vm.stopPrank();
        
        // Try to upgrade as non-owner
        vm.startPrank(user);
        vm.expectRevert();
        Upgrades.upgradeProxy(kmsProxy, "DstackKmsV2.sol", "");
        vm.stopPrank();
    }
    
    function test_ComplexUpgradeScenario() public {
        vm.startPrank(owner);
        
        // Deploy KMS with app implementation
        DstackApp appImpl = new DstackApp();
        address kmsProxy = Upgrades.deployUUPSProxy(
            "DstackKms.sol",
            abi.encodeCall(DstackKms.initialize, (owner, address(appImpl)))
        );
        
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
        bytes32 mrAggregated = bytes32(uint256(101112));
        
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