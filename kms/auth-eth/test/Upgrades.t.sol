// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "openzeppelin-foundry-upgrades/Upgrades.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";
import "../contracts/IAppAuth.sol";

contract UpgradesTest is Test {
    DstackKms public kms;
    DstackApp public app;
    address public owner;
    address public user;
    
    event Upgraded(address indexed implementation);
    
    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        
        vm.startPrank(owner);
        
        // Deploy DstackApp implementation
        DstackApp appImpl = new DstackApp();
        
        // Deploy DstackKms proxy using OpenZeppelin plugin
        address kmsProxy = Upgrades.deployUUPSProxy(
            "DstackKms.sol",
            abi.encodeCall(DstackKms.initialize, (owner, address(appImpl)))
        );
        kms = DstackKms(kmsProxy);
        
        // Deploy DstackApp proxy using OpenZeppelin plugin
        address appProxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol",
            abi.encodeCall(DstackApp.initialize, (owner, false, false, bytes32(0), bytes32(0)))
        );
        app = DstackApp(appProxy);
        
        vm.stopPrank();
    }
    
    function test_UpgradeKmsContract() public {
        // Upgrade using OpenZeppelin plugin
        vm.prank(owner);
        Upgrades.upgradeProxy(address(kms), "DstackKms.sol", "");
        
        // Verify state is preserved
        assertEq(kms.owner(), owner);
    }
    
    function test_UpgradeAppContract() public {
        // Upgrade using OpenZeppelin plugin
        vm.prank(owner);
        Upgrades.upgradeProxy(address(app), "DstackApp.sol", "");
        
        // Verify state is preserved
        assertEq(app.owner(), owner);
    }
    
    function test_OnlyOwnerCanUpgrade() public {
        vm.prank(user);
        vm.expectRevert();
        Upgrades.upgradeProxy(address(kms), "DstackKms.sol", "");
    }
    
    function test_UpgradeWithInitialization() public {
        // Prepare initialization data
        bytes memory initData = abi.encodeCall(
            DstackKms.setGatewayAppId,
            ("upgraded-gateway-id")
        );
        
        vm.prank(owner);
        Upgrades.upgradeProxy(address(kms), "DstackKms.sol", initData);
        
        // Verify the initialization happened
        assertEq(kms.gatewayAppId(), "upgraded-gateway-id");
    }
    
    function test_CannotUpgradeWhenDisabled() public {
        // First disable upgrades
        vm.prank(owner);
        app.disableUpgrades();
        
        // Try to upgrade using plugin - should fail
        vm.prank(owner);
        vm.expectRevert("Upgrades are permanently disabled");
        Upgrades.upgradeProxy(address(app), "DstackApp.sol", "");
    }
    
    function test_StatePreservedAcrossUpgrade() public {
        // Set some state
        bytes32 deviceId = bytes32(uint256(123));
        bytes32 composeHash = bytes32(uint256(456));
        
        vm.startPrank(owner);
        app.addDevice(deviceId);
        app.addComposeHash(composeHash);
        app.setAllowAnyDevice(true);
        vm.stopPrank();
        
        // Verify state before upgrade
        assertTrue(app.allowedDeviceIds(deviceId));
        assertTrue(app.allowedComposeHashes(composeHash));
        assertTrue(app.allowAnyDevice());
        
        // Upgrade using plugin
        vm.prank(owner);
        Upgrades.upgradeProxy(address(app), "DstackApp.sol", "");
        
        // Verify state after upgrade
        assertTrue(app.allowedDeviceIds(deviceId));
        assertTrue(app.allowedComposeHashes(composeHash));
        assertTrue(app.allowAnyDevice());
        assertEq(app.owner(), owner);
    }
    
    function test_KmsStatePreservedAcrossUpgrade() public {
        // Set some KMS state
        bytes32 mrAggregated = bytes32(uint256(789));
        bytes32 osImageHash = bytes32(uint256(101112));
        string memory gatewayId = "test-gateway";
        
        vm.startPrank(owner);
        kms.addKmsAggregatedMr(mrAggregated);
        kms.addOsImageHash(osImageHash);
        kms.setGatewayAppId(gatewayId);
        vm.stopPrank();
        
        // Verify state before upgrade
        assertTrue(kms.kmsAllowedAggregatedMrs(mrAggregated));
        assertTrue(kms.allowedOsImages(osImageHash));
        assertEq(kms.gatewayAppId(), gatewayId);
        
        // Upgrade using plugin
        vm.prank(owner);
        Upgrades.upgradeProxy(address(kms), "DstackKms.sol", "");
        
        // Verify state after upgrade
        assertTrue(kms.kmsAllowedAggregatedMrs(mrAggregated));
        assertTrue(kms.allowedOsImages(osImageHash));
        assertEq(kms.gatewayAppId(), gatewayId);
        assertEq(kms.owner(), owner);
    }
}