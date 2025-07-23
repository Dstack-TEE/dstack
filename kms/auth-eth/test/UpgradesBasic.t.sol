// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";
import "../contracts/test-utils/DstackKmsV1.sol";
import "../contracts/test-utils/DstackAppV1.sol";

contract UpgradesBasicTest is Test {
    address public owner;
    address public user;
    
    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
    }
    
    function test_DeployBasicProxy() public {
        vm.startPrank(owner);
        
        // Deploy implementation
        DstackApp appImpl = new DstackApp();
        
        // Deploy proxy manually
        bytes memory initData = abi.encodeCall(
            DstackApp.initialize, 
            (owner, false, false, bytes32(0), bytes32(0))
        );
        
        ERC1967Proxy proxy = new ERC1967Proxy(address(appImpl), initData);
        DstackApp app = DstackApp(address(proxy));
        
        // Verify initialization worked
        assertEq(app.owner(), owner);
        assertEq(app.allowAnyDevice(), false);
        
        vm.stopPrank();
    }
    
    function test_UpgradeFromV1ToV2() public {
        vm.startPrank(owner);
        
        // Deploy V1 implementation
        DstackKmsV1 kmsV1Impl = new DstackKmsV1();
        
        // Deploy proxy with V1
        bytes memory initData = abi.encodeCall(DstackKmsV1.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy(address(kmsV1Impl), initData);
        
        // Test V1 functionality
        DstackKmsV1 kmsV1 = DstackKmsV1(address(proxy));
        assertEq(kmsV1.owner(), owner);
        
        // Deploy V2 implementation
        DstackKms kmsV2Impl = new DstackKms();
        
        // Perform upgrade to V2
        kmsV1.upgradeToAndCall(address(kmsV2Impl), "");
        
        // Now interact with the same proxy but as V2
        DstackKms kmsV2 = DstackKms(address(proxy));
        assertEq(kmsV2.owner(), owner);
        
        // Test V2-specific functionality (appImplementation was added in V2)
        DstackApp appImpl = new DstackApp();
        kmsV2.setAppImplementation(address(appImpl));
        assertEq(kmsV2.appImplementation(), address(appImpl));
        
        vm.stopPrank();
    }
    
    function test_UpgradeAppFromV1ToV2() public {
        vm.startPrank(owner);
        
        // Deploy V1 implementation
        DstackAppV1 appV1Impl = new DstackAppV1();
        
        // Deploy proxy with V1
        bytes memory initData = abi.encodeCall(
            DstackAppV1.initialize, 
            (owner, false, false, bytes32(0), bytes32(0))
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(appV1Impl), initData);
        
        // Test V1 functionality
        DstackAppV1 appV1 = DstackAppV1(address(proxy));
        assertEq(appV1.owner(), owner);
        
        // Deploy V2 implementation
        DstackApp appV2Impl = new DstackApp();
        
        // Perform upgrade to V2
        appV1.upgradeToAndCall(address(appV2Impl), "");
        
        // Now interact with the same proxy but as V2
        DstackApp appV2 = DstackApp(address(proxy));
        assertEq(appV2.owner(), owner);
        assertEq(appV2.allowAnyDevice(), false);
        
        vm.stopPrank();
    }
    
    function test_CannotUpgradeWhenDisabled() public {
        vm.startPrank(owner);
        
        // Deploy implementation and proxy
        DstackApp appImpl = new DstackApp();
        bytes memory initData = abi.encodeCall(
            DstackApp.initialize, 
            (owner, false, false, bytes32(0), bytes32(0))
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(appImpl), initData);
        DstackApp app = DstackApp(address(proxy));
        
        // Disable upgrades
        app.disableUpgrades();
        
        // Deploy new implementation
        DstackApp newImpl = new DstackApp();
        
        // Try to upgrade - should fail
        vm.expectRevert("Upgrades are permanently disabled");
        app.upgradeToAndCall(address(newImpl), "");
        
        vm.stopPrank();
    }
    
    function test_OnlyOwnerCanUpgrade() public {
        vm.startPrank(owner);
        
        // Deploy implementation and proxy
        DstackKms kmsImpl = new DstackKms();
        DstackApp appImpl = new DstackApp();
        bytes memory initData = abi.encodeCall(
            DstackKms.initialize, 
            (owner, address(appImpl))
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(kmsImpl), initData);
        DstackKms kms = DstackKms(address(proxy));
        
        vm.stopPrank();
        
        // Try to upgrade as non-owner
        vm.startPrank(user);
        DstackKms newImpl = new DstackKms();
        
        vm.expectRevert();
        kms.upgradeToAndCall(address(newImpl), "");
        
        vm.stopPrank();
    }
}