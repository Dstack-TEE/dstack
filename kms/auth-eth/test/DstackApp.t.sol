/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "openzeppelin-foundry-upgrades/Upgrades.sol";
import "../contracts/DstackApp.sol";
import "../contracts/IAppAuth.sol";

contract DstackAppTest is Test {
    DstackApp public app;
    address public owner;
    address public user;

    event ComposeHashAdded(bytes32 hash);
    event ComposeHashRemoved(bytes32 hash);
    event DeviceAdded(bytes32 deviceId);
    event DeviceRemoved(bytes32 deviceId);
    event AllowAnyDeviceSet(bool allowAnyDevice);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");

        vm.startPrank(owner);

        // Deploy DstackApp proxy using OpenZeppelin plugin
        address appProxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol", abi.encodeCall(DstackApp.initialize, (owner, false, false, bytes32(0), bytes32(0)))
        );
        app = DstackApp(appProxy);

        vm.stopPrank();
    }

    function test_Initialize() public view {
        assertEq(app.owner(), owner);
        assertFalse(app.allowAnyDevice());
    }

    function test_InitializeWithData() public {
        bytes32 deviceId = bytes32(uint256(123));
        bytes32 composeHash = bytes32(uint256(456));

        vm.startPrank(owner);

        // Deploy DstackApp proxy with initialization data using OpenZeppelin plugin
        address testAppProxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol", abi.encodeCall(DstackApp.initialize, (owner, false, true, deviceId, composeHash))
        );
        DstackApp testApp = DstackApp(testAppProxy);

        assertEq(testApp.owner(), owner);
        assertTrue(testApp.allowAnyDevice());
        assertTrue(testApp.allowedDeviceIds(deviceId));
        assertTrue(testApp.allowedComposeHashes(composeHash));

        vm.stopPrank();
    }

    function test_AddComposeHash() public {
        bytes32 hash = bytes32(uint256(123));

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit ComposeHashAdded(hash);

        app.addComposeHash(hash);
        assertTrue(app.allowedComposeHashes(hash));
    }

    function test_RemoveComposeHash() public {
        bytes32 hash = bytes32(uint256(123));

        vm.startPrank(owner);
        app.addComposeHash(hash);
        assertTrue(app.allowedComposeHashes(hash));

        vm.expectEmit(true, true, true, true);
        emit ComposeHashRemoved(hash);

        app.removeComposeHash(hash);
        assertFalse(app.allowedComposeHashes(hash));
        vm.stopPrank();
    }

    function test_AddDevice() public {
        bytes32 deviceId = bytes32(uint256(456));

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit DeviceAdded(deviceId);

        app.addDevice(deviceId);
        assertTrue(app.allowedDeviceIds(deviceId));
    }

    function test_RemoveDevice() public {
        bytes32 deviceId = bytes32(uint256(456));

        vm.startPrank(owner);
        app.addDevice(deviceId);
        assertTrue(app.allowedDeviceIds(deviceId));

        vm.expectEmit(true, true, true, true);
        emit DeviceRemoved(deviceId);

        app.removeDevice(deviceId);
        assertFalse(app.allowedDeviceIds(deviceId));
        vm.stopPrank();
    }

    function test_SetAllowAnyDevice() public {
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit AllowAnyDeviceSet(true);

        app.setAllowAnyDevice(true);
        assertTrue(app.allowAnyDevice());

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit AllowAnyDeviceSet(false);

        app.setAllowAnyDevice(false);
        assertFalse(app.allowAnyDevice());
    }

    function test_OnlyOwnerFunctions() public {
        bytes32 hash = bytes32(uint256(123));
        bytes32 deviceId = bytes32(uint256(456));

        vm.startPrank(user);

        vm.expectRevert();
        app.addComposeHash(hash);

        vm.expectRevert();
        app.removeComposeHash(hash);

        vm.expectRevert();
        app.addDevice(deviceId);

        vm.expectRevert();
        app.removeDevice(deviceId);

        vm.expectRevert();
        app.setAllowAnyDevice(true);

        vm.stopPrank();
    }

    function test_IsAppAllowed() public {
        bytes32 deviceId = bytes32(uint256(123));
        bytes32 composeHash = bytes32(uint256(456));

        vm.startPrank(owner);
        app.addDevice(deviceId);
        app.addComposeHash(composeHash);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: address(app),
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });

        (bool allowed, string memory reason) = app.isAppAllowed(bootInfo);
        assertTrue(allowed);
        assertEq(reason, "");

        // Test with wrong device
        bytes32 wrongDevice = bytes32(uint256(789));
        bootInfo.deviceId = wrongDevice;
        (allowed, reason) = app.isAppAllowed(bootInfo);
        assertFalse(allowed);
        assertEq(reason, "Device not allowed");

        // Test with allowAnyDevice = true
        vm.prank(owner);
        app.setAllowAnyDevice(true);

        (allowed, reason) = app.isAppAllowed(bootInfo);
        assertTrue(allowed);
        assertEq(reason, "");
    }

    function test_RejectUnallowedComposeHash() public {
        bytes32 deviceId = bytes32(uint256(123));
        bytes32 allowedHash = bytes32(uint256(456));
        bytes32 unallowedHash = bytes32(uint256(789));

        vm.startPrank(owner);
        app.addDevice(deviceId);
        app.addComposeHash(allowedHash);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: address(app),
            composeHash: unallowedHash,
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });

        (bool allowed, string memory reason) = app.isAppAllowed(bootInfo);
        assertFalse(allowed);
        assertEq(reason, "Compose hash not allowed");
    }

    function test_SupportsInterface() public view {
        // Test IAppAuth interface
        assertTrue(app.supportsInterface(0x1e079198));

        // Test IAppAuthBasicManagement interface
        assertTrue(app.supportsInterface(0x8fd37527));

        // Test IERC165 interface
        assertTrue(app.supportsInterface(0x01ffc9a7));

        // Test invalid interface
        assertFalse(app.supportsInterface(0x12345678));
    }
}
