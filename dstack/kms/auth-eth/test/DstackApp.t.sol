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
    event RequireTcbUpToDateSet(bool requireUpToDate);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");

        vm.startPrank(owner);

        // Deploy DstackApp proxy using OpenZeppelin plugin
        address appProxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol",
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bytes32,bytes32)", owner, false, false, bytes32(0), bytes32(0)
            )
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
            "DstackApp.sol",
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bytes32,bytes32)", owner, false, true, deviceId, composeHash
            )
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

    function test_Version() public view {
        assertEq(app.version(), 2);
    }

    function test_RequireTcbUpToDate_DefaultFalseAfter5ArgInit() public view {
        // setUp used the legacy 5-arg initialize; the TCB slot must read zero.
        assertFalse(app.requireTcbUpToDate());
    }

    function test_SetRequireTcbUpToDate() public {
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit RequireTcbUpToDateSet(true);
        app.setRequireTcbUpToDate(true);
        assertTrue(app.requireTcbUpToDate());

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit RequireTcbUpToDateSet(false);
        app.setRequireTcbUpToDate(false);
        assertFalse(app.requireTcbUpToDate());
    }

    function test_SetRequireTcbUpToDate_OnlyOwner() public {
        vm.prank(user);
        vm.expectRevert();
        app.setRequireTcbUpToDate(true);
    }

    function test_IsAppAllowed_RejectsOutdatedTcbWhenRequired() public {
        bytes32 deviceId = bytes32(uint256(123));
        bytes32 composeHash = bytes32(uint256(456));

        vm.startPrank(owner);
        app.addDevice(deviceId);
        app.addComposeHash(composeHash);
        app.setRequireTcbUpToDate(true);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: address(app),
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "OutOfDate",
            advisoryIds: new string[](0)
        });

        (bool allowed, string memory reason) = app.isAppAllowed(bootInfo);
        assertFalse(allowed);
        assertEq(reason, "TCB status is not up to date");

        bootInfo.tcbStatus = "UpToDate";
        (allowed, reason) = app.isAppAllowed(bootInfo);
        assertTrue(allowed);
        assertEq(reason, "");
    }

    function test_Initialize6Arg_RequireTcbUpToDateTrue() public {
        bytes32 deviceId = bytes32(uint256(0xDEAD));
        bytes32 composeHash = bytes32(uint256(0xBEEF));

        vm.startPrank(owner);
        address proxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol",
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bool,bytes32,bytes32)", owner, false, true, true, deviceId, composeHash
            )
        );
        DstackApp tcbApp = DstackApp(proxy);
        vm.stopPrank();

        assertTrue(tcbApp.requireTcbUpToDate());
        assertTrue(tcbApp.allowAnyDevice());
        assertTrue(tcbApp.allowedDeviceIds(deviceId));
        assertTrue(tcbApp.allowedComposeHashes(composeHash));

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: address(tcbApp),
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "OutOfDate",
            advisoryIds: new string[](0)
        });
        (bool allowed, string memory reason) = tcbApp.isAppAllowed(bootInfo);
        assertFalse(allowed);
        assertEq(reason, "TCB status is not up to date");
    }

    function test_Initialize6Arg_RequireTcbUpToDateFalse() public {
        vm.startPrank(owner);
        address proxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol",
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bool,bytes32,bytes32)", owner, false, false, true, bytes32(0), bytes32(0)
            )
        );
        DstackApp plainApp = DstackApp(proxy);
        vm.stopPrank();

        assertFalse(plainApp.requireTcbUpToDate());
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

    // ----------------------------------------------------------------
    // Two-step ownership (Ownable2StepUpgradeable). DstackApp inherits the
    // same base as DstackKms; this confirms the App contract didn't
    // accidentally shadow/override the two-step semantics. The KMS test
    // suite covers the full matrix; here we assert the core safety
    // property and a happy-path completion.
    // ----------------------------------------------------------------

    function test_TransferOwnership_StagesPendingWithoutChangingOwner() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(owner);
        app.transferOwnership(newOwner);

        assertEq(app.owner(), owner, "owner must not change on transferOwnership");
        assertEq(app.pendingOwner(), newOwner, "pendingOwner must be staged");
    }

    function test_AcceptOwnership_CompletesTransfer() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(owner);
        app.transferOwnership(newOwner);
        vm.prank(newOwner);
        app.acceptOwnership();

        assertEq(app.owner(), newOwner);
        assertEq(app.pendingOwner(), address(0));

        // owner-only authority follows the new owner
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", owner));
        app.addComposeHash(bytes32(uint256(1)));

        vm.prank(newOwner);
        app.addComposeHash(bytes32(uint256(1)));
        assertTrue(app.allowedComposeHashes(bytes32(uint256(1))));
    }
}
