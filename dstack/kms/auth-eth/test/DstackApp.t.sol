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

        IAppAuth.AppInfo memory bootInfo = IAppAuth.AppInfo({
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

        IAppAuth.AppInfo memory bootInfo = IAppAuth.AppInfo({
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
        vm.stopPrank();

        string[] memory advisoryIds = new string[](1);
        advisoryIds[0] = "INTEL-SA-00614";

        IAppAuth.AppInfo memory bootInfo = IAppAuth.AppInfo({
            appId: address(app),
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "OutOfDate",
            advisoryIds: advisoryIds
        });

        // Legacy 5-arg init skips the TCB check (specification.md §3.4). This deliberately
        // diverges from auth-simple's strict default; see auth-simple/index.test.ts.
        (bool allowed, string memory reason) = app.isAppAllowed(bootInfo);
        assertTrue(allowed);

        vm.prank(owner);
        app.setRequireTcbUpToDate(true);
        (allowed, reason) = app.isAppAllowed(bootInfo);
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

        IAppAuth.AppInfo memory bootInfo = IAppAuth.AppInfo({
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

    function test_AddZeroValuedPolicyEntriesIsRejected() public {
        vm.startPrank(owner);
        vm.expectRevert("invalid compose hash");
        app.addComposeHash(bytes32(0));
        vm.expectRevert("invalid device ID");
        app.addDevice(bytes32(0));
        vm.stopPrank();
    }

    function epochInfo() internal view returns (IAppAuth.AppInfo memory info) {
        info.appId = address(app);
        info.composeHash = bytes32(uint256(1));
        info.deviceId = bytes32(uint256(2));
        info.tcbStatus = "UpToDate";
    }

    function appRequest(
        IAppAuth.AppInfo memory info,
        OptionalUint256 memory appEpoch,
        bytes32 operation
    )
        internal
        pure
        returns (AuthorizationRequest memory)
    {
        return AuthorizationRequest(info, operation, appEpoch, OptionalUint256(false, 0));
    }

    function authorizeAt(
        IAppAuth.AppInfo memory info,
        uint256 epoch,
        bytes32 operation
    )
        internal
        view
        returns (bool, string memory)
    {
        AuthorizationResult memory result = app.authorizeApp(appRequest(info, OptionalUint256(true, epoch), operation));
        return (result.authorized, result.rejectionReason);
    }

    function test_AuthorizeAppOwnsOperationScopeAndAppEpoch() public {
        IAppAuth.AppInfo memory info = epochInfo();
        vm.startPrank(owner);
        app.addComposeHashAtEpoch(0, info.composeHash);
        app.addDeviceAtEpoch(0, info.deviceId);
        app.advanceAppEpoch(0);
        vm.stopPrank();

        AuthorizationResult memory result =
            app.authorizeApp(appRequest(info, OptionalUint256(true, 0), keccak256("kms_serve")));
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "Invalid authorization operation");
        assertEq(result.currentAppEpoch, 1);

        result = app.authorizeApp(appRequest(info, OptionalUint256(true, 2), keccak256("app_get_key")));
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "Requested app epoch is not active");
        assertEq(result.currentAppEpoch, 1);

        // Omission selects the current epoch, whose row is still empty.
        result = app.authorizeApp(appRequest(info, OptionalUint256(false, 0), keccak256("app_get_key")));
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "Compose hash not allowed");
        assertEq(result.currentAppEpoch, 1);

        result = app.authorizeApp(appRequest(info, OptionalUint256(true, 0), keccak256("app_get_key")));
        assertTrue(result.authorized);
        assertEq(result.rejectionReason, "");
        assertEq(result.currentAppEpoch, 1);
        // Gateway and root epoch fields belong to the KMS.
        assertEq(result.gatewayAppId, "");
        assertEq(result.currentRootEpoch, 0);
        assertEq(result.currentRootEpochHash, bytes32(0));
    }

    function test_AppOperationsSharePolicyButRejectUnknownOrKmsOperations() public {
        IAppAuth.AppInfo memory info = epochInfo();
        vm.startPrank(owner);
        app.addComposeHash(info.composeHash);
        app.addDevice(info.deviceId);
        vm.stopPrank();
        (bool allowed,) = authorizeAt(info, 0, keccak256("app_get_cert"));
        assertTrue(allowed);
        (allowed,) = authorizeAt(info, 0, keccak256("app_get_key"));
        assertTrue(allowed);
        (allowed,) = authorizeAt(info, 0, keccak256("kms_import_keys"));
        assertFalse(allowed);
        (allowed,) = authorizeAt(info, 0, bytes32(0));
        assertFalse(allowed);
    }

    function test_AppEpochRowsAreIndependentAndDefaultsUseCurrentEpoch() public {
        IAppAuth.AppInfo memory info = epochInfo();
        vm.startPrank(owner);
        app.addComposeHashAtEpoch(0, info.composeHash);
        app.addDeviceAtEpoch(0, info.deviceId);
        app.advanceAppEpoch(0);
        bool allowed = authorizeCurrent(info);
        assertFalse(allowed);
        (allowed,) = authorizeAt(info, 0, keccak256("app_get_key"));
        assertTrue(allowed);
        app.addComposeHash(info.composeHash);
        allowed = authorizeCurrent(info);
        assertFalse(allowed, "each material must be approved in the selected row");
        app.addDevice(info.deviceId);
        allowed = authorizeCurrent(info);
        assertTrue(allowed);
        app.removeComposeHash(info.composeHash);
        assertFalse(app.allowedComposeHashesAtEpoch(1, info.composeHash));
        assertTrue(app.allowedComposeHashes(info.composeHash));
        (allowed,) = authorizeAt(info, 0, keccak256("app_get_key"));
        assertTrue(allowed);
        app.addComposeHash(info.composeHash);
        app.removeDeviceAtEpoch(0, info.deviceId);
        assertFalse(app.allowedDeviceIds(info.deviceId));
        (allowed,) = authorizeAt(info, 0, keccak256("app_get_key"));
        assertFalse(allowed);
        allowed = authorizeCurrent(info);
        assertTrue(allowed, "revoking epoch zero must not revoke epoch one");
        (allowed,) = authorizeAt(info, 2, keccak256("app_get_key"));
        assertFalse(allowed);
        vm.stopPrank();
    }

    function test_NewImageCanBeExplicitlyAddedToOldRowForHandover() public {
        IAppAuth.AppInfo memory oldInfo = epochInfo();
        IAppAuth.AppInfo memory newInfo = epochInfo();
        newInfo.composeHash = bytes32(uint256(3));
        vm.startPrank(owner);
        app.addComposeHashAtEpoch(0, oldInfo.composeHash);
        app.addDeviceAtEpoch(0, oldInfo.deviceId);
        app.advanceAppEpoch(0);
        app.addComposeHash(newInfo.composeHash);
        app.addDevice(newInfo.deviceId);
        (bool allowed,) = authorizeAt(newInfo, 0, keccak256("app_get_key"));
        assertFalse(allowed, "new epoch approval must not imply historical access");
        app.addComposeHashAtEpoch(0, newInfo.composeHash);
        (allowed,) = authorizeAt(newInfo, 0, keccak256("app_get_key"));
        assertTrue(allowed);
        allowed = authorizeCurrent(oldInfo);
        assertFalse(allowed, "old image cannot read new keys");
        app.removeComposeHashAtEpoch(0, oldInfo.composeHash);
        (allowed,) = authorizeAt(oldInfo, 0, keccak256("app_get_key"));
        assertFalse(allowed);
        allowed = authorizeCurrent(newInfo);
        assertTrue(allowed);
        vm.stopPrank();
    }

    function test_AllowAnyDeviceIsScopedToExactlyOneEpoch() public {
        IAppAuth.AppInfo memory info = epochInfo();
        vm.startPrank(owner);
        app.addComposeHashAtEpoch(0, info.composeHash);
        app.setAllowAnyDeviceAtEpoch(0, true);
        app.advanceAppEpoch(0);
        app.addComposeHash(info.composeHash);
        bool allowed = authorizeCurrent(info);
        assertFalse(allowed);
        app.addDevice(info.deviceId);
        allowed = authorizeCurrent(info);
        assertTrue(allowed, "explicit device can replace wildcard in a newer row");
        app.removeDevice(info.deviceId);
        app.setAllowAnyDevice(true);
        app.setAllowAnyDeviceAtEpoch(0, false);
        assertFalse(app.allowAnyDevice());
        assertTrue(app.allowAnyDeviceAtEpoch(1));
        (allowed,) = authorizeAt(info, 0, keccak256("app_get_key"));
        assertFalse(allowed);
        allowed = authorizeCurrent(info);
        assertTrue(allowed);
        app.setAllowAnyDevice(false);
        allowed = authorizeCurrent(info);
        assertFalse(allowed);
        vm.stopPrank();
    }

    function authorizeCurrent(IAppAuth.AppInfo memory info) internal view returns (bool allowed) {
        (allowed,) = authorizeAt(info, app.currentAppEpoch(), keccak256("app_get_key"));
    }

    function test_LegacyAppCheckRefusesOnceTheAppEpochAdvances() public {
        IAppAuth.AppInfo memory info = epochInfo();
        vm.startPrank(owner);
        app.addComposeHash(info.composeHash);
        app.addDevice(info.deviceId);
        // At epoch 0 the legacy check reads row 0, as in v0.6.0.
        (bool allowed, string memory reason) = app.isAppAllowed(info);
        assertTrue(allowed, reason);
        app.removeComposeHashAtEpoch(1, info.composeHash);
        (allowed,) = app.isAppAllowed(info);
        assertTrue(allowed, "the prepared next row does not affect the legacy check");
        app.addComposeHashAtEpoch(1, info.composeHash);

        app.advanceAppEpoch(0);
        (allowed, reason) = app.isAppAllowed(info);
        assertFalse(allowed);
        assertEq(reason, "App epoch requires epoch-aware authorization");
        // Epoch-aware callers keep working at both epochs.
        (allowed,) = authorizeAt(info, 1, keccak256("app_get_key"));
        assertTrue(allowed);
        (allowed,) = authorizeAt(info, 0, keccak256("app_get_key"));
        assertTrue(allowed);
        vm.stopPrank();
    }

    function test_NextAppEpochRowCanBePreparedBeforeAdvancing() public {
        IAppAuth.AppInfo memory info = epochInfo();
        IAppAuth.AppInfo memory next = epochInfo();
        next.composeHash = bytes32(uint256(3));
        vm.startPrank(owner);
        app.addComposeHashAtEpoch(0, info.composeHash);
        app.addDeviceAtEpoch(0, info.deviceId);
        app.addComposeHashAtEpoch(1, next.composeHash);
        app.addDeviceAtEpoch(1, next.deviceId);
        app.setAllowAnyDeviceAtEpoch(1, true);
        // Preparing the next row leaves the current one as it was.
        bool allowed = authorizeCurrent(info);
        assertTrue(allowed);
        allowed = authorizeCurrent(next);
        assertFalse(allowed);
        (allowed,) = authorizeAt(next, 1, keccak256("app_get_key"));
        assertFalse(allowed, "the next row is not active before advancing");
        vm.expectRevert("Unknown app epoch");
        app.addComposeHashAtEpoch(2, next.composeHash);

        app.advanceAppEpoch(0);
        allowed = authorizeCurrent(next);
        assertTrue(allowed, "a prepared row authorizes as soon as it is current");
        (allowed,) = authorizeAt(next, 1, keccak256("app_get_key"));
        assertTrue(allowed);
        (allowed,) = authorizeAt(info, 0, keccak256("app_get_key"));
        assertTrue(allowed);
        app.addComposeHashAtEpoch(2, next.composeHash);
        vm.stopPrank();
    }

    function test_EpochlessAppSettersChangeTheCurrentAndNextRows() public {
        bytes32 composeHash = bytes32(uint256(7));
        bytes32 deviceId = bytes32(uint256(8));
        vm.startPrank(owner);
        app.advanceAppEpoch(0);
        app.addComposeHash(composeHash);
        app.addDevice(deviceId);
        app.setAllowAnyDevice(true);
        for (uint256 epoch = 1; epoch <= 2; ++epoch) {
            assertTrue(app.allowedComposeHashesAtEpoch(epoch, composeHash));
            assertTrue(app.allowedDeviceIdsAtEpoch(epoch, deviceId));
            assertTrue(app.allowAnyDeviceAtEpoch(epoch));
        }
        assertFalse(app.allowedComposeHashesAtEpoch(0, composeHash));
        assertFalse(app.allowedDeviceIdsAtEpoch(0, deviceId));
        app.removeComposeHash(composeHash);
        app.removeDevice(deviceId);
        app.setAllowAnyDevice(false);
        for (uint256 epoch = 1; epoch <= 2; ++epoch) {
            assertFalse(app.allowedComposeHashesAtEpoch(epoch, composeHash));
            assertFalse(app.allowedDeviceIdsAtEpoch(epoch, deviceId));
            assertFalse(app.allowAnyDeviceAtEpoch(epoch));
        }
        assertFalse(app.allowedComposeHashesAtEpoch(3, composeHash));
        vm.stopPrank();
    }

    function test_ExplicitAppEpochSettersRequireOwnerAndKnownEpoch() public {
        vm.startPrank(owner);
        // Only the current row and the next one can be written.
        vm.expectRevert("Unknown app epoch");
        app.addComposeHashAtEpoch(2, bytes32(uint256(1)));
        vm.expectRevert("Unknown app epoch");
        app.removeComposeHashAtEpoch(2, bytes32(uint256(1)));
        vm.expectRevert("Unknown app epoch");
        app.addDeviceAtEpoch(2, bytes32(uint256(1)));
        vm.expectRevert("Unknown app epoch");
        app.removeDeviceAtEpoch(2, bytes32(uint256(1)));
        vm.expectRevert("Unknown app epoch");
        app.setAllowAnyDeviceAtEpoch(2, true);
        vm.stopPrank();
        bytes memory unauthorized = abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, user);
        vm.startPrank(user);
        vm.expectRevert(unauthorized);
        app.addComposeHashAtEpoch(0, bytes32(uint256(1)));
        vm.expectRevert(unauthorized);
        app.removeComposeHashAtEpoch(0, bytes32(uint256(1)));
        vm.expectRevert(unauthorized);
        app.addDeviceAtEpoch(0, bytes32(uint256(1)));
        vm.expectRevert(unauthorized);
        app.removeDeviceAtEpoch(0, bytes32(uint256(1)));
        vm.expectRevert(unauthorized);
        app.setAllowAnyDeviceAtEpoch(0, true);
        vm.stopPrank();
    }

    function test_epoch_auth_interface_combines_discovery_and_authorization() public view {
        bytes4 combined = IAppEpochAuth.currentAppEpoch.selector ^ IAppEpochAuth.authorizeApp.selector;
        assertEq(bytes32(type(IAppEpochAuth).interfaceId), bytes32(combined));
        assertTrue(app.supportsInterface(combined));
        assertFalse(app.supportsInterface(IAppEpochAuth.currentAppEpoch.selector));
        assertFalse(app.supportsInterface(IAppEpochAuth.authorizeApp.selector));
    }

    function testFuzz_AppAuthorizationMatchesOnlyTheSelectedRow(uint8 approved, uint8 requested) public {
        uint256 row = bound(approved, 0, 4);
        uint256 selected = bound(requested, 0, 6);
        IAppAuth.AppInfo memory info = epochInfo();
        vm.startPrank(owner);
        for (uint256 i; i < 5; i++) {
            app.advanceAppEpoch(i);
        }
        app.addComposeHashAtEpoch(row, info.composeHash);
        app.addDeviceAtEpoch(row, info.deviceId);
        vm.stopPrank();
        (bool allowed,) = authorizeAt(info, selected, keccak256("app_get_key"));
        assertEq(allowed, selected == row);
    }
}
