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

contract DstackKmsTest is Test {
    DstackKms public kms;
    DstackApp public appImpl;
    address public owner;
    address public user;

    event KmsInfoSet(bytes k256Pubkey);

    event AppRegistered(address appId);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");

        vm.startPrank(owner);

        // Deploy DstackApp implementation
        appImpl = new DstackApp();

        // Deploy DstackKms proxy using OpenZeppelin plugin
        address kmsProxy =
            Upgrades.deployUUPSProxy("DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(appImpl))));
        kms = DstackKms(kmsProxy);

        vm.stopPrank();
    }

    function test_Initialize() public view {
        assertEq(kms.owner(), owner);
        assertEq(kms.appImplementation(), address(appImpl));
    }

    function test_SetKmsInfo() public {
        bytes memory k256Pubkey = hex"123456";
        bytes memory caPubkey = hex"789abc";
        bytes memory quote = hex"defdef";
        bytes memory eventlog = hex"abcabc";

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit KmsInfoSet(k256Pubkey);

        kms.setKmsInfo(
            DstackKms.KmsInfo({ k256Pubkey: k256Pubkey, caPubkey: caPubkey, quote: quote, eventlog: eventlog })
        );

        (bytes memory storedK256, bytes memory storedCa, bytes memory storedQuote, bytes memory storedEventlog) =
            kms.kmsInfo();
        assertEq(storedK256, k256Pubkey);
        assertEq(storedCa, caPubkey);
        assertEq(storedQuote, quote);
        assertEq(storedEventlog, eventlog);
    }

    function test_SetKmsInfoOnlyOwner() public {
        bytes memory k256Pubkey = hex"123456";
        bytes memory caPubkey = hex"789abc";
        bytes memory quote = hex"defdef";
        bytes memory eventlog = hex"abcabc";

        vm.prank(user);
        vm.expectRevert();
        kms.setKmsInfo(
            DstackKms.KmsInfo({ k256Pubkey: k256Pubkey, caPubkey: caPubkey, quote: quote, eventlog: eventlog })
        );
    }

    function test_AddKmsAggregatedMr() public {
        bytes32 mr = bytes32(uint256(123));

        vm.prank(owner);
        kms.addKmsAggregatedMr(mr);

        assertTrue(kms.kmsAllowedAggregatedMrs(mr));
    }

    function test_RemoveKmsAggregatedMr() public {
        bytes32 mr = bytes32(uint256(123));

        vm.startPrank(owner);
        kms.addKmsAggregatedMr(mr);
        assertTrue(kms.kmsAllowedAggregatedMrs(mr));

        kms.removeKmsAggregatedMr(mr);
        assertFalse(kms.kmsAllowedAggregatedMrs(mr));
        vm.stopPrank();
    }

    function test_RegisterApp() public {
        // Deploy a test DstackApp using plugin
        vm.startPrank(user);
        address appProxy = Upgrades.deployUUPSProxy(
            "DstackApp.sol",
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bytes32,bytes32)", user, false, false, bytes32(0), bytes32(0)
            )
        );
        vm.stopPrank();

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit AppRegistered(appProxy);

        kms.registerApp(appProxy);
        assertTrue(kms.registeredApps(appProxy));
    }

    function test_DeployAndRegisterApp() public {
        bytes32 deviceId = bytes32(uint256(456));
        bytes32 composeHash = bytes32(uint256(789));

        vm.prank(owner);
        address appId = kms.deployAndRegisterApp(user, false, false, deviceId, composeHash);

        assertTrue(kms.registeredApps(appId));

        DstackApp app = DstackApp(appId);
        assertEq(app.owner(), user);
        assertTrue(app.allowedDeviceIds(deviceId));
        assertTrue(app.allowedComposeHashes(composeHash));
    }

    function test_SetGatewayAppId() public {
        string memory gatewayAppId = "test-gateway-id";

        vm.prank(owner);
        kms.setGatewayAppId(gatewayAppId);

        assertEq(kms.gatewayAppId(), gatewayAppId);
    }

    function test_AddAndRemoveKmsDevice() public {
        bytes32 deviceId = bytes32(uint256(999));

        vm.startPrank(owner);
        kms.addKmsDevice(deviceId);
        assertTrue(kms.kmsAllowedDeviceIds(deviceId));

        kms.removeKmsDevice(deviceId);
        assertFalse(kms.kmsAllowedDeviceIds(deviceId));
        vm.stopPrank();
    }

    function test_AddAndRemoveOsImageHash() public {
        bytes32 imageHash = bytes32(uint256(888));

        vm.startPrank(owner);
        kms.addOsImageHash(imageHash);
        assertTrue(kms.allowedOsImages(imageHash));

        kms.removeOsImageHash(imageHash);
        assertFalse(kms.allowedOsImages(imageHash));
        vm.stopPrank();
    }

    function test_SetKmsQuoteAndEventlog() public {
        bytes memory newQuote = hex"deadbeef";
        bytes memory newEventlog = hex"cafebabe";

        vm.startPrank(owner);
        kms.setKmsQuote(newQuote);
        kms.setKmsEventlog(newEventlog);
        vm.stopPrank();

        (,, bytes memory storedQuote, bytes memory storedEventlog) = kms.kmsInfo();
        assertEq(storedQuote, newQuote);
        assertEq(storedEventlog, newEventlog);
    }

    function test_IsKmsAllowed() public {
        bytes32 deviceId = bytes32(uint256(123));
        bytes32 mrAggregated = bytes32(uint256(456));
        bytes32 osImageHash = bytes32(uint256(789));

        // Setup allowed values
        vm.startPrank(owner);
        kms.addKmsDevice(deviceId);
        kms.addKmsAggregatedMr(mrAggregated);
        kms.addOsImageHash(osImageHash);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: address(0),
            composeHash: bytes32(0),
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: mrAggregated,
            mrSystem: bytes32(0),
            osImageHash: osImageHash,
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });

        (bool allowed, string memory reason) = kms.isKmsAllowed(bootInfo);
        assertTrue(allowed);
        assertEq(reason, "");
    }

    function test_IsKmsAllowed_RejectOutdatedTcb() public {
        bytes32 deviceId = bytes32(uint256(123));
        bytes32 mrAggregated = bytes32(uint256(456));
        bytes32 osImageHash = bytes32(uint256(789));

        // Setup allowed values
        vm.startPrank(owner);
        kms.addKmsDevice(deviceId);
        kms.addKmsAggregatedMr(mrAggregated);
        kms.addOsImageHash(osImageHash);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: address(0),
            composeHash: bytes32(0),
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: mrAggregated,
            mrSystem: bytes32(0),
            osImageHash: osImageHash,
            tcbStatus: "Outdated", // This should fail
            advisoryIds: new string[](0)
        });

        (bool allowed, string memory reason) = kms.isKmsAllowed(bootInfo);
        assertFalse(allowed);
        assertEq(reason, "TCB status is not up to date");
    }

    function test_IsAppAllowed_CompleteFlow() public {
        // Deploy a test app through the factory
        bytes32 deviceId = bytes32(uint256(456));
        bytes32 composeHash = bytes32(uint256(789));
        bytes32 osImageHash = bytes32(uint256(111));

        vm.startPrank(owner);
        kms.addOsImageHash(osImageHash);
        address appId = kms.deployAndRegisterApp(user, false, false, deviceId, composeHash);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory bootInfo = IAppAuth.AppBootInfo({
            appId: appId,
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: osImageHash,
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });

        (bool allowed, string memory reason) = kms.isAppAllowed(bootInfo);
        assertTrue(allowed);
        assertEq(reason, "");
    }

    function test_SetAppImplementation() public {
        DstackApp newImpl = new DstackApp();

        vm.prank(owner);
        kms.setAppImplementation(address(newImpl));

        assertEq(kms.appImplementation(), address(newImpl));
    }

    function test_SupportsInterface() public view {
        // Test IAppAuth interface
        assertTrue(kms.supportsInterface(0x1e079198));

        // Test IERC165 interface
        assertTrue(kms.supportsInterface(0x01ffc9a7));

        // Test invalid interface
        assertFalse(kms.supportsInterface(0x12345678));
    }

    // ----------------------------------------------------------------
    // Two-step ownership (Ownable2StepUpgradeable)
    //
    // The migration switched DstackKms from single-step OwnableUpgradeable
    // to Ownable2StepUpgradeable. These tests lock in the new behaviour so
    // a future change back to single-step (which would re-introduce the
    // typo-bricks-contract risk) breaks the suite.
    // ----------------------------------------------------------------

    function test_TransferOwnership_StagesPendingWithoutChangingOwner() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(owner);
        kms.transferOwnership(newOwner);

        // The key safety property: owner is NOT changed by transferOwnership.
        assertEq(kms.owner(), owner, "owner must not change on transferOwnership");
        assertEq(kms.pendingOwner(), newOwner, "pendingOwner must be staged");
    }

    function test_AcceptOwnership_CompletesTransfer() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(owner);
        kms.transferOwnership(newOwner);

        vm.prank(newOwner);
        kms.acceptOwnership();

        assertEq(kms.owner(), newOwner, "acceptOwnership must complete the transfer");
        assertEq(kms.pendingOwner(), address(0), "pendingOwner must be cleared");
    }

    function test_TransferOwnership_OnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        kms.transferOwnership(user);
    }

    function test_AcceptOwnership_OnlyPendingOwner() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(owner);
        kms.transferOwnership(newOwner);

        // Anyone who is not the staged pending owner cannot accept.
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        kms.acceptOwnership();

        // ... and the original owner cannot accept on the pending owner's behalf.
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", owner));
        kms.acceptOwnership();
    }

    function test_TransferOwnership_RetargetInvalidatesPriorPending() public {
        address first = makeAddr("first");
        address second = makeAddr("second");

        vm.startPrank(owner);
        kms.transferOwnership(first);
        kms.transferOwnership(second); // re-target before anyone accepts
        vm.stopPrank();

        assertEq(kms.pendingOwner(), second, "pendingOwner must be the latest target");

        // The first (now-stale) target can no longer accept.
        vm.prank(first);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", first));
        kms.acceptOwnership();

        // The current target can.
        vm.prank(second);
        kms.acceptOwnership();
        assertEq(kms.owner(), second);
    }

    function test_OwnerOnlyFunctionsFollowOwnershipAfterTransfer() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(owner);
        kms.transferOwnership(newOwner);
        vm.prank(newOwner);
        kms.acceptOwnership();

        bytes32 mr = bytes32(uint256(0xABCD));

        // Old owner has lost authority.
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", owner));
        kms.addKmsAggregatedMr(mr);

        // New owner has it.
        vm.prank(newOwner);
        kms.addKmsAggregatedMr(mr);
        assertTrue(kms.kmsAllowedAggregatedMrs(mr));
    }
}
