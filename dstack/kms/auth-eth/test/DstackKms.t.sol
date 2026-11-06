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
import "../contracts/test-utils/LegacyDstackKms.sol";

contract DstackKmsTest is Test {
    DstackKms public kms;
    DstackApp public appImpl;
    address public owner;
    address public user;

    event KmsInfoSet(bytes k256Pubkey);
    event RootEpochRegistered(
        uint256 indexed epoch, bytes32 chainHash, bytes caPubkey, bytes k256Pubkey, string evidenceUrl
    );
    event RootEpochActivated(uint256 indexed epoch);
    event RootEpochPopped(uint256 indexed epoch, bytes32 chainHash);
    event RootEpochEvidenceUrlSet(uint256 indexed epoch, string evidenceUrl);

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

    function upgradeLegacyKms() internal {
        vm.startPrank(owner);
        address proxy = Upgrades.deployUUPSProxy(
            "LegacyDstackKms.sol", abi.encodeCall(LegacyDstackKms.initialize, (owner, address(appImpl)))
        );
        LegacyDstackKms(proxy).setKmsInfo(LegacyDstackKms.KmsInfo(k256(0xb0), ca(0xa0), hex"0d", hex"0e"));
        Options memory opts;
        opts.referenceContract = "LegacyDstackKms.sol";
        Upgrades.upgradeProxy(proxy, "DstackKms.sol", "", opts);
        vm.stopPrank();
        kms = DstackKms(proxy);

        assertEq(kms.owner(), owner);
        assertEq(kms.appImplementation(), address(appImpl));
        assertEq(kms.rootEpochCount(), 0);
        (bytes memory storedK256, bytes memory storedCa, bytes memory quote, bytes memory eventlog) = kms.kmsInfo();
        assertEq(storedK256, k256(0xb0));
        assertEq(storedCa, ca(0xa0));
        assertEq(quote, hex"0d");
        assertEq(eventlog, hex"0e");
    }

    function assertLegacySettersDisabled(address caller) internal {
        (bytes memory key, bytes memory caKey, bytes memory quote, bytes memory eventlog) = kms.kmsInfo();
        vm.startPrank(caller);
        (bool ok,) = address(kms)
            .call(
                abi.encodeWithSignature(
                    "setKmsInfo((bytes,bytes,bytes,bytes))", DstackKms.KmsInfo(k256(0xb1), ca(0xa1), hex"ff", hex"ff")
                )
            );
        assertFalse(ok);
        (ok,) = address(kms).call(abi.encodeWithSignature("setKmsQuote(bytes)", hex"ff"));
        assertFalse(ok);
        (ok,) = address(kms).call(abi.encodeWithSignature("setKmsEventlog(bytes)", hex"ff"));
        assertFalse(ok);
        vm.stopPrank();
        (bytes memory storedKey, bytes memory storedCa, bytes memory storedQuote, bytes memory storedEventlog) =
            kms.kmsInfo();
        assertEq(storedKey, key);
        assertEq(storedCa, caKey);
        assertEq(storedQuote, quote);
        assertEq(storedEventlog, eventlog);
    }

    function test_legacy_setters_disabled_before_and_after_epoch_registration() public {
        assertLegacySettersDisabled(owner);
        assertLegacySettersDisabled(user);
        vm.prank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0");
        assertLegacySettersDisabled(owner);
        assertLegacySettersDisabled(user);
    }

    function test_legacy_setters_disabled_after_upgrade() public {
        upgradeLegacyKms();
        assertLegacySettersDisabled(owner);
        assertLegacySettersDisabled(user);
    }

    // Well-formed root public keys whose point bytes are all `fill`; shared with
    // the off-chain implementations' tests.
    function ca(uint8 fill) internal pure returns (bytes memory key) {
        key = bytes.concat(hex"3059301306072a8648ce3d020106082a8648ce3d03010703420004", new bytes(64));
        for (uint256 i = 27; i < 91; i++) {
            key[i] = bytes1(fill);
        }
    }

    function k256(uint8 fill) internal pure returns (bytes memory key) {
        key = new bytes(33);
        key[0] = 0x02;
        for (uint256 i = 1; i < 33; i++) {
            key[i] = bytes1(fill);
        }
    }

    function chainHash(bytes32 previous, bytes memory caKey, bytes memory k256Key) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(previous, keccak256(caKey), keccak256(k256Key)));
    }

    function test_RegisterRootEpochAppendsAndChains() public {
        assertEq(kms.rootEpochCount(), 0);
        vm.expectRevert("No root epoch registered");
        kms.currentRootEpoch();

        bytes32 h0 = chainHash(bytes32(0), ca(0xa0), k256(0xb0));
        bytes32 h1 = chainHash(h0, ca(0xa1), k256(0xb1));
        // Shared with the off-chain implementations' tests.
        assertEq(h0, 0x10ab6b6c8e7601901b0f1767985bf40d35bf3129e0866fe12dcc7c8f04a298f2);
        assertEq(h1, 0x50152a82023f2219a31723b476c13bc5f608ab4147946dabdec15d4f3d648ed4);
        vm.startPrank(owner);
        vm.expectEmit(true, true, true, true);
        emit RootEpochRegistered(0, h0, ca(0xa0), k256(0xb0), "ipfs://c0");
        vm.expectEmit(true, true, true, true);
        emit RootEpochActivated(0);
        assertEq(kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0"), 0);
        assertEq(kms.registerRootEpoch(ca(0xa1), k256(0xb1), "ipfs://c1"), 1);
        vm.stopPrank();

        assertEq(kms.rootEpochCount(), 2);
        (bytes memory caKey, bytes memory k256Key, string memory evidenceUrl, bytes32 h) = kms.rootEpoch(1);
        assertEq(caKey, ca(0xa1));
        assertEq(k256Key, k256(0xb1));
        assertEq(evidenceUrl, "ipfs://c1");
        assertEq(h, h1);
        vm.expectRevert("Unknown root epoch");
        kms.rootEpoch(2);

        // Epoch 1 is registered but epoch 0 is still served.
        (uint256 current, bytes32 currentHash) = kms.currentRootEpoch();
        assertEq(current, 0);
        assertEq(currentHash, h0);
    }

    function test_ActivateRootEpochMovesForwardOneAtATime() public {
        bytes32 h0 = chainHash(bytes32(0), ca(0xa0), k256(0xb0));
        bytes32 h1 = chainHash(h0, ca(0xa1), k256(0xb1));
        bytes32 h2 = chainHash(h1, ca(0xa2), k256(0xb2));
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0");
        vm.expectRevert("Invalid root epoch activation");
        kms.activateRootEpoch(1, h1);
        kms.registerRootEpoch(ca(0xa1), k256(0xb1), "ipfs://c1");
        kms.registerRootEpoch(ca(0xa2), k256(0xb2), "ipfs://c2");
        vm.expectRevert("Invalid root epoch activation");
        kms.activateRootEpoch(2, h2);
        vm.expectEmit(true, true, true, true);
        emit RootEpochActivated(1);
        kms.activateRootEpoch(1, h1);
        vm.expectRevert("Invalid root epoch activation");
        kms.activateRootEpoch(1, h1);
        vm.expectRevert("Invalid root epoch activation");
        kms.activateRootEpoch(0, h0);
        vm.stopPrank();

        (uint256 current,) = kms.currentRootEpoch();
        assertEq(current, 1);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, user));
        kms.activateRootEpoch(2, h2);
    }

    function test_activate_root_epoch_rejects_replaced_pending_epoch() public {
        bytes32 h0 = chainHash(bytes32(0), ca(0xa0), k256(0xb0));
        bytes32 h1 = chainHash(h0, ca(0xa1), k256(0xb1));
        bytes32 replacementHash = chainHash(h0, ca(0xa2), k256(0xb2));
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0");
        kms.registerRootEpoch(ca(0xa1), k256(0xb1), "ipfs://c1");
        kms.popRootEpoch(1, h1);
        kms.registerRootEpoch(ca(0xa2), k256(0xb2), "ipfs://replacement");

        vm.expectRevert("root epoch chain hash mismatch");
        kms.activateRootEpoch(1, h1);
        (uint256 current, bytes32 currentHash) = kms.currentRootEpoch();
        assertEq(current, 0);
        assertEq(currentHash, h0);
        (bytes memory k256Key, bytes memory caKey,,) = kms.kmsInfo();
        assertEq(caKey, ca(0xa0));
        assertEq(k256Key, k256(0xb0));

        kms.activateRootEpoch(1, replacementHash);
        (current, currentHash) = kms.currentRootEpoch();
        assertEq(current, 1);
        assertEq(currentHash, replacementHash);
        (k256Key, caKey,,) = kms.kmsInfo();
        assertEq(caKey, ca(0xa2));
        assertEq(k256Key, k256(0xb2));
        vm.stopPrank();
    }

    function test_RegisterRootEpochZeroMustMatchKmsInfo() public {
        upgradeLegacyKms();
        vm.startPrank(owner);
        vm.expectRevert("Epoch 0 keys differ from kmsInfo");
        kms.registerRootEpoch(ca(0xa1), k256(0xb0), "ipfs://c0");
        vm.expectRevert("Epoch 0 keys differ from kmsInfo");
        kms.registerRootEpoch(ca(0xa0), k256(0xb1), "ipfs://c0");
        assertEq(kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0"), 0);
        // Later epochs are new keys by definition.
        assertEq(kms.registerRootEpoch(ca(0xa1), k256(0xb1), "ipfs://c1"), 1);
        vm.stopPrank();
    }

    function test_PopRootEpochDropsOnlyThePendingOne() public {
        bytes32 h0 = chainHash(bytes32(0), ca(0xa0), k256(0xb0));
        bytes32 h1 = chainHash(h0, ca(0xa1), k256(0xb1));
        bytes32 h1b = chainHash(h0, ca(0xa2), k256(0xb2));
        vm.startPrank(owner);
        vm.expectRevert("Not the pending root epoch");
        kms.popRootEpoch(0, h0);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0");
        vm.expectRevert("Not the pending root epoch");
        kms.popRootEpoch(0, h0);
        kms.registerRootEpoch(ca(0xa1), k256(0xb1), "ipfs://c1");
        vm.expectRevert("Not the pending root epoch");
        kms.popRootEpoch(2, h1);
        vm.expectRevert("Root epoch chain hash mismatch");
        kms.popRootEpoch(1, h1b);

        vm.expectEmit(true, true, true, true);
        emit RootEpochPopped(1, h1);
        kms.popRootEpoch(1, h1);
        assertEq(kms.rootEpochCount(), 1);

        // A new epoch 1 replaces the dropped one; a stale pop of the old one
        // cannot drop it.
        assertEq(kms.registerRootEpoch(ca(0xa2), k256(0xb2), "ipfs://c2"), 1);
        vm.expectRevert("Root epoch chain hash mismatch");
        kms.popRootEpoch(1, h1);
        kms.activateRootEpoch(1, h1b);
        vm.expectRevert("Not the pending root epoch");
        kms.popRootEpoch(1, h1b);
        vm.stopPrank();

        (uint256 epoch, bytes32 h) = kms.currentRootEpoch();
        assertEq(epoch, 1);
        assertEq(h, h1b);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, user));
        kms.popRootEpoch(1, h1b);
    }

    function test_SetRootEpochEvidenceUrl() public {
        vm.startPrank(owner);
        vm.expectRevert("Unknown root epoch");
        kms.setRootEpochEvidenceUrl(0, "ipfs://moved");
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0");
        vm.expectRevert("Empty epoch evidence URL");
        kms.setRootEpochEvidenceUrl(0, "");
        vm.expectEmit(true, true, true, true);
        emit RootEpochEvidenceUrlSet(0, "https://mirror/c0");
        kms.setRootEpochEvidenceUrl(0, "https://mirror/c0");
        vm.stopPrank();

        (,, string memory evidenceUrl, bytes32 h) = kms.rootEpoch(0);
        assertEq(evidenceUrl, "https://mirror/c0");
        assertEq(h, chainHash(bytes32(0), ca(0xa0), k256(0xb0)));

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, user));
        kms.setRootEpochEvidenceUrl(0, "ipfs://evil");
    }

    function test_KmsInfoFollowsTheCurrentRootEpoch() public {
        upgradeLegacyKms();
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0");
        (bytes memory k256Key, bytes memory caKey, bytes memory quote, bytes memory eventlog) = kms.kmsInfo();
        assertEq(caKey, ca(0xa0));
        assertEq(k256Key, k256(0xb0));
        assertEq(quote.length + eventlog.length, 0);

        // A pending epoch is not the KMS identity yet.
        kms.registerRootEpoch(ca(0xa1), k256(0xb1), "ipfs://c1");
        (k256Key, caKey,,) = kms.kmsInfo();
        assertEq(caKey, ca(0xa0));
        (,,, bytes32 h1) = kms.rootEpoch(1);
        kms.activateRootEpoch(1, h1);
        (k256Key, caKey,,) = kms.kmsInfo();
        assertEq(caKey, ca(0xa1));
        assertEq(k256Key, k256(0xb1));

        vm.stopPrank();
        assertLegacySettersDisabled(owner);
        assertLegacySettersDisabled(user);
    }

    function test_RegisterRootEpochOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, user));
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0");
    }

    function test_RegisterRootEpochRejectsMalformedKeys() public {
        bytes memory compressedCa = ca(0xa0);
        compressedCa[26] = 0x02;
        bytes memory otherCurve = ca(0xa0);
        otherCurve[25] = 0x0a;
        bytes memory uncompressedK256 = bytes.concat(hex"04", new bytes(64));
        vm.startPrank(owner);
        vm.expectRevert("Invalid epoch CA public key");
        kms.registerRootEpoch("", k256(0xb0), "ipfs://c0");
        vm.expectRevert("Invalid epoch CA public key");
        kms.registerRootEpoch(bytes.concat(ca(0xa0), hex"00"), k256(0xb0), "ipfs://c0");
        vm.expectRevert("Invalid epoch CA public key");
        kms.registerRootEpoch(compressedCa, k256(0xb0), "ipfs://c0");
        vm.expectRevert("Invalid epoch CA public key");
        kms.registerRootEpoch(otherCurve, k256(0xb0), "ipfs://c0");
        vm.expectRevert("Invalid epoch k256 public key");
        kms.registerRootEpoch(ca(0xa0), "", "ipfs://c0");
        vm.expectRevert("Invalid epoch k256 public key");
        kms.registerRootEpoch(ca(0xa0), uncompressedK256, "ipfs://c0");
        vm.expectRevert("Invalid epoch k256 public key");
        kms.registerRootEpoch(ca(0xa0), bytes.concat(hex"04", new bytes(32)), "ipfs://c0");
        vm.expectRevert("Empty epoch evidence URL");
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "");
        vm.stopPrank();
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

    function authorizationInfo(address appId) internal pure returns (DstackKms.AppInfo memory) {
        return DstackKms.AppInfo({
            appId: appId,
            composeHash: bytes32(uint256(789)),
            instanceId: address(0),
            deviceId: bytes32(uint256(123)),
            mrAggregated: bytes32(uint256(456)),
            mrSystem: bytes32(0),
            osImageHash: bytes32(uint256(111)),
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });
    }

    function authorize(DstackKms.AppInfo memory info) internal view returns (DstackKms.AuthorizationResult memory) {
        return kms.checkAuthorization(DstackKms.AuthorizationRequest(info, DstackKms.OptionalEpoch(false, 0)));
    }

    function test_CheckAuthorization_OptionalEpochDistinguishesZeroFromDefault() public {
        DstackKms.AppInfo memory info = authorizationInfo(address(kms));
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "https://example.com/epoch-0");
        kms.registerRootEpoch(ca(0xa1), k256(0xb1), "https://example.com/epoch-1");
        kms.addOsImageHash(info.osImageHash);
        kms.addKmsDevice(info.deviceId);
        kms.addKmsAggregatedMr(info.mrAggregated);
        vm.stopPrank();

        DstackKms.AuthorizationRequest memory request =
            DstackKms.AuthorizationRequest(info, DstackKms.OptionalEpoch(true, 1));
        DstackKms.AuthorizationResult memory result = kms.checkAuthorization(request);
        assertFalse(result.isAllowed);
        assertEq(result.rejectionReason, "Requested root epoch is not active");
        bytes32 h1 = chainHash(chainHash(bytes32(0), ca(0xa0), k256(0xb0)), ca(0xa1), k256(0xb1));
        vm.prank(owner);
        kms.activateRootEpoch(1, h1);
        assertTrue(kms.checkAuthorization(request).isAllowed);
        request.requestedEpoch.value = 0;
        assertTrue(kms.checkAuthorization(request).isAllowed);
        request.requestedEpoch.value = type(uint256).max;
        assertFalse(kms.checkAuthorization(request).isAllowed);
        request.requestedEpoch.isSet = false;
        result = kms.checkAuthorization(request);
        assertTrue(result.isAllowed);
        assertEq(result.currentRootEpoch, 1);
        assertEq(result.currentRootEpochHash, h1);
    }

    function test_CheckAuthorization_UnregisteredEpochReturnsRejection() public view {
        DstackKms.AuthorizationResult memory result = authorize(authorizationInfo(address(kms)));
        assertFalse(result.isAllowed);
        assertEq(result.rejectionReason, "Root epoch not registered");
        assertEq(result.currentRootEpoch, 0);
        assertEq(result.currentRootEpochHash, bytes32(0));
    }

    function test_CheckAuthorization_SelectsPolicyByAppId() public {
        DstackKms.AppInfo memory info = authorizationInfo(address(kms));
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "https://example.com/epoch-0");
        kms.setGatewayAppId("gateway");
        kms.addOsImageHash(info.osImageHash);
        kms.addKmsDevice(info.deviceId);
        kms.addKmsAggregatedMr(info.mrAggregated);
        address appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        vm.stopPrank();

        DstackKms.AuthorizationResult memory result = authorize(info);
        assertTrue(result.isAllowed);
        assertEq(result.rejectionReason, "");
        assertEq(result.gatewayAppId, "gateway");
        assertEq(result.currentRootEpochHash, chainHash(bytes32(0), ca(0xa0), k256(0xb0)));

        info.appId = user;
        result = authorize(info);
        assertFalse(result.isAllowed);
        assertEq(result.rejectionReason, "App not registered");

        info.appId = appId;
        info.mrAggregated = bytes32(0);
        result = authorize(info);
        assertTrue(result.isAllowed);
        info.appId = address(kms);
        result = authorize(info);
        assertFalse(result.isAllowed);
        assertEq(result.rejectionReason, "Aggregated MR not allowed");
    }

    function test_CheckAuthorization_RejectionIncludesActivatedEpoch() public {
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "https://example.com/epoch-0");
        kms.registerRootEpoch(ca(0xa1), k256(0xb1), "https://example.com/epoch-1");
        kms.activateRootEpoch(1);
        vm.stopPrank();

        DstackKms.AuthorizationResult memory result = authorize(authorizationInfo(user));
        assertFalse(result.isAllowed);
        assertEq(result.rejectionReason, "App not registered");
        assertEq(result.currentRootEpoch, 1);
        assertEq(
            result.currentRootEpochHash, chainHash(chainHash(bytes32(0), ca(0xa0), k256(0xb0)), ca(0xa1), k256(0xb1))
        );
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
