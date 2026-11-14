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
import { DstackKms as DstackKmsV059 } from "../contracts/test-utils/reference/v0.5.9/DstackKmsV059.sol";

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
            "DstackKmsV059.sol:DstackKms", abi.encodeCall(DstackKmsV059.initialize, (owner, address(appImpl)))
        );
        DstackKmsV059(proxy).setKmsInfo(DstackKmsV059.KmsInfo(k256(0xb0), ca(0xa0), hex"0d", hex"0e"));
        Options memory opts;
        opts.referenceContract = "DstackKmsV059.sol:DstackKms";
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
        vm.expectRevert(DstackKms.NoRootEpochRegistered.selector);
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
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
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
        vm.expectRevert(DstackKms.InvalidRootEpochActivation.selector);
        kms.activateRootEpoch(1, h1);
        kms.registerRootEpoch(ca(0xa1), k256(0xb1), "ipfs://c1");
        kms.registerRootEpoch(ca(0xa2), k256(0xb2), "ipfs://c2");
        vm.expectRevert(DstackKms.InvalidRootEpochActivation.selector);
        kms.activateRootEpoch(2, h2);
        vm.expectEmit(true, true, true, true);
        emit RootEpochActivated(1);
        kms.activateRootEpoch(1, h1);
        vm.expectRevert(DstackKms.InvalidRootEpochActivation.selector);
        kms.activateRootEpoch(1, h1);
        vm.expectRevert(DstackKms.InvalidRootEpochActivation.selector);
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

        vm.expectRevert(DstackKms.RootEpochChainHashMismatch.selector);
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
        vm.expectRevert(DstackKms.Epoch0KeysDifferFromKmsInfo.selector);
        kms.registerRootEpoch(ca(0xa1), k256(0xb0), "ipfs://c0");
        vm.expectRevert(DstackKms.Epoch0KeysDifferFromKmsInfo.selector);
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
        vm.expectRevert(DstackKms.NotPendingRootEpoch.selector);
        kms.popRootEpoch(0, h0);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0");
        vm.expectRevert(DstackKms.NotPendingRootEpoch.selector);
        kms.popRootEpoch(0, h0);
        kms.registerRootEpoch(ca(0xa1), k256(0xb1), "ipfs://c1");
        vm.expectRevert(DstackKms.NotPendingRootEpoch.selector);
        kms.popRootEpoch(2, h1);
        vm.expectRevert(DstackKms.RootEpochChainHashMismatch.selector);
        kms.popRootEpoch(1, h1b);

        vm.expectEmit(true, true, true, true);
        emit RootEpochPopped(1, h1);
        kms.popRootEpoch(1, h1);
        assertEq(kms.rootEpochCount(), 1);

        // A new epoch 1 replaces the dropped one; a stale pop of the old one
        // cannot drop it.
        assertEq(kms.registerRootEpoch(ca(0xa2), k256(0xb2), "ipfs://c2"), 1);
        vm.expectRevert(DstackKms.RootEpochChainHashMismatch.selector);
        kms.popRootEpoch(1, h1);
        kms.activateRootEpoch(1, h1b);
        vm.expectRevert(DstackKms.NotPendingRootEpoch.selector);
        kms.popRootEpoch(1, h1b);
        vm.stopPrank();

        (uint256 epoch, bytes32 h) = kms.currentRootEpoch();
        assertEq(epoch, 1);
        assertEq(h, h1b);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, user));
        kms.popRootEpoch(1, h1b);
    }

    function test_PolicyRowsBelongToTheRegisteredKeysOfAnEpoch() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(kms));
        vm.startPrank(owner);
        // Epoch 0 keeps the legacy mappings, even before any registration.
        approveKmsAtEpoch(info, 0);
        assertTrue(kms.allowedOsImages(info.osImageHash));
        assertTrue(kms.kmsAllowedAggregatedMrs(info.mrAggregated));
        assertTrue(kms.kmsAllowedDeviceIds(info.deviceId));
        // Rows of an unregistered epoch can be neither written nor read.
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.addOsImageHashAtEpochs(1, 1, info.osImageHash);
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.addKmsAggregatedMrAtEpochs(1, 1, info.mrAggregated);
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.addKmsDeviceAtEpochs(1, 1, info.deviceId);
        registerNextRootEpoch();
        registerNextRootEpoch();
        approveKmsAtEpoch(info, 1);
        assertTrue(kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized);

        (,,, bytes32 h1) = kms.rootEpoch(1);
        kms.popRootEpoch(1, h1);
        assertFalse(kms.allowedOsImagesAtEpoch(1, info.osImageHash));
        // Other keys registered under the same number start with empty rows.
        kms.registerRootEpoch(ca(0xc1), k256(0xd1), "ipfs://replacement");
        assertFalse(kms.allowedOsImagesAtEpoch(1, info.osImageHash));
        assertFalse(kms.kmsAllowedAggregatedMrsAtEpoch(1, info.mrAggregated));
        assertFalse(kms.kmsAllowedDeviceIdsAtEpoch(1, info.deviceId));
        assertFalse(kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized);
        approveKmsAtEpoch(info, 1);
        assertTrue(kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized);
        // Epoch 0 is untouched throughout.
        assertTrue(kms.allowedOsImagesAtEpoch(0, info.osImageHash));
        vm.stopPrank();
    }

    function test_SetRootEpochEvidenceUrl() public {
        vm.startPrank(owner);
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.setRootEpochEvidenceUrl(0, "ipfs://moved");
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "ipfs://c0");
        vm.expectRevert(DstackKms.EmptyEpochEvidenceUrl.selector);
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
        vm.expectRevert(DstackKms.InvalidEpochCaPubkey.selector);
        kms.registerRootEpoch("", k256(0xb0), "ipfs://c0");
        vm.expectRevert(DstackKms.InvalidEpochCaPubkey.selector);
        kms.registerRootEpoch(bytes.concat(ca(0xa0), hex"00"), k256(0xb0), "ipfs://c0");
        vm.expectRevert(DstackKms.InvalidEpochCaPubkey.selector);
        kms.registerRootEpoch(compressedCa, k256(0xb0), "ipfs://c0");
        vm.expectRevert(DstackKms.InvalidEpochCaPubkey.selector);
        kms.registerRootEpoch(otherCurve, k256(0xb0), "ipfs://c0");
        vm.expectRevert(DstackKms.InvalidEpochK256Pubkey.selector);
        kms.registerRootEpoch(ca(0xa0), "", "ipfs://c0");
        vm.expectRevert(DstackKms.InvalidEpochK256Pubkey.selector);
        kms.registerRootEpoch(ca(0xa0), uncompressedK256, "ipfs://c0");
        vm.expectRevert(DstackKms.InvalidEpochK256Pubkey.selector);
        kms.registerRootEpoch(ca(0xa0), bytes.concat(hex"04", new bytes(32)), "ipfs://c0");
        vm.expectRevert(DstackKms.EmptyEpochEvidenceUrl.selector);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "");
        vm.stopPrank();
    }

    function test_AddKmsAggregatedMr() public {
        bytes32 mr = bytes32(uint256(123));

        vm.prank(owner);
        kms.addKmsAggregatedMrAtEpochs(0, 0, mr);

        assertTrue(kms.kmsAllowedAggregatedMrs(mr));
    }

    function test_RemoveKmsAggregatedMr() public {
        bytes32 mr = bytes32(uint256(123));

        vm.startPrank(owner);
        kms.addKmsAggregatedMrAtEpochs(0, 0, mr);
        assertTrue(kms.kmsAllowedAggregatedMrs(mr));

        kms.removeKmsAggregatedMrAtEpochs(0, 0, mr);
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
        kms.addKmsDeviceAtEpochs(0, 0, deviceId);
        assertTrue(kms.kmsAllowedDeviceIds(deviceId));

        kms.removeKmsDeviceAtEpochs(0, 0, deviceId);
        assertFalse(kms.kmsAllowedDeviceIds(deviceId));
        vm.stopPrank();
    }

    function test_AddAndRemoveOsImageHash() public {
        bytes32 imageHash = bytes32(uint256(888));

        vm.startPrank(owner);
        kms.addOsImageHashAtEpochs(0, 0, imageHash);
        assertTrue(kms.allowedOsImages(imageHash));

        kms.removeOsImageHashAtEpochs(0, 0, imageHash);
        assertFalse(kms.allowedOsImages(imageHash));
        vm.stopPrank();
    }

    function authorizationInfo(address appId) internal pure returns (IAppAuth.AppInfo memory) {
        return IAppAuth.AppInfo({
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

    function authorize(IAppAuth.AppInfo memory info, bool isKms) internal view returns (AuthorizationResult memory) {
        AuthorizationRequest memory request = AuthorizationRequest(
            info,
            isKms ? keccak256("kms_serve") : keccak256("app_get_key"),
            OptionalUint256(false, 0),
            OptionalUint256(false, 0),
            "dstack-tdx",
            bytes32(0)
        );
        return isKms ? kms.authorizeKms(request) : kms.authorizeApp(request);
    }

    function test_TeeVariantsRestrictKmsAndApps() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(kms));
        assertTrue(kms.allowAnyTeeVariant());
        string[] memory tdx = new string[](2);
        tdx[0] = "dstack-tdx";
        tdx[1] = "dstack-gcp-tdx";
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "https://example.com/epoch-0");
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        kms.addKmsDeviceAtEpochs(0, 0, info.deviceId);
        kms.addKmsAggregatedMrAtEpochs(0, 0, info.mrAggregated);
        address appId = kms.deployAndRegisterApp(user, false, true, info.deviceId, info.composeHash);
        kms.setAllowedTeeVariants(tdx);
        kms.setAllowAnyTeeVariant(false);
        vm.stopPrank();

        assertTrue(authorize(info, true).authorized);
        (bool allowed, string memory reason) = kms.isKmsAllowed(info);
        assertFalse(allowed);
        assertEq(reason, "TEE variant not allowed");
        AuthorizationRequest memory request = AuthorizationRequest(
            info, keccak256("kms_serve"), OptionalUint256(false, 0), OptionalUint256(false, 0), "dstack-tdx", bytes32(0)
        );
        request.teeVariant = "dstack-gcp-tdx";
        assertTrue(kms.authorizeKms(request).authorized);
        request.teeVariant = "dstack-amd-sev-snp";
        assertEq(kms.authorizeKms(request).rejectionReason, "TEE variant not allowed");
        // A platform the contract does not know is refused once restricted.
        request.teeVariant = "dstack-new-platform";
        assertEq(kms.authorizeKms(request).rejectionReason, "TEE variant not allowed");

        info.appId = appId;
        assertTrue(authorize(info, false).authorized);
        (allowed, reason) = kms.isAppAllowed(info);
        assertFalse(allowed);
        assertEq(reason, "TEE variant not allowed");
        request = AuthorizationRequest(
            info,
            keccak256("app_get_key"),
            OptionalUint256(false, 0),
            OptionalUint256(false, 0),
            "dstack-tdx",
            bytes32(0)
        );
        request.teeVariant = "dstack-amd-sev-snp";
        assertEq(kms.authorizeApp(request).rejectionReason, "TEE variant not allowed");

        // Allowing any platform lifts the restriction, including for legacy callers.
        vm.prank(owner);
        kms.setAllowAnyTeeVariant(true);
        assertTrue(kms.authorizeApp(request).authorized);
        (allowed,) = kms.isAppAllowed(info);
        assertTrue(allowed);

        // With the KMS unrestricted, the app's own policy still applies.
        vm.startPrank(user);
        DstackApp(appId).setAllowedTeeVariants(tdx);
        DstackApp(appId).setAllowAnyTeeVariant(false);
        vm.stopPrank();
        assertEq(kms.authorizeApp(request).rejectionReason, "TEE variant not allowed");
        (allowed, reason) = kms.isAppAllowed(info);
        assertFalse(allowed);
        assertEq(reason, "TEE variant not allowed");
        request.teeVariant = "dstack-gcp-tdx";
        assertTrue(kms.authorizeApp(request).authorized);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, user));
        kms.setAllowAnyTeeVariant(false);
    }

    function test_AuthorizationOperationsFailClosedAndBootstrapBeforeRegistration() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(kms));
        vm.startPrank(owner);
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        kms.addKmsDeviceAtEpochs(0, 0, info.deviceId);
        kms.addKmsAggregatedMrAtEpochs(0, 0, info.mrAggregated);
        vm.stopPrank();
        AuthorizationRequest memory request = AuthorizationRequest(
            info,
            keccak256("kms_bootstrap"),
            OptionalUint256(false, 0),
            OptionalUint256(false, 0),
            "dstack-tdx",
            bytes32(0)
        );
        assertTrue(kms.authorizeKms(request).authorized);
        assertEq(kms.authorizeKms(request).currentRootEpochHash, bytes32(0));
        request.operation = keccak256("kms_export_keys");
        assertEq(kms.authorizeKms(request).rejectionReason, "Root epoch not registered");
        vm.prank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "https://example.com/epoch-0");
        assertTrue(kms.authorizeKms(request).authorized);
        request.operation = keccak256("kms_import_keys");
        assertTrue(kms.authorizeKms(request).authorized);
        assertEq(kms.authorizeApp(request).rejectionReason, "Invalid authorization operation");
        request.operation = keccak256("app_get_cert");
        assertEq(kms.authorizeKms(request).rejectionReason, "Invalid authorization operation");
        request.operation = bytes32(0);
        assertEq(kms.authorizeKms(request).rejectionReason, "Invalid authorization operation");
        assertEq(kms.authorizeApp(request).rejectionReason, "Invalid authorization operation");
    }

    function test_KmsLaunchTicketGatesOnlyTheKeyImport() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(kms));
        bytes32 ticket = sha256("dstack-launch-ticket/v1:replica");
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "https://example.com/epoch-0");
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        kms.addKmsDeviceAtEpochs(0, 0, info.deviceId);
        kms.addKmsAggregatedMrAtEpochs(0, 0, info.mrAggregated);
        kms.setRequireKmsLaunchTicket(true);
        vm.expectRevert(DstackKms.InvalidLaunchTicketHash.selector);
        kms.addKmsLaunchTicket(bytes32(0), "zero");
        kms.addKmsLaunchTicket(ticket, "replica");
        vm.stopPrank();
        assertEq(kms.kmsLaunchTickets()[0], ticket);

        AuthorizationRequest memory request = AuthorizationRequest(
            info,
            keccak256("kms_import_keys"),
            OptionalUint256(false, 0),
            OptionalUint256(false, 0),
            "dstack-tdx",
            bytes32(0)
        );
        assertEq(kms.authorizeKms(request).rejectionReason, "Invalid launch ticket");
        request.launchTicketHash = ticket;
        assertTrue(kms.authorizeKms(request).authorized);
        // The other operations hand out no root keys and need no ticket.
        request.launchTicketHash = bytes32(0);
        request.operation = keccak256("kms_export_keys");
        assertTrue(kms.authorizeKms(request).authorized);
        request.operation = keccak256("kms_serve");
        assertTrue(kms.authorizeKms(request).authorized);
        request.operation = keccak256("kms_bootstrap");
        assertTrue(kms.authorizeKms(request).authorized);
        // Legacy callers cannot present one.
        (bool allowed, string memory reason) = kms.isKmsAllowed(info);
        assertFalse(allowed);
        assertEq(reason, "Invalid launch ticket");

        vm.prank(owner);
        kms.removeKmsLaunchTicket(ticket);
        assertEq(kms.kmsLaunchTickets().length, 0);
        request.operation = keccak256("kms_import_keys");
        request.launchTicketHash = ticket;
        assertEq(kms.authorizeKms(request).rejectionReason, "Invalid launch ticket");

        vm.startPrank(user);
        bytes memory unauthorized = abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user);
        vm.expectRevert(unauthorized);
        kms.setRequireKmsLaunchTicket(false);
        vm.expectRevert(unauthorized);
        kms.addKmsLaunchTicket(ticket, "replica");
        vm.expectRevert(unauthorized);
        kms.removeKmsLaunchTicket(ticket);
        vm.stopPrank();
    }

    function test_CheckAuthorization_OptionalUint256DistinguishesZeroFromDefault() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(kms));
        vm.startPrank(owner);
        registerNextRootEpoch();
        registerNextRootEpoch();
        approveKmsAtEpoch(info, 1);
        assertFalse(kms.allowedOsImages(info.osImageHash));
        assertTrue(kms.allowedOsImagesAtEpoch(1, info.osImageHash));
        assertFalse(authorize(info, true).authorized);
        assertTrue(
            kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized, "pending handover must be explicitly approved"
        );
        assertFalse(kms.authorizeApp(epochRequest(info, 1, 0)).authorized, "apps cannot fetch pending keys");
        AuthorizationResult memory result = kms.authorizeKms(kmsEpochRequest(info, 2, 0));
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "Requested root epoch is not registered");
        activateNextRootEpoch();
        result = authorize(info, true);
        assertTrue(result.authorized);
        assertEq(result.currentRootEpoch, 1);
        assertFalse(kms.authorizeKms(kmsEpochRequest(info, 0, 0)).authorized, "epoch one does not imply epoch zero");
        approveKmsAtEpoch(info, 0);
        assertTrue(kms.authorizeKms(kmsEpochRequest(info, 0, 0)).authorized);
        vm.stopPrank();
    }

    function test_CheckAuthorization_UnregisteredEpochReturnsRejection() public view {
        AuthorizationResult memory result = authorize(authorizationInfo(address(kms)), true);
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "Root epoch not registered");
        assertEq(result.currentRootEpoch, 0);
        assertEq(result.currentRootEpochHash, bytes32(0));
    }

    function test_CheckAuthorization_ValidatesRequestedPolicy() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(kms));
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "https://example.com/epoch-0");
        kms.setGatewayAppId("gateway");
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        kms.addKmsDeviceAtEpochs(0, 0, info.deviceId);
        kms.addKmsAggregatedMrAtEpochs(0, 0, info.mrAggregated);
        address appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        vm.stopPrank();

        AuthorizationResult memory result = authorize(info, true);
        assertTrue(result.authorized);
        assertEq(result.rejectionReason, "");
        assertEq(result.gatewayAppId, "gateway");
        assertEq(result.currentRootEpochHash, chainHash(bytes32(0), ca(0xa0), k256(0xb0)));

        info.appId = user;
        result = authorize(info, false);
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "App not registered");

        info.appId = appId;
        info.mrAggregated = bytes32(0);
        result = authorize(info, false);
        assertTrue(result.authorized);
        result = authorize(info, true);
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "Aggregated MR not allowed");
        AuthorizationRequest memory appRequest = AuthorizationRequest(
            info,
            keccak256("app_get_key"),
            OptionalUint256(true, 1),
            OptionalUint256(false, 0),
            "dstack-tdx",
            bytes32(0)
        );
        result = kms.authorizeApp(appRequest);
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "Requested app epoch is not active");
        assertEq(result.currentRootEpochHash, chainHash(bytes32(0), ca(0xa0), k256(0xb0)));
        info.appId = address(kms);
        result = authorize(info, false);
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "App not registered");
        result = authorize(info, true);
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "Aggregated MR not allowed");
    }

    function test_AppEpochCapabilityIsOptionalButGetterFailuresPropagate() public {
        address policy = address(new DstackApp());
        kms.registerApp(policy);
        vm.mockCall(policy, abi.encodeCall(IAppEpochAuth.currentAppEpoch, ()), abi.encode(uint256(7)));
        assertEq(kms.currentAppEpoch(policy), 7);
        vm.mockCall(
            policy, abi.encodeCall(IERC165.supportsInterface, (type(IAppEpochAuth).interfaceId)), abi.encode(false)
        );
        // Advertising either old single-method interface does not opt into the combined capability.
        vm.mockCall(
            policy,
            abi.encodeCall(IERC165.supportsInterface, (IAppEpochAuth.currentAppEpoch.selector)),
            abi.encode(true)
        );
        vm.mockCall(
            policy, abi.encodeCall(IERC165.supportsInterface, (IAppEpochAuth.authorizeApp.selector)), abi.encode(true)
        );
        assertEq(kms.currentAppEpoch(policy), 0);
        vm.clearMockedCalls();
        vm.mockCallRevert(policy, abi.encodeCall(IAppEpochAuth.currentAppEpoch, ()), "epoch unavailable");
        vm.expectRevert("epoch unavailable");
        kms.currentAppEpoch(policy);
    }

    function test_AppEpochQueryRevertsForUnregisteredOrUndeployedApps() public {
        address policy = address(new DstackApp());
        vm.expectRevert(DstackKms.AppNotRegistered.selector);
        kms.currentAppEpoch(policy);
        address eoa = address(0xbeef);
        kms.registerApp(eoa);
        vm.expectRevert(DstackKms.AppNotDeployed.selector);
        kms.currentAppEpoch(eoa);
        // A registered legacy policy without the capability is epoch zero.
        kms.registerApp(policy);
        vm.mockCall(
            policy, abi.encodeCall(IERC165.supportsInterface, (type(IAppEpochAuth).interfaceId)), abi.encode(false)
        );
        assertEq(kms.currentAppEpoch(policy), 0);
        // The authorization paths still report the rejection instead of reverting.
        DstackKms.AppInfo memory info = authorizationInfo(address(0x1234));
        (bool allowed, string memory reason) = kms.isAppAllowed(info);
        assertFalse(allowed);
        assertEq(reason, "App not registered");
        vm.prank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "https://example.com/epoch-0");
        assertEq(authorize(info, false).rejectionReason, "App not registered");
    }

    function test_AppEpochRotationIsOwnerScopedAndDoesNotChangeRootEpoch() public {
        DstackKms.AppInfo memory info = authorizationInfo(address(0));
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "https://example.com/epoch-0");
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        address appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        address otherApp = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        vm.stopPrank();
        info.appId = appId;
        assertEq(kms.currentAppEpoch(appId), 0);
        vm.prank(owner);
        vm.expectRevert();
        DstackApp(appId).advanceAppEpoch(0);
        vm.prank(user);
        DstackApp(appId).advanceAppEpoch(0);
        vm.prank(user);
        vm.expectRevert("App epoch changed");
        DstackApp(appId).advanceAppEpoch(0);
        assertEq(kms.currentAppEpoch(appId), 1);
        assertEq(kms.currentAppEpoch(otherApp), 0);
        (uint256 rootEpoch,) = kms.currentRootEpoch();
        assertEq(rootEpoch, 0);
        AuthorizationRequest memory request = AuthorizationRequest(
            info,
            keccak256("app_get_key"),
            OptionalUint256(false, 0),
            OptionalUint256(false, 0),
            "dstack-tdx",
            bytes32(0)
        );
        AuthorizationResult memory result = kms.authorizeApp(request);
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "Compose hash not allowed");
        assertEq(result.currentAppEpoch, 1);
        request.requestedAppEpoch = OptionalUint256(true, 0);
        assertTrue(kms.authorizeApp(request).authorized);
        request.requestedAppEpoch.value = 2;
        result = kms.authorizeApp(request);
        assertFalse(result.authorized);
        assertEq(result.currentAppEpoch, 1);
        assertEq(result.rejectionReason, "Requested app epoch is not active");
        request.requestedAppEpoch = OptionalUint256(false, 0);
        request.appInfo.composeHash = bytes32(0);
        result = kms.authorizeApp(request);
        assertFalse(result.authorized);
        assertEq(result.currentAppEpoch, 1);
        vm.prank(user);
        DstackApp(appId).advanceAppEpoch(1);
        assertEq(kms.currentAppEpoch(appId), 2);
    }

    function test_CheckAuthorization_RejectionIncludesActivatedEpoch() public {
        vm.startPrank(owner);
        kms.registerRootEpoch(ca(0xa0), k256(0xb0), "https://example.com/epoch-0");
        kms.registerRootEpoch(ca(0xa1), k256(0xb1), "https://example.com/epoch-1");
        kms.activateRootEpoch(1, chainHash(chainHash(bytes32(0), ca(0xa0), k256(0xb0)), ca(0xa1), k256(0xb1)));
        vm.stopPrank();

        bytes32 hash1 = chainHash(chainHash(bytes32(0), ca(0xa0), k256(0xb0)), ca(0xa1), k256(0xb1));
        AuthorizationResult memory result = authorize(authorizationInfo(user), false);
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "App not registered");
        assertEq(result.currentRootEpoch, 1);
        assertEq(result.currentRootEpochHash, hash1);

        AuthorizationRequest memory request = AuthorizationRequest(
            authorizationInfo(user),
            keccak256("kms_serve"),
            OptionalUint256(false, 0),
            OptionalUint256(false, 0),
            "dstack-tdx",
            bytes32(0)
        );
        result = kms.authorizeApp(request);
        assertEq(result.rejectionReason, "Invalid authorization operation");
        assertEq(result.currentRootEpoch, 1);
        assertEq(result.currentRootEpochHash, hash1);
    }

    function test_IsKmsAllowed() public {
        bytes32 deviceId = bytes32(uint256(123));
        bytes32 mrAggregated = bytes32(uint256(456));
        bytes32 osImageHash = bytes32(uint256(789));

        // Setup allowed values
        vm.startPrank(owner);
        kms.addKmsDeviceAtEpochs(0, 0, deviceId);
        kms.addKmsAggregatedMrAtEpochs(0, 0, mrAggregated);
        kms.addOsImageHashAtEpochs(0, 0, osImageHash);
        vm.stopPrank();

        IAppAuth.AppInfo memory bootInfo = IAppAuth.AppInfo({
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
        kms.addKmsDeviceAtEpochs(0, 0, deviceId);
        kms.addKmsAggregatedMrAtEpochs(0, 0, mrAggregated);
        kms.addOsImageHashAtEpochs(0, 0, osImageHash);
        vm.stopPrank();

        IAppAuth.AppInfo memory bootInfo = IAppAuth.AppInfo({
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
        kms.addOsImageHashAtEpochs(0, 0, osImageHash);
        address appId = kms.deployAndRegisterApp(user, false, false, deviceId, composeHash);
        vm.stopPrank();

        IAppAuth.AppInfo memory bootInfo = IAppAuth.AppInfo({
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
        kms.addKmsAggregatedMrAtEpochs(0, 0, mr);

        // New owner has it.
        vm.prank(newOwner);
        kms.addKmsAggregatedMrAtEpochs(0, 0, mr);
        assertTrue(kms.kmsAllowedAggregatedMrs(mr));
    }

    function registerNextRootEpoch() internal {
        uint256 epoch = kms.rootEpochCount();
        kms.registerRootEpoch(ca(uint8(0xa0 + epoch)), k256(uint8(0xb0 + epoch)), "ipfs://epoch");
    }

    function activateNextRootEpoch() internal {
        (uint256 current,) = kms.currentRootEpoch();
        (,,, bytes32 hash) = kms.rootEpoch(current + 1);
        kms.activateRootEpoch(current + 1, hash);
    }

    function epochRequest(
        IAppAuth.AppInfo memory info,
        uint256 root,
        uint256 appEpoch
    )
        internal
        pure
        returns (AuthorizationRequest memory)
    {
        return AuthorizationRequest(
            info,
            keccak256("app_get_key"),
            OptionalUint256(true, appEpoch),
            OptionalUint256(true, root),
            "dstack-tdx",
            bytes32(0)
        );
    }

    function kmsEpochRequest(
        IAppAuth.AppInfo memory info,
        uint256 root,
        uint256 appEpoch
    )
        internal
        pure
        returns (AuthorizationRequest memory request)
    {
        request = epochRequest(info, root, appEpoch);
        request.operation = keccak256("kms_import_keys");
    }

    function approveKmsAtEpoch(IAppAuth.AppInfo memory info, uint256 epoch) internal {
        kms.addOsImageHashAtEpochs(epoch, epoch, info.osImageHash);
        kms.addKmsAggregatedMrAtEpochs(epoch, epoch, info.mrAggregated);
        kms.addKmsDeviceAtEpochs(epoch, epoch, info.deviceId);
    }

    function test_KmsEpochRowsDoNotInheritAndCanBeRevokedIndependently() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(kms));
        vm.startPrank(owner);
        registerNextRootEpoch();
        approveKmsAtEpoch(info, 0);
        registerNextRootEpoch();
        activateNextRootEpoch();
        assertTrue(kms.authorizeKms(kmsEpochRequest(info, 0, 0)).authorized);
        assertFalse(authorize(info, true).authorized);
        (bool allowed, string memory reason) = kms.isKmsAllowed(info);
        assertFalse(allowed, "legacy KMS check ends at rotation");
        assertEq(reason, "Root epoch requires epoch-aware authorization");
        kms.addOsImageHashAtEpochs(1, 1, info.osImageHash);
        assertFalse(authorize(info, true).authorized);
        kms.addKmsAggregatedMrAtEpochs(1, 1, info.mrAggregated);
        assertFalse(authorize(info, true).authorized);
        kms.addKmsDeviceAtEpochs(1, 1, info.deviceId);
        assertTrue(authorize(info, true).authorized);
        kms.removeOsImageHashAtEpochs(1, 1, info.osImageHash);
        assertFalse(authorize(info, true).authorized);
        assertTrue(kms.allowedOsImages(info.osImageHash));
        assertTrue(kms.authorizeKms(kmsEpochRequest(info, 0, 0)).authorized);
        kms.addOsImageHashAtEpochs(1, 1, info.osImageHash);
        kms.removeKmsAggregatedMrAtEpochs(0, 0, info.mrAggregated);
        assertFalse(kms.authorizeKms(kmsEpochRequest(info, 0, 0)).authorized);
        assertTrue(authorize(info, true).authorized);
        kms.addKmsAggregatedMrAtEpochs(0, 0, info.mrAggregated);
        kms.removeKmsDeviceAtEpochs(0, 0, info.deviceId);
        assertFalse(kms.authorizeKms(kmsEpochRequest(info, 0, 0)).authorized);
        assertTrue(authorize(info, true).authorized);
        vm.stopPrank();
    }

    function test_AppAndRootRowsAreSelectedIndependently() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(0));
        vm.startPrank(owner);
        registerNextRootEpoch();
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        info.appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        registerNextRootEpoch();
        activateNextRootEpoch();
        vm.stopPrank();
        DstackApp policy = DstackApp(info.appId);
        vm.prank(user);
        policy.advanceAppEpoch(0);
        assertFalse(kms.authorizeApp(epochRequest(info, 0, 1)).authorized);
        assertFalse(kms.authorizeApp(epochRequest(info, 1, 0)).authorized);
        assertTrue(kms.authorizeApp(epochRequest(info, 0, 0)).authorized);
        vm.startPrank(user);
        policy.addComposeHashAtEpoch(1, info.composeHash);
        policy.addDeviceAtEpoch(1, info.deviceId);
        vm.stopPrank();
        assertTrue(kms.authorizeApp(epochRequest(info, 0, 1)).authorized);
        assertFalse(authorize(info, false).authorized);
        vm.prank(owner);
        kms.addOsImageHashAtEpochs(1, 1, info.osImageHash);
        assertTrue(authorize(info, false).authorized);
        assertTrue(kms.authorizeApp(epochRequest(info, 1, 0)).authorized);
        vm.prank(owner);
        kms.removeOsImageHashAtEpochs(0, 0, info.osImageHash);
        assertFalse(kms.authorizeApp(epochRequest(info, 0, 0)).authorized);
        assertTrue(authorize(info, false).authorized);
    }

    function test_ExplicitRootEpochSettersRequireOwnerAndRegisteredEpoch() public {
        vm.startPrank(owner);
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.addOsImageHashAtEpochs(1, 1, bytes32(uint256(1)));
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.removeOsImageHashAtEpochs(1, 1, bytes32(uint256(1)));
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.addKmsAggregatedMrAtEpochs(1, 1, bytes32(uint256(1)));
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.removeKmsAggregatedMrAtEpochs(1, 1, bytes32(uint256(1)));
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.addKmsDeviceAtEpochs(1, 1, bytes32(uint256(1)));
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.removeKmsDeviceAtEpochs(1, 1, bytes32(uint256(1)));
        vm.stopPrank();
        bytes memory unauthorized = abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, user);
        vm.startPrank(user);
        vm.expectRevert(unauthorized);
        kms.addOsImageHashAtEpochs(0, 0, bytes32(uint256(1)));
        vm.expectRevert(unauthorized);
        kms.removeOsImageHashAtEpochs(0, 0, bytes32(uint256(1)));
        vm.expectRevert(unauthorized);
        kms.addKmsAggregatedMrAtEpochs(0, 0, bytes32(uint256(1)));
        vm.expectRevert(unauthorized);
        kms.removeKmsAggregatedMrAtEpochs(0, 0, bytes32(uint256(1)));
        vm.expectRevert(unauthorized);
        kms.addKmsDeviceAtEpochs(0, 0, bytes32(uint256(1)));
        vm.expectRevert(unauthorized);
        kms.removeKmsDeviceAtEpochs(0, 0, bytes32(uint256(1)));
        vm.stopPrank();
    }

    function test_AppOperationIsForwardedAndLegacyAuthorizationEndsAtRotation() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(0));
        vm.startPrank(owner);
        registerNextRootEpoch();
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        info.appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        vm.stopPrank();
        AuthorizationRequest memory request = epochRequest(info, 0, 0);
        vm.mockCall(
            info.appId,
            abi.encodeCall(IAppEpochAuth.authorizeApp, (request)),
            abi.encode(AuthorizationResult(false, "key retrieval denied", "", 0, bytes32(0), 0, 0, bytes32(0)))
        );
        assertEq(kms.authorizeApp(request).rejectionReason, "key retrieval denied");
        request.operation = keccak256("app_get_cert");
        vm.mockCall(
            info.appId,
            abi.encodeCall(IAppEpochAuth.authorizeApp, (request)),
            abi.encode(AuthorizationResult(true, "", "", 0, bytes32(0), 0, 0, bytes32(0)))
        );
        assertTrue(kms.authorizeApp(request).authorized);
        (bool allowed,) = kms.isAppAllowed(info);
        assertTrue(allowed);

        vm.startPrank(owner);
        registerNextRootEpoch();
        activateNextRootEpoch();
        vm.stopPrank();
        string memory reason;
        (allowed, reason) = kms.isAppAllowed(info);
        assertFalse(allowed);
        assertEq(reason, "Root epoch requires epoch-aware authorization");
    }

    function test_LegacyAppCheckRefusesOnceTheAppEpochAdvances() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(0));
        vm.startPrank(owner);
        registerNextRootEpoch();
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        info.appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        vm.stopPrank();
        (bool allowed,) = kms.isAppAllowed(info);
        assertTrue(allowed);

        vm.prank(user);
        DstackApp(info.appId).advanceAppEpoch(0);
        string memory reason;
        (allowed, reason) = kms.isAppAllowed(info);
        assertFalse(allowed);
        assertEq(reason, "App epoch requires epoch-aware authorization");
    }

    function test_AuthorizeAppForwardsRequestAndFillsKmsFields() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(0));
        vm.startPrank(owner);
        registerNextRootEpoch();
        kms.setGatewayAppId("gateway");
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        info.appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        vm.stopPrank();
        (, bytes32 rootHash) = kms.currentRootEpoch();
        AuthorizationRequest memory request = epochRequest(info, 0, 3);
        request.requestedRootEpoch = OptionalUint256(false, 0);
        // The KMS overwrites whatever the policy reports for fields it owns.
        vm.mockCall(
            info.appId,
            abi.encodeCall(IAppEpochAuth.authorizeApp, (request)),
            abi.encode(
                AuthorizationResult(true, "", "policy-gateway", 9, bytes32(uint256(9)), 3, 9, bytes32(uint256(9)))
            )
        );
        vm.expectCall(info.appId, abi.encodeCall(IAppEpochAuth.authorizeApp, (request)), 1);
        // The app epoch comes from the forwarded decision only.
        vm.expectCall(info.appId, abi.encodeCall(IAppEpochAuth.currentAppEpoch, ()), 0);
        AuthorizationResult memory result = kms.authorizeApp(request);
        assertTrue(result.authorized);
        assertEq(result.currentAppEpoch, 3);
        assertEq(result.gatewayAppId, "gateway");
        assertEq(result.currentRootEpoch, 0);
        assertEq(result.currentRootEpochHash, rootHash);
        assertEq(result.latestRootEpoch, 0);
        assertEq(result.latestRootEpochHash, rootHash);
    }

    function test_AuthorizationReportsTheLatestRegisteredRootEpoch() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(0));
        AuthorizationResult memory result = authorize(authorizationInfo(address(kms)), true);
        assertEq(result.latestRootEpoch, 0);
        assertEq(result.latestRootEpochHash, bytes32(0));
        vm.startPrank(owner);
        registerNextRootEpoch();
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        info.appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        registerNextRootEpoch();
        vm.stopPrank();
        (,,, bytes32 currentHash) = kms.rootEpoch(0);
        (,,, bytes32 pendingHash) = kms.rootEpoch(1);
        assertTrue(currentHash != pendingHash);
        AuthorizationRequest memory request = epochRequest(info, 0, 0);
        AuthorizationResult[3] memory results = [
            kms.authorizeKms(kmsEpochRequest(authorizationInfo(address(kms)), 1, 0)),
            kms.authorizeApp(request),
            // A KMS-side rejection still reports both epochs.
            kms.authorizeApp(epochRequest(info, 1, 0))
        ];
        for (uint256 i; i < results.length; i++) {
            assertEq(results[i].currentRootEpoch, 0);
            assertEq(results[i].currentRootEpochHash, currentHash);
            assertEq(results[i].latestRootEpoch, 1);
            assertEq(results[i].latestRootEpochHash, pendingHash);
        }
        assertTrue(results[1].authorized);
        assertEq(results[2].rejectionReason, "Requested root epoch is not active");
    }

    function test_AuthorizeAppKeepsKmsChecksBeforeForwarding() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(0));
        vm.startPrank(owner);
        registerNextRootEpoch();
        info.appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        vm.stopPrank();
        bytes memory forwarded = abi.encodeWithSelector(IAppEpochAuth.authorizeApp.selector);
        vm.expectCall(info.appId, forwarded, 0);
        assertEq(kms.authorizeApp(epochRequest(info, 0, 0)).rejectionReason, "OS image is not allowed");
        AuthorizationRequest memory request = epochRequest(info, 0, 0);
        request.operation = keccak256("kms_serve");
        assertEq(kms.authorizeApp(request).rejectionReason, "Invalid authorization operation");
        assertEq(kms.authorizeApp(epochRequest(info, 1, 0)).rejectionReason, "Requested root epoch is not active");
        info.appId = user;
        assertEq(kms.authorizeApp(epochRequest(info, 0, 0)).rejectionReason, "App not registered");
    }

    function test_LegacyAppPolicyCannotAuthorizeNonzeroAppEpochs() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(0));
        vm.startPrank(owner);
        registerNextRootEpoch();
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        info.appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        vm.stopPrank();
        vm.prank(user);
        DstackApp(info.appId).advanceAppEpoch(0);
        vm.mockCall(
            info.appId, abi.encodeCall(IERC165.supportsInterface, (type(IAppEpochAuth).interfaceId)), abi.encode(false)
        );
        vm.mockCall(info.appId, abi.encodeCall(IAppAuth.isAppAllowed, (info)), abi.encode(true, ""));
        assertTrue(kms.authorizeApp(epochRequest(info, 0, 0)).authorized);
        AuthorizationResult memory result = authorize(info, false);
        assertTrue(result.authorized);
        assertEq(result.currentAppEpoch, 0);
        result = kms.authorizeApp(epochRequest(info, 0, 1));
        assertFalse(result.authorized);
        assertEq(result.rejectionReason, "Requested app epoch is not active");
        vm.clearMockedCalls();
        vm.mockCallRevert(
            info.appId, abi.encodeCall(IAppEpochAuth.authorizeApp, (epochRequest(info, 0, 0))), "policy unavailable"
        );
        vm.expectRevert(bytes("policy unavailable"));
        kms.authorizeApp(epochRequest(info, 0, 0));
    }

    function test_RangeSettersCoverEveryRowInRange() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(0));
        vm.startPrank(owner);
        registerNextRootEpoch();
        registerNextRootEpoch();
        kms.addOsImageHashAtEpochs(0, 1, info.osImageHash);
        kms.addKmsAggregatedMrAtEpochs(0, 1, info.mrAggregated);
        kms.addKmsDeviceAtEpochs(0, 1, info.deviceId);
        info.appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        for (uint256 epoch = 0; epoch < 2; ++epoch) {
            assertTrue(kms.allowedOsImagesAtEpoch(epoch, info.osImageHash));
            assertTrue(kms.kmsAllowedAggregatedMrsAtEpoch(epoch, info.mrAggregated));
            assertTrue(kms.kmsAllowedDeviceIdsAtEpoch(epoch, info.deviceId));
        }
        assertTrue(authorize(info, true).authorized);
        assertTrue(kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized);
        assertTrue(authorize(info, false).authorized);

        kms.removeKmsAggregatedMrAtEpochs(0, 1, info.mrAggregated);
        assertFalse(authorize(info, true).authorized);
        assertFalse(kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized);
        kms.addKmsAggregatedMrAtEpochs(0, 1, info.mrAggregated);
        kms.removeKmsDeviceAtEpochs(0, 1, info.deviceId);
        assertFalse(authorize(info, true).authorized);
        assertFalse(kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized);
        kms.addKmsDeviceAtEpochs(0, 1, info.deviceId);

        vm.expectRevert(DstackKms.InvalidRootEpochRange.selector);
        kms.removeOsImageHashAtEpochs(1, 0, info.osImageHash);
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.removeOsImageHashAtEpochs(0, 2, info.osImageHash);
        vm.stopPrank();
    }

    function test_RangeRemovalRevokesOlderRootRows() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(0));
        vm.startPrank(owner);
        registerNextRootEpoch();
        kms.addOsImageHashAtEpochs(0, 0, info.osImageHash);
        info.appId = kms.deployAndRegisterApp(user, false, false, info.deviceId, info.composeHash);
        registerNextRootEpoch();
        activateNextRootEpoch();
        kms.addOsImageHashAtEpochs(1, 1, info.osImageHash);
        assertTrue(authorize(info, false).authorized);
        assertTrue(kms.authorizeApp(epochRequest(info, 0, 0)).authorized);

        kms.removeOsImageHashAtEpochs(0, 1, info.osImageHash);
        vm.stopPrank();
        assertFalse(authorize(info, false).authorized);
        for (uint256 epoch = 0; epoch < 2; ++epoch) {
            assertFalse(kms.allowedOsImagesAtEpoch(epoch, info.osImageHash));
            AuthorizationResult memory result = kms.authorizeApp(epochRequest(info, epoch, 0));
            assertEq(result.rejectionReason, "OS image is not allowed");
        }
    }

    function test_PopThenReRegisterIdenticalKeysStartsWithEmptyRows() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(kms));
        vm.startPrank(owner);
        registerNextRootEpoch();
        registerNextRootEpoch();
        approveKmsAtEpoch(info, 1);
        assertTrue(kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized);
        (,,, bytes32 popped) = kms.rootEpoch(1);

        kms.popRootEpoch(1, popped);
        assertFalse(kms.allowedOsImagesAtEpoch(1, info.osImageHash));
        vm.expectRevert(DstackKms.UnknownRootEpoch.selector);
        kms.removeOsImageHashAtEpochs(1, 1, info.osImageHash);

        registerNextRootEpoch();
        (,,, bytes32 again) = kms.rootEpoch(1);
        assertEq(again, popped);
        assertFalse(kms.allowedOsImagesAtEpoch(1, info.osImageHash));
        assertFalse(kms.kmsAllowedAggregatedMrsAtEpoch(1, info.mrAggregated));
        assertFalse(kms.kmsAllowedDeviceIdsAtEpoch(1, info.deviceId));
        assertFalse(kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized);
        vm.stopPrank();
    }

    function test_KmsServeIsLimitedToTheCurrentRootEpoch() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(kms));
        vm.startPrank(owner);
        registerNextRootEpoch();
        registerNextRootEpoch();
        approveKmsAtEpoch(info, 0);
        approveKmsAtEpoch(info, 1);
        vm.stopPrank();
        AuthorizationRequest memory request = kmsEpochRequest(info, 1, 0);
        assertTrue(kms.authorizeKms(request).authorized);
        request.operation = keccak256("kms_export_keys");
        assertTrue(kms.authorizeKms(request).authorized);
        request.operation = keccak256("kms_serve");
        assertEq(kms.authorizeKms(request).rejectionReason, "Requested root epoch is not active");
        request.requestedRootEpoch = OptionalUint256(true, 0);
        assertTrue(kms.authorizeKms(request).authorized);
        request.requestedRootEpoch = OptionalUint256(false, 0);
        assertTrue(kms.authorizeKms(request).authorized);
    }

    function test_AtEpochSettersChangeOnlyTheirRow() public {
        IAppAuth.AppInfo memory info = authorizationInfo(address(kms));
        vm.startPrank(owner);
        registerNextRootEpoch();
        registerNextRootEpoch();
        approveKmsAtEpoch(info, 1);
        assertFalse(kms.allowedOsImagesAtEpoch(0, info.osImageHash));
        assertFalse(kms.kmsAllowedAggregatedMrsAtEpoch(0, info.mrAggregated));
        assertFalse(kms.kmsAllowedDeviceIdsAtEpoch(0, info.deviceId));
        assertFalse(authorize(info, true).authorized);
        assertTrue(kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized);

        approveKmsAtEpoch(info, 0);
        kms.removeOsImageHashAtEpochs(1, 1, info.osImageHash);
        kms.removeKmsAggregatedMrAtEpochs(1, 1, info.mrAggregated);
        kms.removeKmsDeviceAtEpochs(1, 1, info.deviceId);
        assertTrue(kms.allowedOsImagesAtEpoch(0, info.osImageHash));
        assertTrue(kms.kmsAllowedAggregatedMrsAtEpoch(0, info.mrAggregated));
        assertTrue(kms.kmsAllowedDeviceIdsAtEpoch(0, info.deviceId));
        assertTrue(authorize(info, true).authorized);
        assertFalse(kms.authorizeKms(kmsEpochRequest(info, 1, 0)).authorized);
        vm.stopPrank();
    }
}
