/*
 * SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "openzeppelin-foundry-upgrades/Upgrades.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";

// The epoch-less setters of the released app policies.
interface ILegacyApp {
    function addComposeHash(bytes32 composeHash) external;
    function removeComposeHash(bytes32 composeHash) external;
    function setAllowAnyDevice(bool allowed) external;
}

/// An upgraded DstackKms with app policies still on the v0.5.9 and v0.6.0
/// implementations, which app owners upgrade on their own schedule.
contract LegacyAppCompatTest is Test {
    DstackKms kms;
    address owner = makeAddr("owner");
    address appOwner = makeAddr("appOwner");

    string[2] internal appReleases = ["DstackAppV059.sol:DstackApp", "DstackAppV060.sol:DstackApp"];

    bytes32 constant COMPOSE = bytes32(uint256(0xc0));
    bytes32 constant DEVICE = bytes32(uint256(0xd0));
    bytes32 constant IMAGE = bytes32(uint256(0x10));

    function setUp() public {
        vm.startPrank(owner);
        kms = DstackKms(
            Upgrades.deployUUPSProxy("DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(0))))
        );
        kms.registerRootEpoch(key(91, 0xa0), key(33, 0xb0), "ipfs://0");
        kms.addOsImageHashAtEpochs(0, 0, IMAGE);
        vm.stopPrank();
    }

    function key(uint256 length, uint8 fill) internal pure returns (bytes memory k) {
        k = new bytes(length);
        for (uint256 i; i < length; ++i) {
            k[i] = bytes1(fill);
        }
        if (length == 91) {
            bytes memory prefix = hex"3059301306072a8648ce3d020106082a8648ce3d03010703420004";
            for (uint256 i; i < prefix.length; ++i) {
                k[i] = prefix[i];
            }
        } else {
            k[0] = 0x02;
        }
    }

    function deployLegacyApp(uint256 release) internal returns (address app) {
        vm.prank(appOwner);
        app = Upgrades.deployUUPSProxy(
            appReleases[release],
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bytes32,bytes32)", appOwner, false, false, DEVICE, COMPOSE
            )
        );
        kms.registerApp(app);
    }

    function request(address app, bool appSet, uint256 appEpoch) internal pure returns (AuthorizationRequest memory) {
        IAppAuth.AppInfo memory info;
        info.appId = app;
        info.composeHash = COMPOSE;
        info.deviceId = DEVICE;
        info.osImageHash = IMAGE;
        info.tcbStatus = "UpToDate";
        info.advisoryIds = new string[](0);
        return AuthorizationRequest(
            info, keccak256("app_get_key"), OptionalUint256(appSet, appEpoch), OptionalUint256(false, 0), "dstack-tdx"
        );
    }

    function rotateRoot() internal {
        vm.startPrank(owner);
        kms.registerRootEpoch(key(91, 0xa1), key(33, 0xb1), "ipfs://1");
        kms.addOsImageHashAtEpochs(1, 1, IMAGE);
        (,,, bytes32 hash) = kms.rootEpoch(1);
        kms.activateRootEpoch(1, hash);
        vm.stopPrank();
    }

    function test_LegacyAppsAreAuthorizedAtAppEpochZeroAcrossRootRotation() public {
        for (uint256 release; release < appReleases.length; ++release) {
            address app = deployLegacyApp(release);
            assertEq(kms.currentAppEpoch(app), 0);
            assertTrue(kms.authorizeApp(request(app, false, 0)).authorized);
            assertTrue(kms.authorizeApp(request(app, true, 0)).authorized);
            AuthorizationResult memory result = kms.authorizeApp(request(app, true, 1));
            assertFalse(result.authorized);
            assertEq(result.rejectionReason, "Requested app epoch is not active");

            // Its epoch-less setters still decide app epoch 0.
            vm.prank(appOwner);
            ILegacyApp(app).removeComposeHash(COMPOSE);
            assertFalse(kms.authorizeApp(request(app, false, 0)).authorized);
            vm.prank(appOwner);
            ILegacyApp(app).addComposeHash(COMPOSE);
        }
        rotateRoot();
        for (uint256 release; release < appReleases.length; ++release) {
            address app = deployLegacyApp(release);
            assertEq(kms.currentAppEpoch(app), 0);
            AuthorizationResult memory result = kms.authorizeApp(request(app, false, 0));
            assertTrue(result.authorized, result.rejectionReason);
            assertEq(result.currentRootEpoch, 1);
            assertEq(result.currentAppEpoch, 0);
            assertFalse(kms.authorizeApp(request(app, true, 1)).authorized);
        }
    }

    function test_RestrictedKmsGatesLegacyAppsByTeeVariant() public {
        string[] memory tdx = new string[](1);
        tdx[0] = "dstack-tdx";
        vm.startPrank(owner);
        kms.setAllowedTeeVariants(tdx);
        kms.setAllowAnyTeeVariant(false);
        vm.stopPrank();
        for (uint256 release; release < appReleases.length; ++release) {
            address app = deployLegacyApp(release);
            assertTrue(kms.authorizeApp(request(app, false, 0)).authorized);
            AuthorizationRequest memory snp = request(app, false, 0);
            snp.teeVariant = "dstack-amd-sev-snp";
            assertEq(kms.authorizeApp(snp).rejectionReason, "TEE variant not allowed");
        }
    }

    function test_InterfaceIdsTellLegacyAndEpochAppsApart() public {
        bytes4 basicManagement = 0x8fd37527;
        for (uint256 release; release < appReleases.length; ++release) {
            address app = deployLegacyApp(release);
            assertTrue(IERC165(app).supportsInterface(basicManagement));
            assertFalse(IERC165(app).supportsInterface(type(IAppEpochManagement).interfaceId));
            assertFalse(IERC165(app).supportsInterface(type(IAppEpochAuth).interfaceId));
        }
        DstackApp current = DstackApp(
            Upgrades.deployUUPSProxy(
                "DstackApp.sol",
                abi.encodeWithSignature(
                    "initialize(address,bool,bool,bytes32,bytes32)", appOwner, false, false, DEVICE, COMPOSE
                )
            )
        );
        assertFalse(current.supportsInterface(basicManagement));
        assertTrue(current.supportsInterface(type(IAppEpochManagement).interfaceId));
        assertTrue(current.supportsInterface(type(IAppEpochAuth).interfaceId));
    }

    function test_UpgradedV059AppKeepsItsPolicyAtAppEpochZero() public {
        checkUpgradeKeepsPolicy(0, false);
    }

    function test_UpgradedV059AnyDeviceAppKeepsItsPolicyAtAppEpochZero() public {
        checkUpgradeKeepsPolicy(0, true);
    }

    function test_UpgradedV060AppKeepsItsPolicyAtAppEpochZero() public {
        checkUpgradeKeepsPolicy(1, false);
    }

    function test_UpgradedV060AnyDeviceAppKeepsItsPolicyAtAppEpochZero() public {
        checkUpgradeKeepsPolicy(1, true);
    }

    function checkUpgradeKeepsPolicy(uint256 release, bool anyDevice) internal {
        address app = deployLegacyApp(release);
        if (anyDevice) {
            vm.prank(appOwner);
            ILegacyApp(app).setAllowAnyDevice(true);
        }
        Options memory opts;
        opts.referenceContract = appReleases[release];
        vm.startPrank(appOwner);
        Upgrades.upgradeProxy(app, "DstackApp.sol", "", opts);
        vm.stopPrank();

        DstackApp upgraded = DstackApp(app);
        assertEq(upgraded.currentAppEpoch(), 0);
        assertTrue(upgraded.allowedComposeHashesAtEpoch(0, COMPOSE));
        assertTrue(upgraded.allowedDeviceIdsAtEpoch(0, DEVICE));
        assertEq(upgraded.allowAnyDevice(), anyDevice);
        // Upgraded policies allow any TEE platform.
        assertTrue(upgraded.allowAnyTeeVariant());
        assertEq(upgraded.allowedTeeVariants().length, 0);
        AuthorizationRequest memory snp = request(app, true, 0);
        snp.teeVariant = "dstack-amd-sev-snp";
        assertTrue(kms.authorizeApp(snp).authorized);
        assertFalse(upgraded.allowedComposeHashesAtEpoch(1, COMPOSE));
        assertTrue(kms.authorizeApp(request(app, true, 0)).authorized);

        // The epoch-less setters are gone; the rows are written by epoch.
        vm.prank(appOwner);
        vm.expectRevert();
        ILegacyApp(app).addComposeHash(bytes32(uint256(0xc1)));
        // The upgraded allowAnyDevice covers later epochs too: row 1 lists no device.
        vm.startPrank(appOwner);
        upgraded.advanceAppEpoch(0);
        upgraded.addComposeHashAtEpoch(1, COMPOSE);
        vm.stopPrank();
        assertEq(kms.authorizeApp(request(app, true, 1)).authorized, anyDevice);

        vm.prank(appOwner);
        upgraded.removeComposeHashAtEpochs(0, 1, COMPOSE);
        assertFalse(kms.authorizeApp(request(app, true, 0)).authorized);
    }
}
