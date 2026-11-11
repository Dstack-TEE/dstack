/*
 * SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/AuthorizationOperation.sol";
import "../contracts/DstackApp.sol";
import "../contracts/DstackKms.sol";

function _appAuth(
    DstackApp target,
    IAppAuth.AppInfo memory info,
    uint256 epoch,
    bytes32 operation
)
    view
    returns (bool, string memory)
{
    AuthorizationResult memory result = target.authorizeApp(
        AuthorizationRequest(info, operation, OptionalUint256(true, epoch), OptionalUint256(false, 0))
    );
    return (result.authorized, result.rejectionReason);
}

/// @notice Halmos symbolic tests for DstackKms root epochs and epoch-scoped
/// authorization.
///
/// setUp registers root epochs 0, 1 and 2, activates 1 (so 2 is pending),
/// admits one KMS identity and OS image per epoch, and deploys an app at app
/// epoch 1. Halmos has no symbolic storage, so the properties are proved from
/// this state, after one symbolic call where noted.
///
/// Run with `halmos --contract DstackKmsEpochSymbolicTest`.
contract DstackKmsEpochSymbolicTest is Test {
    DstackKms internal kms;
    DstackApp internal app;
    address internal constant OWNER = address(0xA11CE);
    bytes27 internal constant P256_SPKI_PREFIX = 0x3059301306072a8648ce3d020106082a8648ce3d03010703420004;
    uint256 internal constant KMS_POLICY_SETTERS = 12;

    /// The AppInfo fields DstackKms and DstackApp read; the app ID is the
    /// deployed app and the remaining fields stay zero.
    struct Identity {
        bytes32 osImageHash;
        bytes32 mrAggregated;
        bytes32 deviceId;
        bytes32 composeHash;
        bool upToDate;
    }

    function setUp() public {
        DstackKms impl = new DstackKms();
        bytes memory initData = abi.encodeCall(DstackKms.initialize, (OWNER, address(new DstackApp())));
        kms = DstackKms(address(new ERC1967Proxy(address(impl), initData)));

        vm.startPrank(OWNER);
        for (uint256 epoch = 0; epoch < 3; epoch++) {
            kms.registerRootEpoch(_ca(bytes32(epoch + 1), bytes32(0)), _k256(true, bytes32(epoch + 1)), "evidence");
            kms.addOsImageHashAtEpoch(epoch, _id(0x05, epoch));
            kms.addKmsAggregatedMrAtEpoch(epoch, _id(0x0a, epoch));
            kms.addKmsDeviceAtEpoch(epoch, _id(0x0d, epoch));
        }
        (, bytes32 hash1) = _entry(1);
        kms.activateRootEpoch(1, hash1);

        app = DstackApp(kms.deployAndRegisterApp(OWNER, false, false, true, bytes32(0), _id(0xc0, 0)));
        app.advanceAppEpoch(0);
        app.addComposeHash(_id(0xc0, 1));
        app.setAllowAnyDevice(true);
        vm.stopPrank();
    }

    function _id(uint256 kind, uint256 epoch) internal pure returns (bytes32) {
        return bytes32((kind << 8) | epoch);
    }

    function _ca(bytes32 x, bytes32 y) internal pure returns (bytes memory) {
        return abi.encodePacked(P256_SPKI_PREFIX, x, y);
    }

    function _k256(bool even, bytes32 x) internal pure returns (bytes memory) {
        return abi.encodePacked(even ? bytes1(0x02) : bytes1(0x03), x);
    }

    function _current() internal view returns (uint256 epoch) {
        (epoch,) = kms.currentRootEpoch();
    }

    /// Hash of an epoch's keys, and its chain hash.
    function _entry(uint256 epoch) internal view returns (bytes32 keys, bytes32 chainHash) {
        (bytes memory ca, bytes memory k256,, bytes32 hash) = kms.rootEpoch(epoch);
        return (keccak256(abi.encode(ca, k256)), hash);
    }

    function _info(Identity memory id) internal view returns (IAppAuth.AppInfo memory info) {
        info.appId = address(app);
        info.osImageHash = id.osImageHash;
        info.mrAggregated = id.mrAggregated;
        info.deviceId = id.deviceId;
        info.composeHash = id.composeHash;
        info.tcbStatus = id.upToDate ? "UpToDate" : "OutOfDate";
    }

    function _request(
        IAppAuth.AppInfo memory info,
        bytes32 operation,
        bool rootSet,
        uint256 root,
        bool appSet,
        uint256 appEpoch
    )
        internal
        pure
        returns (AuthorizationRequest memory)
    {
        return AuthorizationRequest(info, operation, OptionalUint256(appSet, appEpoch), OptionalUint256(rootSet, root));
    }

    /// Calldata of one KMS policy setter writing the row of `epoch` and, for the
    /// range setters, every later registered row.
    function _kmsPolicyCall(uint256 which, uint256 epoch, bytes32 word) internal view returns (bytes memory data) {
        uint256 latest = kms.rootEpochCount() - 1;
        if (which == 0) data = abi.encodeCall(DstackKms.addKmsAggregatedMrAtEpoch, (epoch, word));
        else if (which == 1) data = abi.encodeCall(DstackKms.removeKmsAggregatedMrAtEpoch, (epoch, word));
        else if (which == 2) data = abi.encodeCall(DstackKms.addKmsDeviceAtEpoch, (epoch, word));
        else if (which == 3) data = abi.encodeCall(DstackKms.removeKmsDeviceAtEpoch, (epoch, word));
        else if (which == 4) data = abi.encodeCall(DstackKms.addOsImageHashAtEpoch, (epoch, word));
        else if (which == 5) data = abi.encodeCall(DstackKms.removeOsImageHashAtEpoch, (epoch, word));
        else if (which == 6) data = abi.encodeCall(DstackKms.addKmsAggregatedMrAtEpochs, (epoch, latest, word));
        else if (which == 7) data = abi.encodeCall(DstackKms.removeKmsAggregatedMrAtEpochs, (epoch, latest, word));
        else if (which == 8) data = abi.encodeCall(DstackKms.addKmsDeviceAtEpochs, (epoch, latest, word));
        else if (which == 9) data = abi.encodeCall(DstackKms.removeKmsDeviceAtEpochs, (epoch, latest, word));
        else if (which == 10) data = abi.encodeCall(DstackKms.addOsImageHashAtEpochs, (epoch, latest, word));
        else data = abi.encodeCall(DstackKms.removeOsImageHashAtEpochs, (epoch, latest, word));
    }

    // ---------------------------------------------------------------
    // Root registry step invariant. After any single call to any
    // enumerated mutating function, by any caller with symbolic args:
    // - the current epoch stays registered and only the owner's
    //   activation of the next epoch, naming its chain hash, moves it,
    //   by one;
    // - the registry changes by at most one entry at its end, and only
    //   the owner's pop of a pending epoch, naming its chain hash,
    //   removes one;
    // - existing entries keep their keys and chain hashes;
    // - every chain hash commits to its keys and the previous hash;
    // - kmsInfo holds the current epoch's keys and no legacy evidence.
    // ---------------------------------------------------------------

    /// Calldata of any enumerated mutating function.
    function _anyCall(
        uint256 which,
        uint256 epoch,
        bytes32 word,
        bytes32 hash,
        bool flag,
        address addr
    )
        internal
        view
        returns (bytes memory data)
    {
        if (which < KMS_POLICY_SETTERS) {
            data = _kmsPolicyCall(which, epoch, word);
        } else if (which == 12) {
            data = abi.encodeCall(DstackKms.registerRootEpoch, (_ca(word, hash), _k256(flag, word), "url"));
        } else if (which == 13) {
            data = abi.encodeCall(DstackKms.activateRootEpoch, (epoch, hash));
        } else if (which == 14) {
            data = abi.encodeCall(DstackKms.popRootEpoch, (epoch, hash));
        } else if (which == 15) {
            data = abi.encodeCall(DstackKms.setRootEpochEvidenceUrl, (epoch, "url"));
        } else if (which == 16) {
            data = abi.encodeCall(DstackKms.setGatewayAppId, ("gateway"));
        } else if (which == 17) {
            data = abi.encodeCall(DstackKms.setAppImplementation, (addr));
        } else if (which == 18) {
            data = abi.encodeCall(DstackKms.registerApp, (addr));
        } else if (which == 19) {
            data = abi.encodeWithSignature(
                "deployAndRegisterApp(address,bool,bool,bool,bytes32,bytes32)", addr, flag, flag, flag, word, hash
            );
        } else if (which == 20) {
            data = abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (addr, ""));
        } else if (which == 21) {
            data = abi.encodeCall(Ownable2StepUpgradeable.transferOwnership, (addr));
        } else if (which == 22) {
            data = abi.encodeCall(OwnableUpgradeable.renounceOwnership, ());
        }
    }

    function _snapshot() internal view returns (bytes32[] memory entries, bytes32[] memory hashes) {
        uint256 count = kms.rootEpochCount();
        entries = new bytes32[](count);
        hashes = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            (entries[i], hashes[i]) = _entry(i);
        }
    }

    /// Every chain hash commits to its keys and the previous hash, entries
    /// that existed before keep their keys and hashes, and kmsInfo holds
    /// the current keys without legacy evidence.
    function _assertRegistryConsistent(bytes32[] memory entries, bytes32[] memory hashes) internal view {
        bytes32 previous;
        for (uint256 i = 0; i < kms.rootEpochCount(); i++) {
            (bytes memory ca, bytes memory k256,, bytes32 chainHash) = kms.rootEpoch(i);
            assert(chainHash == keccak256(abi.encodePacked(previous, keccak256(ca), keccak256(k256))));
            if (i < entries.length) assert(keccak256(abi.encode(ca, k256)) == entries[i] && chainHash == hashes[i]);
            previous = chainHash;
        }
        (bytes memory infoK256, bytes memory infoCa, bytes memory quote, bytes memory eventlog) = kms.kmsInfo();
        (bytes memory currentCa, bytes memory currentK256,,) = kms.rootEpoch(_current());
        assert(keccak256(infoCa) == keccak256(currentCa) && keccak256(infoK256) == keccak256(currentK256));
        assert(quote.length == 0 && eventlog.length == 0);
    }

    /// @custom:halmos --loop 4
    function check_RootRegistry_StepInvariant(
        address caller,
        uint256 which,
        uint256 epoch,
        bytes32 word,
        bytes32 hash,
        bool flag,
        address addr
    )
        external
    {
        vm.assume(which <= 22);
        // Registry functions index the root epoch array, which Halmos cannot
        // do symbolically. Only epochs 0-2 exist, so every larger index
        // behaves as 3; branching makes each case concrete.
        if (which >= 13 && which <= 15) epoch = epoch == 0 ? 0 : epoch == 1 ? 1 : epoch == 2 ? 2 : 3;
        uint256 currentBefore = _current();
        (bytes32[] memory entries, bytes32[] memory hashes) = _snapshot();

        vm.prank(caller);
        (bool ok,) = address(kms).call(_anyCall(which, epoch, word, hash, flag, addr));
        ok;

        uint256 count = kms.rootEpochCount();
        uint256 current = _current();
        assert(current < count);
        if (current != currentBefore) {
            assert(current == currentBefore + 1);
            assert(caller == OWNER && which == 13 && epoch == current && hash == hashes[current]);
        }
        assert(count + 1 >= entries.length && count <= entries.length + 1);
        if (count < entries.length) {
            assert(caller == OWNER && which == 14 && epoch == count && epoch > currentBefore && hash == hashes[count]);
        }
        if (count > entries.length) assert(caller == OWNER && which == 12);
        _assertRegistryConsistent(entries, hashes);
    }

    /// Drop the last byte, keep the bytes, or append a zero byte.
    function _resize(bytes memory data, int8 change) internal pure returns (bytes memory) {
        if (change < 0) {
            assembly {
                mstore(data, sub(mload(data), 1))
            }
            return data;
        }
        return change == 0 ? data : abi.encodePacked(data, bytes1(0));
    }

    // ---------------------------------------------------------------
    // registerRootEpoch accepts exactly the encodings the KMS
    // produces: a 91-byte uncompressed P-256 SubjectPublicKeyInfo and
    // a 33-byte compressed secp256k1 key.
    // ---------------------------------------------------------------

    function check_RegisterRootEpoch_AcceptsOnlyCanonicalEncodings(
        bytes27 prefix,
        bytes32 x,
        bytes1 tag,
        int8 caLength,
        int8 k256Length
    )
        external
    {
        bytes memory ca = _resize(abi.encodePacked(prefix, x, x), caLength);
        bytes memory k256 = _resize(abi.encodePacked(tag, x), k256Length);

        vm.prank(OWNER);
        (bool ok,) = address(kms).call(abi.encodeCall(DstackKms.registerRootEpoch, (ca, k256, "url")));

        bool canonical = ca.length == 91 && prefix == P256_SPKI_PREFIX && k256.length == 33
            && (tag == bytes1(0x02) || tag == bytes1(0x03));
        assert(ok == canonical);
    }

    // ---------------------------------------------------------------
    // Authorization bounds: an operation of the wrong kind, an app
    // root epoch above the current one, a KMS root epoch above the
    // latest registered one, or an app epoch above the app's current
    // one is never authorized. Every result reports the current root
    // epoch and its chain hash.
    // ---------------------------------------------------------------

    function check_Authorize_EnforcesEpochBounds(
        bool isKms,
        bytes32 operation,
        bool rootSet,
        uint256 root,
        bool appSet,
        uint256 appEpoch,
        Identity calldata id
    )
        external
        view
    {
        AuthorizationRequest memory request = _request(_info(id), operation, rootSet, root, appSet, appEpoch);
        AuthorizationResult memory result = isKms ? kms.authorizeKms(request) : kms.authorizeApp(request);

        (uint256 current, bytes32 currentHash) = kms.currentRootEpoch();
        assert(result.currentRootEpoch == current && result.currentRootEpochHash == currentHash);

        bool kindMatches = isKms ? AuthorizationOperation.isKms(operation) : AuthorizationOperation.isApp(operation);
        bool issuesKeys = !isKms || operation == AuthorizationOperation.KMS_SERVE;
        uint256 rootBound = issuesKeys ? current : kms.rootEpochCount() - 1;
        uint256 appBound = isKms ? 0 : app.currentAppEpoch();
        if (!kindMatches || (rootSet && root > rootBound) || (appSet && appEpoch > appBound)) {
            assert(!result.authorized);
        }
    }

    // ---------------------------------------------------------------
    // Before any root epoch is registered, only KMS bootstrap can be
    // authorized.
    // ---------------------------------------------------------------

    function check_Authorize_OnlyBootstrapBeforeRegistration(
        bool isKms,
        bytes32 operation,
        Identity calldata id
    )
        external
    {
        DstackKms impl = new DstackKms();
        bytes memory initData = abi.encodeCall(DstackKms.initialize, (OWNER, address(new DstackApp())));
        DstackKms fresh = DstackKms(address(new ERC1967Proxy(address(impl), initData)));
        vm.startPrank(OWNER);
        fresh.addOsImageHashAtEpoch(0, id.osImageHash);
        fresh.addKmsAggregatedMrAtEpoch(0, id.mrAggregated);
        fresh.addKmsDeviceAtEpoch(0, id.deviceId);
        vm.stopPrank();

        AuthorizationRequest memory request = _request(_info(id), operation, false, 0, false, 0);
        AuthorizationResult memory result = isKms ? fresh.authorizeKms(request) : fresh.authorizeApp(request);
        if (result.authorized) assert(isKms && operation == AuthorizationOperation.KMS_BOOTSTRAP);
    }

    // ---------------------------------------------------------------
    // KMS authorization matches the policy of the selected root epoch
    // (requested, or current when unset), after any one owner write.
    // ---------------------------------------------------------------

    function check_AuthorizeKms_MatchesEpochPolicy(
        uint256 which,
        uint256 writeEpoch,
        bytes32 word,
        bytes32 operation,
        bool rootSet,
        uint256 root,
        Identity calldata id
    )
        external
    {
        if (which < KMS_POLICY_SETTERS) {
            bytes memory data = _kmsPolicyCall(which, writeEpoch, word);
            vm.prank(OWNER);
            (bool ok,) = address(kms).call(data);
            ok;
        }

        AuthorizationResult memory result = kms.authorizeKms(_request(_info(id), operation, rootSet, root, false, 0));

        uint256 epoch = rootSet ? root : _current();
        uint256 bound = operation == AuthorizationOperation.KMS_SERVE ? _current() : kms.rootEpochCount() - 1;
        bool expected = AuthorizationOperation.isKms(operation) && epoch <= bound && id.upToDate
            && kms.allowedOsImagesAtEpoch(epoch, id.osImageHash)
            && kms.kmsAllowedAggregatedMrsAtEpoch(epoch, id.mrAggregated)
            && kms.kmsAllowedDeviceIdsAtEpoch(epoch, id.deviceId);
        assert(result.authorized == expected);
    }

    // ---------------------------------------------------------------
    // App authorization admits exactly a registered app whose OS image
    // the selected root epoch allows and whose own policy admits it at
    // the selected app epoch.
    // ---------------------------------------------------------------

    function check_AuthorizeApp_MatchesKmsAndAppPolicy(
        bool getCert,
        bool rootSet,
        uint256 root,
        bool appSet,
        uint256 appEpoch,
        Identity calldata id
    )
        external
        view
    {
        bytes32 operation = getCert ? AuthorizationOperation.APP_GET_CERT : AuthorizationOperation.APP_GET_KEY;
        IAppAuth.AppInfo memory info = _info(id);
        AuthorizationResult memory result = kms.authorizeApp(_request(info, operation, rootSet, root, appSet, appEpoch));

        uint256 rootEpoch = rootSet ? root : _current();
        uint256 selectedAppEpoch = appSet ? appEpoch : app.currentAppEpoch();
        bool expected = rootEpoch <= _current() && selectedAppEpoch <= app.currentAppEpoch()
            && kms.allowedOsImagesAtEpoch(rootEpoch, id.osImageHash);
        if (expected) (expected,) = _appAuth(app, info, selectedAppEpoch, operation);
        assert(result.authorized == expected);
    }

    // ---------------------------------------------------------------
    // Epoch isolation: a KMS policy write at one root epoch never
    // changes a KMS authorization decision at another.
    // ---------------------------------------------------------------

    function check_KmsPolicyWrite_PreservesOtherEpochDecisions(
        uint256 which,
        uint256 writeEpoch,
        bytes32 word,
        bytes32 operation,
        uint256 root,
        Identity calldata id
    )
        external
    {
        vm.assume(which < KMS_POLICY_SETTERS);
        bytes memory data = _kmsPolicyCall(which, writeEpoch, word);
        vm.assume(which < 6 ? writeEpoch != root : root < writeEpoch);

        AuthorizationRequest memory request = _request(_info(id), operation, true, root, false, 0);
        AuthorizationResult memory before = kms.authorizeKms(request);
        vm.prank(OWNER);
        (bool ok,) = address(kms).call(data);
        ok;
        AuthorizationResult memory afterWrite = kms.authorizeKms(request);

        assert(before.authorized == afterWrite.authorized);
        assert(keccak256(bytes(before.rejectionReason)) == keccak256(bytes(afterWrite.rejectionReason)));
    }

    // ---------------------------------------------------------------
    // Legacy entry points serve KMS binaries that only hold root epoch 0:
    // before any rotation isKmsAllowed decides as KMS_SERVE at epoch 0,
    // and once a later epoch is current both refuse. isAppAllowed never
    // authorizes an app whose policy has left app epoch 0.
    // ---------------------------------------------------------------

    function check_LegacyEntryPoints_RefuseOnceRotated(Identity calldata id) external view {
        IAppAuth.AppInfo memory info = _info(id);
        bytes32 rotated = keccak256("Root epoch requires epoch-aware authorization");
        (bool kmsAllowed, string memory kmsReason) = kms.isKmsAllowed(info);
        assert(!kmsAllowed && keccak256(bytes(kmsReason)) == rotated);
        (bool appAllowed, string memory appReason) = kms.isAppAllowed(info);
        assert(!appAllowed && keccak256(bytes(appReason)) == rotated);
    }

    function check_LegacyKmsCheck_ReadsEpochZeroBeforeRotation(Identity calldata id) external {
        bytes memory initData = abi.encodeCall(DstackKms.initialize, (OWNER, address(new DstackApp())));
        kms = DstackKms(address(new ERC1967Proxy(address(new DstackKms()), initData)));
        vm.startPrank(OWNER);
        for (uint256 epoch = 0; epoch < 2; epoch++) {
            kms.registerRootEpoch(_ca(bytes32(epoch + 1), bytes32(0)), _k256(true, bytes32(epoch + 1)), "evidence");
            kms.addOsImageHashAtEpoch(epoch, _id(0x05, epoch));
            kms.addKmsAggregatedMrAtEpoch(epoch, _id(0x0a, epoch));
            kms.addKmsDeviceAtEpoch(epoch, _id(0x0d, epoch));
        }
        vm.stopPrank();
        // Epoch 1 is registered and prepared but pending.
        IAppAuth.AppInfo memory info = _info(id);
        (bool kmsAllowed,) = kms.isKmsAllowed(info);
        AuthorizationResult memory serve =
            kms.authorizeKms(_request(info, AuthorizationOperation.KMS_SERVE, true, 0, false, 0));
        assert(kmsAllowed == serve.authorized);
    }
}
