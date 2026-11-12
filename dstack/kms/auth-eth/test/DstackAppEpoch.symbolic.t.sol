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

/// @notice Halmos symbolic tests for DstackApp app epochs.
///
/// Halmos has no symbolic storage, so tests that quantify over policy states
/// first apply one symbolic owner write on top of setUp's concrete state.
/// DstackApp reads only the compose hash, device ID and TCB status of an
/// AppInfo, so those are the symbolic inputs; the remaining fields stay zero.
///
/// Run with `halmos --contract DstackAppEpochSymbolicTest`.
/// @custom:halmos --loop 5
contract DstackAppEpochSymbolicTest is Test {
    DstackApp internal app;
    address internal constant OWNER = address(0xA11CE);
    uint256 internal constant POLICY_SETTERS = 8;

    function setUp() public {
        DstackApp impl = new DstackApp();
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,bool,bool,bytes32,bytes32)", OWNER, false, false, bytes32(0), bytes32(0)
        );
        app = DstackApp(address(new ERC1967Proxy(address(impl), initData)));
        // Epoch 0 keeps the legacy storage fields; epochs 1 and 2 use the
        // per-epoch maps. Each epoch admits some app so that decisions can be
        // allowed as well as denied.
        vm.startPrank(OWNER);
        app.addComposeHashAtEpoch(0, bytes32(uint256(0xc0)));
        app.addDeviceAtEpoch(0, bytes32(uint256(0xd0)));
        app.advanceAppEpoch(0);
        app.addComposeHashAtEpoch(1, bytes32(uint256(0xc1)));
        app.addDeviceAtEpoch(1, bytes32(uint256(0xd1)));
        app.advanceAppEpoch(1);
        app.addComposeHashAtEpoch(2, bytes32(uint256(0xc2)));
        app.addDeviceAtEpoch(2, bytes32(uint256(0xd2)));
        vm.stopPrank();
    }

    /// Calldata of one epoch-scoped policy setter: 0-3 write the row of `epoch`,
    /// 4-7 are their range forms, writing every row from `epoch` through the next one.
    function _policyCall(uint256 which, uint256 epoch, bytes32 word) internal view returns (bytes memory) {
        return _rangePolicyCall(which, epoch, app.currentAppEpoch() + 1, word);
    }

    /// As _policyCall, with the range setters writing `epoch` through `next`.
    function _rangePolicyCall(
        uint256 which,
        uint256 epoch,
        uint256 next,
        bytes32 word
    )
        internal
        pure
        returns (bytes memory data)
    {
        if (which == 0) data = abi.encodeCall(DstackApp.addComposeHashAtEpoch, (epoch, word));
        else if (which == 1) data = abi.encodeCall(DstackApp.removeComposeHashAtEpoch, (epoch, word));
        else if (which == 2) data = abi.encodeCall(DstackApp.addDeviceAtEpoch, (epoch, word));
        else if (which == 3) data = abi.encodeCall(DstackApp.removeDeviceAtEpoch, (epoch, word));
        else if (which == 4) data = abi.encodeCall(DstackApp.addComposeHashAtEpochs, (epoch, next, word));
        else if (which == 5) data = abi.encodeCall(DstackApp.removeComposeHashAtEpochs, (epoch, next, word));
        else if (which == 6) data = abi.encodeCall(DstackApp.addDeviceAtEpochs, (epoch, next, word));
        else data = abi.encodeCall(DstackApp.removeDeviceAtEpochs, (epoch, next, word));
    }

    function _ownerPolicyWrite(uint256 which, uint256 epoch, bytes32 word) internal {
        if (which >= POLICY_SETTERS) return;
        bytes memory data = _policyCall(which, epoch, word);
        vm.prank(OWNER);
        (bool ok,) = address(app).call(data);
        ok; // a reverted write leaves the setUp state, which is also a valid pre-state
    }

    function _info(
        bytes32 composeHash,
        bytes32 deviceId,
        bool upToDate
    )
        internal
        pure
        returns (IAppAuth.AppInfo memory info)
    {
        info.composeHash = composeHash;
        info.deviceId = deviceId;
        info.tcbStatus = upToDate ? "UpToDate" : "OutOfDate";
    }

    function _decision(IAppAuth.AppInfo memory info, uint256 epoch) internal view returns (bool, bytes32) {
        (bool allowed, string memory reason) = _appAuth(app, info, epoch, AuthorizationOperation.APP_GET_KEY);
        return (allowed, keccak256(bytes(reason)));
    }

    // ---------------------------------------------------------------
    // The app epoch never decreases, and only the owner's
    // advanceAppEpoch(current) moves it, by exactly one.
    // ---------------------------------------------------------------

    function check_AppEpoch_StepMonotonic(
        address caller,
        uint256 which,
        uint256 epoch,
        bytes32 word,
        bool flag,
        address addr
    )
        external
    {
        uint256 before = app.currentAppEpoch();

        bytes memory data;
        if (which < POLICY_SETTERS) data = _policyCall(which, epoch, word);
        else if (which == 8) data = abi.encodeCall(DstackApp.setAllowAnyDevice, (flag));
        else if (which == 9) data = abi.encodeCall(DstackApp.advanceAppEpoch, (epoch));
        else if (which == 10) data = abi.encodeCall(DstackApp.setRequireTcbUpToDate, (flag));
        else if (which == 11) data = abi.encodeCall(DstackApp.disableUpgrades, ());
        else if (which == 12) data = abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (addr, ""));
        else if (which == 13) data = abi.encodeCall(Ownable2StepUpgradeable.transferOwnership, (addr));
        else if (which == 14) data = abi.encodeCall(Ownable2StepUpgradeable.acceptOwnership, ());
        else if (which == 15) data = abi.encodeCall(OwnableUpgradeable.renounceOwnership, ());
        else return;

        vm.prank(caller);
        (bool ok,) = address(app).call(data);
        ok;

        uint256 afterEpoch = app.currentAppEpoch();
        if (afterEpoch != before) {
            assert(afterEpoch == before + 1);
            assert(caller == OWNER && which == 9 && epoch == before);
        }
    }

    // ---------------------------------------------------------------
    // No caller can write policy for an epoch that is not active yet.
    // ---------------------------------------------------------------

    function check_PolicyWrite_RejectsEpochPastNext(
        address caller,
        uint256 which,
        uint256 epoch,
        uint256 to,
        bytes32 word
    )
        external
    {
        vm.assume(which < POLICY_SETTERS && (which < 4 ? epoch : to) > app.currentAppEpoch() + 1);
        bytes memory data = _rangePolicyCall(which, epoch, to, word);
        vm.prank(caller);
        (bool ok,) = address(app).call(data);
        assert(!ok);
    }

    // ---------------------------------------------------------------
    // An epoch that is not active is never authorized, and only app
    // operations are authorized.
    // ---------------------------------------------------------------

    function check_AuthorizeApp_RejectsInactiveEpochAndForeignOperation(
        uint256 which,
        uint256 writeEpoch,
        bytes32 word,
        bytes32 composeHash,
        bytes32 deviceId,
        bool upToDate,
        uint256 epoch,
        bytes32 operation
    )
        external
    {
        _ownerPolicyWrite(which, writeEpoch, word);
        IAppAuth.AppInfo memory info = _info(composeHash, deviceId, upToDate);
        vm.assume(epoch > app.currentAppEpoch() || !AuthorizationOperation.isApp(operation));
        (bool allowed,) = _appAuth(app, info, epoch, operation);
        assert(!allowed);
    }

    // ---------------------------------------------------------------
    // The legacy IAppAuth entry point decides exactly as the
    // epoch-aware one at the current epoch, never an older policy.
    // ---------------------------------------------------------------

    function check_IsAppAllowed_RefusesAtNonzeroEpoch(
        uint256 which,
        uint256 writeEpoch,
        bytes32 word,
        bytes32 composeHash,
        bytes32 deviceId,
        bool upToDate
    )
        external
    {
        _ownerPolicyWrite(which, writeEpoch, word);
        (bool allowed, string memory reason) = app.isAppAllowed(_info(composeHash, deviceId, upToDate));
        assert(!allowed);
        assert(keccak256(bytes(reason)) == keccak256("App epoch requires epoch-aware authorization"));
    }

    function check_IsAppAllowed_EqualsEpochZeroDecisionBeforeAdvance(
        uint256 which,
        uint256 writeEpoch,
        bytes32 word,
        bytes32 composeHash,
        bytes32 deviceId,
        bool upToDate
    )
        external
    {
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,bool,bool,bytes32,bytes32)", OWNER, false, false, bytes32(0), bytes32(0)
        );
        app = DstackApp(address(new ERC1967Proxy(address(new DstackApp()), initData)));
        vm.startPrank(OWNER);
        app.addComposeHashAtEpoch(0, bytes32(uint256(0xc0)));
        app.addDeviceAtEpoch(0, bytes32(uint256(0xd0)));
        // A prepared next row must not leak into the legacy decision.
        app.addComposeHashAtEpoch(1, bytes32(uint256(0xc1)));
        app.addDeviceAtEpoch(1, bytes32(uint256(0xd1)));
        vm.stopPrank();
        _ownerPolicyWrite(which, writeEpoch, word);
        IAppAuth.AppInfo memory info = _info(composeHash, deviceId, upToDate);
        (bool allowed, string memory reason) = app.isAppAllowed(info);
        (bool expected, bytes32 expectedReason) = _decision(info, 0);
        assert(allowed == expected && keccak256(bytes(reason)) == expectedReason);
    }

    // ---------------------------------------------------------------
    // Epoch isolation: a policy write never changes an authorization decision
    // at an epoch it did not write, including epoch 0's legacy fields.
    // ---------------------------------------------------------------

    function check_PolicyWrite_PreservesOtherEpochDecisions(
        uint256 which,
        uint256 writeEpoch,
        uint256 writeTo,
        bytes32 word,
        bytes32 composeHash,
        bytes32 deviceId,
        bool upToDate,
        uint256 epoch
    )
        external
    {
        vm.assume(which < POLICY_SETTERS);
        vm.assume(which < 4 ? writeEpoch != epoch : epoch < writeEpoch || epoch > writeTo);
        bytes memory data = _rangePolicyCall(which, writeEpoch, writeTo, word);

        IAppAuth.AppInfo memory info = _info(composeHash, deviceId, upToDate);
        (bool allowedBefore, bytes32 reasonBefore) = _decision(info, epoch);
        vm.prank(OWNER);
        (bool ok,) = address(app).call(data);
        ok;
        (bool allowedAfter, bytes32 reasonAfter) = _decision(info, epoch);

        assert(allowedBefore == allowedAfter && reasonBefore == reasonAfter);
    }

    function check_AuthorizeApp_MatchesPolicy(
        uint256 which,
        uint256 writeEpoch,
        bytes32 word,
        bool anyDevice,
        bool tcbFlag,
        bytes32 composeHash,
        bytes32 deviceId,
        bool upToDate,
        uint256 epoch,
        bool getCert
    )
        external
    {
        vm.startPrank(OWNER);
        app.setRequireTcbUpToDate(tcbFlag);
        app.setAllowAnyDevice(anyDevice);
        vm.stopPrank();
        _ownerPolicyWrite(which, writeEpoch, word);
        IAppAuth.AppInfo memory info = _info(composeHash, deviceId, upToDate);
        bytes32 op = getCert ? AuthorizationOperation.APP_GET_CERT : AuthorizationOperation.APP_GET_KEY;
        (bool allowed,) = _appAuth(app, info, epoch, op);
        bool expected = epoch <= app.currentAppEpoch() && (!tcbFlag || upToDate)
            && app.allowedComposeHashesAtEpoch(epoch, composeHash)
            && (anyDevice || app.allowedDeviceIdsAtEpoch(epoch, deviceId));
        assert(allowed == expected);
    }

    // A write takes effect on its row, and a range write on every row in its
    // range.
    function check_PolicyWrite_TakesEffect(
        uint256 which,
        uint256 from,
        uint256 to,
        uint256 epoch,
        bytes32 word
    )
        external
    {
        vm.assume(which < POLICY_SETTERS && epoch <= app.currentAppEpoch() + 1);
        vm.assume(which < 4 ? epoch == from : from <= epoch && epoch <= to && to <= app.currentAppEpoch() + 1);
        bytes memory data = _rangePolicyCall(which, from, to, word);
        vm.prank(OWNER);
        (bool ok,) = address(app).call(data);
        uint256 kind = which % 4;
        if (!ok) {
            assert(word == bytes32(0) && (kind == 0 || kind == 2));
            return;
        }
        if (kind == 0) assert(app.allowedComposeHashesAtEpoch(epoch, word));
        if (kind == 1) assert(!app.allowedComposeHashesAtEpoch(epoch, word));
        if (kind == 2) assert(app.allowedDeviceIdsAtEpoch(epoch, word));
        if (kind == 3) assert(!app.allowedDeviceIdsAtEpoch(epoch, word));
    }

    // ---------------------------------------------------------------
    // Revocation: removing a compose hash from every row, or a device from
    // every row and clearing the any-device flag, 0 through the next epoch,
    // leaves no selectable app epoch at which it is authorized.
    // ---------------------------------------------------------------

    function check_FullRangeRemoval_RevokesAtEveryAppEpoch(
        bool byDevice,
        bytes32 composeHash,
        bytes32 deviceId,
        bool upToDate,
        uint256 epoch,
        bool getCert
    )
        external
    {
        uint256 next = app.currentAppEpoch() + 1;
        vm.startPrank(OWNER);
        if (byDevice) {
            app.removeDeviceAtEpochs(0, next, deviceId);
            app.setAllowAnyDevice(false);
        } else {
            app.removeComposeHashAtEpochs(0, next, composeHash);
        }
        vm.stopPrank();
        bytes32 op = getCert ? AuthorizationOperation.APP_GET_CERT : AuthorizationOperation.APP_GET_KEY;
        (bool allowed,) = _appAuth(app, _info(composeHash, deviceId, upToDate), epoch, op);
        assert(!allowed);
    }
}
