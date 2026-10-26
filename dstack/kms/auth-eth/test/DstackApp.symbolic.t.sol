/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/DstackApp.sol";
import "../contracts/IAppAuth.sol";

/// @notice Halmos symbolic tests for DstackApp.
///
/// We deliberately do NOT include per-function `_OnlyOwner` tests. Each
/// owner-gated mutation goes through OpenZeppelin's `onlyOwner` modifier
/// (literally `_checkOwner(); _;`). Proving symbolically that a non-owner
/// caller reverts on each function is a fuzz-test in symbolic clothing —
/// it adds no information that bounded fuzzing wouldn't already deliver,
/// and the modifier itself is exhaustively tested upstream. The spec
/// (docs/specification.md §3) documents these as `pre: msg.sender == owner()`
/// and trusts the OZ modifier; we don't restate that here.
///
/// Run with `halmos --contract DstackAppSymbolicTest`.
contract DstackAppSymbolicTest is Test {
    DstackApp internal app;
    address internal constant OWNER = address(0xA11CE);

    function setUp() public {
        // Deploy proxy directly via ERC1967, bypassing the OZ Upgrades plugin
        // (which uses FFI and is unsuitable for symbolic execution).
        DstackApp impl = new DstackApp();
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,bool,bool,bytes32,bytes32)", OWNER, false, false, bytes32(0), bytes32(0)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        app = DstackApp(address(proxy));
    }

    // ---------------------------------------------------------------
    // After disableUpgrades(), the *next* upgradeToAndCall reverts for
    // any caller / impl / init data.
    //
    // This is single-call only — not full monotonicity (∀ traces, once
    // _upgradesDisabled = true it stays true), which is INV-1 in the
    // spec and listed there as a cross-transaction gap. Renamed from
    // an earlier "_Monotonic" name that overclaimed.
    // ---------------------------------------------------------------

    function check_DisableUpgrades_BlocksNextUpgrade(address upgrader, address newImpl, bytes calldata data) external {
        vm.prank(OWNER);
        app.disableUpgrades();

        vm.prank(upgrader);
        (bool ok,) = address(app).call(abi.encodeWithSelector(app.upgradeToAndCall.selector, newImpl, data));
        assert(!ok);
    }

    /// @dev `_upgradesDisabled` is slot 1, byte 0 in DstackApp's storage
    ///      (confirmed via `forge inspect DstackApp storageLayout`; the OZ
    ///      v5.4.0 parents use ERC-7201 namespaced storage and consume no
    ///      sequential slots). Read it on the PROXY, which is where the
    ///      delegatecalled implementation actually writes.
    function _upgradesDisabledFlag(address proxy) internal view returns (bool) {
        return uint256(vm.load(proxy, bytes32(uint256(1)))) & 0xff != 0;
    }

    // ---------------------------------------------------------------
    // INV-1 inductive STEP: from the disabled state, no single call to
    // any of DstackApp's externally-callable state-changing functions —
    // by any caller, with symbolic args — can flip `_upgradesDisabled`
    // back to false.
    //
    // The call is issued directly against the PROXY (`address(app)`),
    // so it delegatecalls into the implementation and mutates proxy
    // storage; the assertion reads that same proxy slot. (An earlier
    // attempt used Halmos invariant-mode auto-targeting, which was
    // BROKEN: the fuzzer drove the *implementation* contract while the
    // assertion read the *proxy*, so it passed vacuously and did not
    // catch a permissionless flag-reset mutant. This formulation does
    // catch that mutant — verified by mutation testing.)
    //
    // We enumerate the mutating surface with concrete selectors rather
    // than fully-symbolic calldata: Halmos 0.3.3 raises NotConcreteError
    // when a fully-symbolic calldata blob is decoded as a dynamic type,
    // which would make the result inconclusive. The `which` selector is
    // symbolic, so Halmos explores every branch; args are symbolic.
    //
    // Scope and residual gap: this proves the step from the *canonical*
    // disabled state (fresh proxy + one disableUpgrades), not over an
    // arbitrary disabled pre-state. Full inductive monotonicity would
    // require symbolic storage (absent in Halmos 0.3.3). Combined with
    // the source-level argument in docs/specification.md §4 (only two
    // writers to the slot; the initializer path is closed by
    // check_Initialize_OnceOnly), this is a strong but not complete
    // mechanization. See spec §4 / §7.
    // ---------------------------------------------------------------

    function check_UpgradesDisabled_StepPreservation(
        address caller,
        uint256 which,
        bytes32 word,
        bool flag,
        address addr
    )
        external
    {
        vm.prank(OWNER);
        app.disableUpgrades();
        assert(_upgradesDisabledFlag(address(app))); // base: flag is set

        bytes memory data;
        if (which == 0) data = abi.encodeWithSelector(DstackApp.addComposeHash.selector, word);
        else if (which == 1) data = abi.encodeWithSelector(DstackApp.removeComposeHash.selector, word);
        else if (which == 2) data = abi.encodeWithSelector(DstackApp.addDevice.selector, word);
        else if (which == 3) data = abi.encodeWithSelector(DstackApp.removeDevice.selector, word);
        else if (which == 4) data = abi.encodeWithSelector(DstackApp.setAllowAnyDevice.selector, flag);
        else if (which == 5) data = abi.encodeWithSelector(DstackApp.setRequireTcbUpToDate.selector, flag);
        else if (which == 6) data = abi.encodeWithSelector(DstackApp.disableUpgrades.selector);
        else if (which == 7) data = abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, addr, "");
        else if (which == 8) data = abi.encodeWithSelector(Ownable2StepUpgradeable.transferOwnership.selector, addr);
        else if (which == 9) data = abi.encodeWithSelector(Ownable2StepUpgradeable.acceptOwnership.selector);
        else if (which == 10) data = abi.encodeWithSelector(OwnableUpgradeable.renounceOwnership.selector);
        else return; // outside the enumerated mutating surface

        vm.prank(caller);
        (bool ok,) = address(app).call(data);
        ok; // success/revert both allowed; only the post-state matters

        assert(_upgradesDisabledFlag(address(app))); // step: flag still set
    }

    // ---------------------------------------------------------------
    // 5-arg legacy initializer leaves the new requireTcbUpToDate slot
    // at zero regardless of the other inputs — proves the storage
    // layout for the post-rebase field doesn't accidentally pick up
    // garbage from any input combination.
    // ---------------------------------------------------------------

    function check_Initialize5Arg_DefaultsTcbToFalse(
        address initialOwner,
        bool disableUpgrades,
        bool allowAnyDevice,
        bytes32 deviceId,
        bytes32 composeHash
    )
        external
    {
        vm.assume(initialOwner != address(0));

        DstackApp impl = new DstackApp();
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,bool,bool,bytes32,bytes32)",
            initialOwner,
            disableUpgrades,
            allowAnyDevice,
            deviceId,
            composeHash
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        DstackApp fresh = DstackApp(address(proxy));

        assert(!fresh.requireTcbUpToDate());
    }

    // ---------------------------------------------------------------
    // 6-arg initializer honors the TCB flag exactly for any inputs.
    // ---------------------------------------------------------------

    function check_Initialize6Arg_HonorsTcbFlag(
        address initialOwner,
        bool flag,
        bool allowAnyDevice,
        bytes32 deviceId,
        bytes32 composeHash
    )
        external
    {
        vm.assume(initialOwner != address(0));

        DstackApp impl = new DstackApp();
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,bool,bool,bool,bytes32,bytes32)",
            initialOwner,
            false,
            flag,
            allowAnyDevice,
            deviceId,
            composeHash
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        DstackApp fresh = DstackApp(address(proxy));

        assert(fresh.requireTcbUpToDate() == flag);
    }

    // ---------------------------------------------------------------
    // INV-3: the proxy can be initialized at most once. setUp() runs
    // the 5-arg overload successfully; this test proves both the
    // 5-arg and 6-arg overloads revert for any inputs after that.
    // ---------------------------------------------------------------

    function check_Initialize_OnceOnly(
        address initialOwner,
        bool disableUpgrades,
        bool requireTcbUpToDate,
        bool allowAnyDevice,
        bytes32 deviceId,
        bytes32 composeHash
    )
        external
    {
        bytes memory data5 = abi.encodeWithSignature(
            "initialize(address,bool,bool,bytes32,bytes32)",
            initialOwner,
            disableUpgrades,
            allowAnyDevice,
            deviceId,
            composeHash
        );
        (bool ok5,) = address(app).call(data5);
        assert(!ok5);

        bytes memory data6 = abi.encodeWithSignature(
            "initialize(address,bool,bool,bool,bytes32,bytes32)",
            initialOwner,
            disableUpgrades,
            requireTcbUpToDate,
            allowAnyDevice,
            deviceId,
            composeHash
        );
        (bool ok6,) = address(app).call(data6);
        assert(!ok6);
    }
}
