/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";
import "../contracts/IAppAuth.sol";

/// @notice Halmos symbolic tests for DstackKms.
///
/// Owner-only mutation tests are intentionally omitted — every write
/// function uses OpenZeppelin's `onlyOwner` modifier; the spec
/// (docs/specification.md §3) documents the precondition and trusts
/// the OZ modifier. Proving each one symbolically is a fuzz test in
/// symbolic clothing.
///
/// Run with `halmos --contract DstackKmsSymbolicTest`.

/// @dev Mock app contract with a configurable `isAppAllowed` return.
///      The constructor argument is the symbolic input we treat as
///      "what a benign-shape registered app would return."
contract MockConfigurableApp {
    bool internal immutable _ret;

    constructor(bool ret) {
        _ret = ret;
    }

    function isAppAllowed(IAppAuth.AppBootInfo calldata) external view returns (bool, string memory) {
        return (_ret, "");
    }
}

/// @dev Mock app contract that always reverts on `isAppAllowed`. Used
///      to verify that a malicious registered contract's revert
///      propagates out of `kms.isAppAllowed` rather than being swallowed.
contract MockRevertingApp {
    function isAppAllowed(IAppAuth.AppBootInfo calldata) external pure returns (bool, string memory) {
        revert("malicious app revert");
    }
}

contract DstackKmsSymbolicTest is Test {
    DstackKms internal kms;
    DstackApp internal appImpl;
    address internal constant OWNER = address(0xA11CE);

    function setUp() public {
        appImpl = new DstackApp();

        DstackKms kmsImpl = new DstackKms();
        bytes memory initData = abi.encodeCall(DstackKms.initialize, (OWNER, address(appImpl)));
        ERC1967Proxy proxy = new ERC1967Proxy(address(kmsImpl), initData);
        kms = DstackKms(address(proxy));
    }

    // ---------------------------------------------------------------
    // registerApp is intentionally permissionless. The Halmos run
    // confirms any caller can register any non-zero address; zero is
    // rejected. Authorization is gated downstream by the
    // owner-controlled allowedOsImages whitelist and by the registered
    // app's own isAppAllowed — see check_IsAppAllowed_* below.
    // ---------------------------------------------------------------

    function check_RegisterApp_AnyCallerCanRegisterNonZeroAddress(address caller, address appId) external {
        vm.assume(appId != address(0));
        vm.prank(caller);
        kms.registerApp(appId);
        assert(kms.registeredApps(appId));
    }

    function check_RegisterApp_RejectsZeroAddress(address caller) external {
        vm.prank(caller);
        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.registerApp.selector, address(0)));
        assert(!ok);
    }

    // ---------------------------------------------------------------
    // KMS.isAppAllowed short-circuits — symbolic bootInfo, in each
    // case the gate that's not satisfied is the one that produces
    // the (false, reason) return without delegating.
    // ---------------------------------------------------------------

    function check_IsAppAllowed_RejectsUnregisteredApp(IAppAuth.AppBootInfo calldata bootInfo) external view {
        // No apps registered in setUp(), so any bootInfo.appId is rejected.
        (bool allowed, string memory reason) = kms.isAppAllowed(bootInfo);
        assert(!allowed);
        assert(keccak256(bytes(reason)) == keccak256(bytes("App not registered")));
    }

    function check_IsAppAllowed_RejectsUnknownOsImage(address appId, IAppAuth.AppBootInfo calldata bootInfo) external {
        vm.assume(appId != address(0));

        // Register the appId so the registration check passes.
        vm.prank(OWNER);
        kms.registerApp(appId);

        // No OS image is in the allowlist, so any bootInfo.osImageHash rejects.
        vm.assume(bootInfo.appId == appId);
        (bool allowed, string memory reason) = kms.isAppAllowed(bootInfo);
        assert(!allowed);
        assert(keccak256(bytes(reason)) == keccak256(bytes("OS image is not allowed")));
    }

    // ---------------------------------------------------------------
    // KMS.isAppAllowed delegation, benign-shape registered contract:
    // when the registration and OS-image gates both pass, the outer
    // call's boolean return equals the registered IAppAuth's return.
    //
    // The mock returns whatever bool is passed at construction (Halmos
    // explores both branches). The empty-string reason and the absence
    // of revert/OOG paths are *not* universally quantified — those are
    // separate properties (next test for the revert case; OOG / short-
    // returndata are out of scope and noted in docs/formal-verification.md).
    // ---------------------------------------------------------------

    function check_IsAppAllowed_DelegatesFaithfully(bool mockReturn, bytes32 osImageHash) external {
        MockConfigurableApp mock = new MockConfigurableApp(mockReturn);

        vm.startPrank(OWNER);
        kms.registerApp(address(mock));
        kms.addOsImageHash(osImageHash);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory b = IAppAuth.AppBootInfo({
            appId: address(mock),
            composeHash: bytes32(0),
            instanceId: address(0),
            deviceId: bytes32(0),
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: osImageHash,
            tcbStatus: "",
            advisoryIds: new string[](0)
        });

        (bool outerAllowed,) = kms.isAppAllowed(b);
        assert(outerAllowed == mockReturn);
    }

    // ---------------------------------------------------------------
    // Revert propagation: if the registered IAppAuth reverts, the
    // outer kms.isAppAllowed call also reverts. The KMS does not
    // catch / mask the inner revert. (Spec §5.1.)
    // ---------------------------------------------------------------

    function check_IsAppAllowed_PropagatesMockRevert(bytes32 osImageHash) external {
        MockRevertingApp mock = new MockRevertingApp();

        vm.startPrank(OWNER);
        kms.registerApp(address(mock));
        kms.addOsImageHash(osImageHash);
        vm.stopPrank();

        IAppAuth.AppBootInfo memory b = IAppAuth.AppBootInfo({
            appId: address(mock),
            composeHash: bytes32(0),
            instanceId: address(0),
            deviceId: bytes32(0),
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: osImageHash,
            tcbStatus: "",
            advisoryIds: new string[](0)
        });

        (bool ok,) = address(kms).call(abi.encodeWithSelector(kms.isAppAllowed.selector, b));
        assert(!ok);
    }

    // ---------------------------------------------------------------
    // KMS.isKmsAllowed short-circuits — mirror of the isAppAllowed
    // gate proofs above. Symbolic bootInfo; in each case the gate
    // that isn't satisfied produces the (false, reason) return.
    //
    // We pre-set tcbStatus to "UpToDate" because the keccak-based
    // string compare is byte-exact under collision resistance (see
    // docs/specification.md §3.9); symbolic exploration of that
    // branch via Halmos's uninterpreted-keccak is circular and
    // omitted.
    // ---------------------------------------------------------------

    function check_IsKmsAllowed_RejectsUnknownMr(bytes32 osImageHash, bytes32 mrAggregated) external {
        // Allow the OS image so the second gate passes; leave
        // kmsAllowedAggregatedMrs empty.
        vm.prank(OWNER);
        kms.addOsImageHash(osImageHash);

        IAppAuth.AppBootInfo memory b = IAppAuth.AppBootInfo({
            appId: address(0),
            composeHash: bytes32(0),
            instanceId: address(0),
            deviceId: bytes32(0),
            mrAggregated: mrAggregated,
            mrSystem: bytes32(0),
            osImageHash: osImageHash,
            tcbStatus: "UpToDate",
            advisoryIds: new string[](0)
        });

        (bool allowed, string memory reason) = kms.isKmsAllowed(b);
        assert(!allowed);
        assert(keccak256(bytes(reason)) == keccak256(bytes("Aggregated MR not allowed")));
    }

    function check_IsKmsAllowed_RejectsUnknownDevice(
        bytes32 osImageHash,
        bytes32 mrAggregated,
        bytes32 deviceId
    )
        external
    {
        vm.startPrank(OWNER);
        kms.addOsImageHash(osImageHash);
        kms.addKmsAggregatedMr(mrAggregated);
        vm.stopPrank();
        // kmsAllowedDeviceIds is left empty.

        IAppAuth.AppBootInfo memory b = IAppAuth.AppBootInfo({
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

        (bool allowed, string memory reason) = kms.isKmsAllowed(b);
        assert(!allowed);
        assert(keccak256(bytes(reason)) == keccak256(bytes("KMS is not allowed to boot on this device")));
    }

    // ---------------------------------------------------------------
    // deployAndRegisterApp 6-arg post-state: when the factory call
    // returns, the returned address is registered AND its proxy's
    // owner / allowAnyDevice / requireTcbUpToDate match the supplied
    // flags exactly. Renamed from a previous "_Atomic" name — true
    // atomicity (no partial registration on revert) is an EVM-level
    // guarantee, not a property worth re-proving.
    // ---------------------------------------------------------------

    function check_DeployAndRegisterApp_PostState(
        address initialOwner,
        bool requireTcbUpToDate,
        bool allowAnyDevice,
        bytes32 initialDeviceId,
        bytes32 initialComposeHash
    )
        external
    {
        vm.assume(initialOwner != address(0));

        vm.prank(OWNER);
        address appId = kms.deployAndRegisterApp(
            initialOwner, false, requireTcbUpToDate, allowAnyDevice, initialDeviceId, initialComposeHash
        );

        assert(kms.registeredApps(appId));
        assert(DstackApp(appId).requireTcbUpToDate() == requireTcbUpToDate);
        assert(DstackApp(appId).allowAnyDevice() == allowAnyDevice);
        assert(DstackApp(appId).owner() == initialOwner);
        // Spec §3.3: the conditional initial-state branches actually fire.
        assert(DstackApp(appId).allowedDeviceIds(initialDeviceId) == (initialDeviceId != bytes32(0)));
        assert(DstackApp(appId).allowedComposeHashes(initialComposeHash) == (initialComposeHash != bytes32(0)));
    }

    // Legacy 5-arg overload always defaults `requireTcbUpToDate` to false.
    function check_DeployAndRegisterApp5Arg_DefaultsTcbToFalse(
        address initialOwner,
        bool allowAnyDevice,
        bytes32 initialDeviceId,
        bytes32 initialComposeHash
    )
        external
    {
        vm.assume(initialOwner != address(0));

        vm.prank(OWNER);
        address appId =
            kms.deployAndRegisterApp(initialOwner, false, allowAnyDevice, initialDeviceId, initialComposeHash);

        assert(kms.registeredApps(appId));
        assert(!DstackApp(appId).requireTcbUpToDate());
        // Spec §3.4: defers to 6-arg post-state, including the conditional branches.
        assert(DstackApp(appId).allowedDeviceIds(initialDeviceId) == (initialDeviceId != bytes32(0)));
        assert(DstackApp(appId).allowedComposeHashes(initialComposeHash) == (initialComposeHash != bytes32(0)));
    }

    // ---------------------------------------------------------------
    // INV-2 (owner integrity): none of DstackKms's OWN externally-
    // callable functions can change `owner()`. Only the inherited
    // Ownable2Step functions (transferOwnership + acceptOwnership) and
    // renounceOwnership may change ownership; those are upstream-tested
    // and excluded from the enumeration below. This proves the
    // contract's own surface never writes the owner slot — e.g. via a
    // storage collision or an accidental write — for any caller and
    // any args.
    //
    // Issued directly against the PROXY so the call mutates proxy
    // storage, with the owner read via the getter on the same proxy.
    // (Same construction as the INV-1 step test in DstackApp; the
    // earlier invariant-mode harness that drove the implementation
    // instead of the proxy is deliberately avoided.)
    //
    // Scope: the step is anchored at the canonical post-init state
    // (owner = OWNER, no pending owner). Full quantification over
    // arbitrary pre-states needs symbolic storage (absent in Halmos
    // 0.3.3). Validated by mutation testing — a function mutated to
    // call `_transferOwnership(msg.sender)` is caught. See
    // docs/specification.md §4 (INV-2).
    // ---------------------------------------------------------------

    function check_Owner_NotChangedByKmsFunctions(
        address caller,
        uint256 which,
        bytes32 word,
        address addr,
        bool flag
    )
        external
    {
        address ownerBefore = kms.owner();

        bytes memory data;
        if (which == 0) {
            data = abi.encodeWithSelector(DstackKms.setGatewayAppId.selector, "");
        } else if (which == 1) {
            data = abi.encodeWithSelector(DstackKms.setAppImplementation.selector, addr);
        } else if (which == 2) {
            data = abi.encodeWithSelector(DstackKms.registerApp.selector, addr);
        } else if (which == 3) {
            data = abi.encodeWithSelector(DstackKms.addKmsAggregatedMr.selector, word);
        } else if (which == 4) {
            data = abi.encodeWithSelector(DstackKms.removeKmsAggregatedMr.selector, word);
        } else if (which == 5) {
            data = abi.encodeWithSelector(DstackKms.addKmsDevice.selector, word);
        } else if (which == 6) {
            data = abi.encodeWithSelector(DstackKms.removeKmsDevice.selector, word);
        } else if (which == 7) {
            data = abi.encodeWithSelector(DstackKms.addOsImageHash.selector, word);
        } else if (which == 8) {
            data = abi.encodeWithSelector(DstackKms.removeOsImageHash.selector, word);
        } else if (which == 9) {
            data = abi.encodeWithSelector(
                bytes4(keccak256("deployAndRegisterApp(address,bool,bool,bool,bytes32,bytes32)")),
                addr,
                flag,
                flag,
                flag,
                word,
                word
            );
        } else if (which == 10) {
            data = abi.encodeWithSelector(
                bytes4(keccak256("deployAndRegisterApp(address,bool,bool,bytes32,bytes32)")),
                addr,
                flag,
                flag,
                word,
                word
            );
        } else if (which == 11) {
            data = abi.encodeWithSelector(DstackKms.setKmsQuote.selector, "");
        } else if (which == 12) {
            data = abi.encodeWithSelector(DstackKms.setKmsEventlog.selector, "");
        } else if (which == 13) {
            data = abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, addr, "");
        } else {
            return; // outside the enumerated KMS-own mutating surface
        }

        vm.prank(caller);
        (bool ok,) = address(kms).call(data);
        ok; // success/revert both allowed; only the owner-slot outcome matters

        assert(kms.owner() == ownerBefore);
    }
}
