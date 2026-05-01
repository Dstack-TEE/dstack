/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IAppAuthBasicManagement
 * @notice Management interface for App Authentication contracts
 * @dev This interface declares the read + write surface that operator
 *      tooling (e.g. the Hardhat tasks under `kms/auth-eth/hardhat.config.ts`,
 *      and any equivalent third-party CLI / dashboard) reads and writes
 *      against an app contract identified by its `app_id`. Any contract
 *      implementing this interface should also implement ERC-165 to allow
 *      interface detection.
 *
 *      The reference implementation is `DstackApp.sol`. Third-party app
 *      contracts that satisfy this interface (and `IAppAuth`) are
 *      drop-in replacements as far as dstack tooling is concerned —
 *      every method below is exercised by the existing test suite
 *      against `DstackApp` and is also called by an active hardhat
 *      task or test fixture.
 *
 *      UI tools can check if a contract supports this interface by
 *      calling:
 *         contract.supportsInterface(type(IAppAuthBasicManagement).interfaceId)
 *
 *      Note: interface ID changes when the interface set changes. The
 *      previous (4-mutator-only) version had ID `0x8fd37527`. Implementers
 *      that previously hardcoded that literal should switch to the
 *      `type(...).interfaceId` form so refactors stay consistent.
 */
interface IAppAuthBasicManagement is IERC165 {
    // ── Allowlist mutator events ───────────────────────────────────

    /// @notice Emitted when a new compose hash is added to the allowed list
    /// @param composeHash The compose hash that was added
    event ComposeHashAdded(bytes32 composeHash);

    /// @notice Emitted when a compose hash is removed from the allowed list
    /// @param composeHash The compose hash that was removed
    event ComposeHashRemoved(bytes32 composeHash);

    /// @notice Emitted when a new device ID is added to the allowed list
    /// @param deviceId The device ID that was added
    event DeviceAdded(bytes32 deviceId);

    /// @notice Emitted when a device ID is removed from the allowed list
    /// @param deviceId The device ID that was removed
    event DeviceRemoved(bytes32 deviceId);

    // ── Configuration mutator events ───────────────────────────────

    /// @notice Emitted when the device-allowlist bypass flag is toggled
    /// @param allowAny True if any device is now allowed to boot the app
    event AllowAnyDeviceSet(bool allowAny);

    /// @notice Emitted when the TCB-up-to-date enforcement flag is toggled
    /// @param requireUpToDate True if up-to-date TCB is now required
    event RequireTcbUpToDateSet(bool requireUpToDate);

    // ── Allowlist mutators ─────────────────────────────────────────

    /**
     * @notice Add a compose hash to the allowed list
     * @dev MUST emit `ComposeHashAdded` on success.
     *      MUST revert if caller is not authorized.
     */
    function addComposeHash(bytes32 composeHash) external;

    /**
     * @notice Remove a compose hash from the allowed list
     * @dev MUST emit `ComposeHashRemoved` on success.
     *      MUST revert if caller is not authorized.
     */
    function removeComposeHash(bytes32 composeHash) external;

    /**
     * @notice Add a device ID to the allowed list
     * @dev MUST emit `DeviceAdded` on success.
     *      MUST revert if caller is not authorized.
     */
    function addDevice(bytes32 deviceId) external;

    /**
     * @notice Remove a device ID from the allowed list
     * @dev MUST emit `DeviceRemoved` on success.
     *      MUST revert if caller is not authorized.
     */
    function removeDevice(bytes32 deviceId) external;

    // ── Configuration mutators ─────────────────────────────────────

    /**
     * @notice Toggle the device-allowlist bypass flag
     * @dev When `true`, the app's `isAppAllowed` boot check skips the
     *      `allowedDeviceIds` lookup. Used by deployments that boot on
     *      heterogeneous hardware they do not pre-allowlist.
     *      MUST emit `AllowAnyDeviceSet` on success.
     *      MUST revert if caller is not authorized.
     */
    function setAllowAnyDevice(bool allowAny) external;

    /**
     * @notice Toggle the TCB-up-to-date enforcement flag
     * @dev When `true`, the app's `isAppAllowed` boot check rejects any
     *      `bootInfo.tcbStatus != "UpToDate"`. Useful for tightening
     *      security policy on production workloads after the operator
     *      has confirmed every node is patched.
     *      MUST emit `RequireTcbUpToDateSet` on success.
     *      MUST revert if caller is not authorized.
     */
    function setRequireTcbUpToDate(bool requireUpToDate) external;

    // ── Allowlist read getters ─────────────────────────────────────
    //
    // Symmetry with the mutators above. Operator tooling and external
    // policy checkers need to be able to read the allowlist state
    // through the interface; the existing test suite exercises every
    // one of these against `DstackApp` directly today.

    /// @notice Whether `composeHash` is on the boot allowlist.
    function allowedComposeHashes(bytes32 composeHash) external view returns (bool);

    /// @notice Whether `deviceId` is on the boot allowlist.
    function allowedDeviceIds(bytes32 deviceId) external view returns (bool);

    /// @notice Whether the device allowlist is bypassed for this app.
    function allowAnyDevice() external view returns (bool);

    /// @notice Whether TCB-up-to-date enforcement is on for this app.
    function requireTcbUpToDate() external view returns (bool);

    // ── Identity + protocol read getters ───────────────────────────

    /**
     * @notice Address authorised to call the mutators above.
     * @dev The reference `DstackApp` inherits OZ `OwnableUpgradeable` and
     *      gates every mutator with `onlyOwner`, so `owner()` is the
     *      single authority. Other implementers (multisig, AccessControl,
     *      delegated-mutation patterns) MUST return the canonical address
     *      that off-chain tooling should target when constructing
     *      mutator transactions — typically the current human/EOA at the
     *      top of the governance chain.
     */
    function owner() external view returns (address);

    /**
     * @notice Implementation version number for this contract.
     * @dev Distinct from any UUPS proxy version. Bump on incompatible
     *      changes to the on-chain state shape so off-chain tooling can
     *      detect it via `version()` rather than ABI introspection.
     */
    function version() external view returns (uint256);
}
