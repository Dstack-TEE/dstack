/*
 * SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

/// Allowlist management. Each allowlist setter names the app epoch rows it
/// writes: one epoch, or `fromEpoch` through `toEpoch`, at most the next epoch.
/// `setAllowAnyDevice`, `setAllowAnyTeeVariant` and `setAllowedTeeVariants` cover
/// every app epoch.
/// Replaces the epoch-less IAppAuthBasicManagement (0x8fd37527), which policies
/// predating app epochs still report; tools tell the two apart by interface ID.
interface IAppEpochManagement {
    function addComposeHashAtEpoch(uint256 epoch, bytes32 composeHash) external;
    function addComposeHashAtEpochs(uint256 fromEpoch, uint256 toEpoch, bytes32 composeHash) external;
    function removeComposeHashAtEpoch(uint256 epoch, bytes32 composeHash) external;
    function removeComposeHashAtEpochs(uint256 fromEpoch, uint256 toEpoch, bytes32 composeHash) external;
    function addDeviceAtEpoch(uint256 epoch, bytes32 deviceId) external;
    function addDeviceAtEpochs(uint256 fromEpoch, uint256 toEpoch, bytes32 deviceId) external;
    function removeDeviceAtEpoch(uint256 epoch, bytes32 deviceId) external;
    function removeDeviceAtEpochs(uint256 fromEpoch, uint256 toEpoch, bytes32 deviceId) external;
    function setAllowAnyDevice(bool allowed) external;
    function setAllowAnyTeeVariant(bool allowed) external;
    function setAllowedTeeVariants(string[] calldata teeVariants) external;
}
