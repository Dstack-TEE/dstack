/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IAppAuthBasicManagement
 * @notice Basic management interface for App Authentication contracts
 * @dev This interface defines the standard functions that UI tools and other contracts
 *      can use to interact with App Auth contracts. Any contract implementing this
 *      interface should also implement ERC-165 to allow interface detection.
 *      
 *      Interface ID: 0x8fd37527
 *      
 *      UI tools can check if a contract supports this interface by calling:
 *      contract.supportsInterface(type(IAppAuthBasicManagement).interfaceId)
 */
interface IAppAuthBasicManagement is IERC165 {
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

    /**
     * @notice Add a compose hash to the allowed list
     * @dev MUST emit ComposeHashAdded event on success
     *      MUST revert if caller is not authorized
     * @param composeHash The compose hash to add
     */
    function addComposeHash(bytes32 composeHash) external;
    
    /**
     * @notice Remove a compose hash from the allowed list
     * @dev MUST emit ComposeHashRemoved event on success
     *      MUST revert if caller is not authorized
     * @param composeHash The compose hash to remove
     */
    function removeComposeHash(bytes32 composeHash) external;

    /**
     * @notice Add a device ID to the allowed list
     * @dev MUST emit DeviceAdded event on success
     *      MUST revert if caller is not authorized
     * @param deviceId The device ID to add
     */
    function addDevice(bytes32 deviceId) external;

    /**
     * @notice Remove a device ID from the allowed list
     * @dev MUST emit DeviceRemoved event on success
     *      MUST revert if caller is not authorized
     * @param deviceId The device ID to remove
     */
    function removeDevice(bytes32 deviceId) external;
}