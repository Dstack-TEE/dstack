/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IAppAuth
 * @notice Core interface for App Authentication contracts
 * @dev This interface defines the core function for validating app boot information.
 *      Any contract implementing this interface should also implement ERC-165 to
 *      allow interface detection.
 *
 *      Interface ID: 0x1e079198
 *
 *      This interface can be checked using:
 *      contract.supportsInterface(0x1e079198)
 */
interface IAppAuth is IERC165 {
    /**
     * @notice Information required to validate app boot authorization
     * @param appId The unique identifier for the application
     * @param composeHash Hash of the application composition/configuration
     * @param instanceId Unique identifier for this specific app instance
     * @param deviceId Unique identifier for the device/hardware
     * @param mrAggregated Aggregated measurement register value
     * @param mrSystem System measurement register value
     * @param osImageHash Hash of the operating system image
     * @param tcbStatus Trusted Computing Base status
     * @param advisoryIds Array of security advisory identifiers
     */
    struct AppBootInfo {
        address appId;
        bytes32 composeHash;
        address instanceId;
        bytes32 deviceId;
        bytes32 mrAggregated;
        bytes32 mrSystem;
        bytes32 osImageHash;
        string tcbStatus;
        string[] advisoryIds;
    }

    /**
     * @notice Check if an application is allowed to boot with the given parameters
     * @dev This is the core authorization function that validates all boot parameters
     * @param bootInfo Struct containing all necessary boot validation information
     * @return isAllowed True if the app is authorized to boot, false otherwise
     * @return reason Human-readable reason for the decision (empty if allowed)
     */
    function isAppAllowed(AppBootInfo calldata bootInfo) external view returns (bool isAllowed, string memory reason);
}
