/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IAppTcbPolicy
 * @notice Interface for contracts that provide a TCB (Trusted Computing Base) policy.
 * @dev The policy is stored as an opaque JSON string interpreted by the KMS.
 *      The JSON format is versioned and supports multiple TEE types:
 *
 *      {
 *        "version": 1,
 *        "intel_qal": [
 *          {"environment": {"class_id": "..."}, "reference": {...}},
 *          ...
 *        ]
 *      }
 *
 *      Interface ID: computed from tcbPolicy()
 */
interface IAppTcbPolicy is IERC165 {
    /// @notice Emitted when the TCB policy is updated
    event TcbPolicySet(string policy);

    /**
     * @notice Get the TCB policy JSON string
     * @return The policy JSON, or empty string if no policy is set
     */
    function tcbPolicy() external view returns (string memory);

    /**
     * @notice Set the TCB policy JSON string
     * @dev MUST emit TcbPolicySet event on success
     *      MUST revert if caller is not authorized
     * @param policy The policy JSON string (empty to clear)
     */
    function setTcbPolicy(string calldata policy) external;
}
