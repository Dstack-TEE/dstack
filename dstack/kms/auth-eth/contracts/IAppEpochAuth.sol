/*
 * SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "./IAppAuth.sol";

/// Optional epoch- and operation-aware policy capability. Legacy policies only authorize app epoch zero.
interface IAppEpochAuth {
    function authorizeApp(
        IAppAuth.AppInfo calldata bootInfo,
        uint256 appEpoch,
        bytes32 operation
    )
        external
        view
        returns (bool isAllowed, string memory reason);
}
