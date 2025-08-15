/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.22;

import "../DstackApp.sol";

/**
 * @custom:oz-upgrades-from contracts/DstackApp.sol:DstackApp
 */
contract DstackAppV2 is DstackApp {
    // Minimal V2 contract that can be upgraded from DstackApp
    // Inherits all functionality from DstackApp
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
    
    // Optional: Add a version identifier for testing
    function version() public pure returns (string memory) {
        return "2.0.0";
    }
}