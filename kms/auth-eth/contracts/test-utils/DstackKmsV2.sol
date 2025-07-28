// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "../DstackKms.sol";

/**
 * @custom:oz-upgrades-from contracts/DstackKms.sol:DstackKms
 */
contract DstackKmsV2 is DstackKms {
    // Minimal V2 contract that can be upgraded from DstackKms
    // Inherits all functionality from DstackKms
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
    
    // Optional: Add a version identifier for testing
    function version() public pure returns (string memory) {
        return "2.0.0";
    }
}