/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "../DstackKms.sol";

/// @custom:oz-upgrades-from contracts/DstackKms.sol:DstackKms
/// @custom:oz-upgrades-unsafe-allow missing-initializer missing-initializer-call
contract DstackKmsV2 is DstackKms {
    // Minimal V2 contract that can be upgraded from DstackKms.
    // Inherits all functionality; only exists to give the upgrade-safety
    // validator a distinct target with an explicit reinitializer.

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // No new state in this test V2, but OZ's upgrade-safety validator
    // requires an initializer marked with `reinitializer`. The presence of
    // this function also gives V2 a different bytecode from V1.
    // See DstackAppV2 for explanation of the annotations.
    /// @custom:oz-upgrades-validate-as-initializer
    function initializeV2() public reinitializer(2) { }
}
