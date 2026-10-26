/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "../DstackApp.sol";

// The validator can't unambiguously resolve a parent initializer because
// DstackApp has two `initialize` overloads (legacy 5-arg + new 6-arg with
// the TCB toggle). For this test-only V2 there is no new state, so the
// parents do not need to be re-initialized; the unsafe-allow below
// acknowledges the check is being skipped.
/// @custom:oz-upgrades-from contracts/DstackApp.sol:DstackApp
/// @custom:oz-upgrades-unsafe-allow missing-initializer missing-initializer-call
contract DstackAppV2 is DstackApp {
    // Minimal V2 contract that can be upgraded from DstackApp.
    // Inherits all functionality; only exists to give the upgrade-safety
    // validator a distinct target with an explicit reinitializer.

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // No new state in this test V2, but OZ's upgrade-safety validator
    // requires an initializer marked with `reinitializer`. Empty body is
    // intentional — the upgrade tests don't pass init data. The presence
    // of this function is also what gives V2 a different bytecode from V1.
    // Newer @openzeppelin/upgrades-core (1.44+) recognizes reinitializers
    // only when explicitly opted in via `validate-as-initializer`, and
    // then insists on parent-initializer calls — which we can't honor
    // since the proxy is already initialized. The contract-level
    // `unsafe-allow missing-initializer missing-initializer-call`
    // suppresses both checks for both old and new validator versions.
    /// @custom:oz-upgrades-validate-as-initializer
    function initializeV2() public reinitializer(2) { }
}
