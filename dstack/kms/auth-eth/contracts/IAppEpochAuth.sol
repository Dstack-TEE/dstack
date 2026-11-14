/*
 * SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "./IAppAuth.sol";

/// An explicitly selected value; `isSet == false` selects the current one.
struct OptionalUint256 {
    bool isSet;
    uint256 value;
}

struct AuthorizationRequest {
    IAppAuth.AppInfo appInfo;
    bytes32 operation;
    OptionalUint256 requestedAppEpoch;
    OptionalUint256 requestedRootEpoch;
    /// The TEE platform the KMS attested, e.g. "dstack-tdx" or "dstack-amd-sev-snp".
    /// Measurements, device IDs and TCB status are only meaningful per platform,
    /// and one OS image may boot on several.
    string teeVariant;
    /// The launch ticket the attested subject presented, as
    /// sha256("dstack-launch-ticket/v1:" || ticket); zero when it presented none.
    bytes32 launchTicketHash;
}

struct AuthorizationResult {
    bool authorized;
    string rejectionReason;
    string gatewayAppId;
    uint256 currentRootEpoch;
    bytes32 currentRootEpochHash;
    uint256 currentAppEpoch;
    // The latest registered root epoch, which may be pending activation.
    uint256 latestRootEpoch;
    bytes32 latestRootEpochHash;
}

/// Optional epoch- and operation-aware policy capability. Legacy policies only authorize app epoch zero.
interface IAppEpochAuth {
    function currentAppEpoch() external view returns (uint256);

    /// Receives the KMS request unchanged. The policy validates the operation and app
    /// epoch and fills `authorized`, `rejectionReason` and `currentAppEpoch`; the KMS
    /// owns `gatewayAppId` and the current and latest root epoch fields.
    function authorizeApp(AuthorizationRequest calldata request) external view returns (AuthorizationResult memory);
}
