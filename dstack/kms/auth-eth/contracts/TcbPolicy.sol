// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.24;

import "./TeeVariantPolicy.sol";

/// The TCB statuses and advisory IDs a policy accepts, per TEE platform. A TCB
/// status only means something on the platform that reported it: TDX's comes
/// from Intel's TCB info, SEV-SNP's from the KMS's AMD bulletin list, and the
/// Nitro platforms report none.
library TcbPolicy {
    struct Rule {
        string[] allowedTcbStatuses;
        string[] allowedAdvisoryIds;
    }

    /// Rules by keccak256(teeVariant). A platform without a rule, and a legacy
    /// caller that reports no platform, must be "UpToDate" with advisories
    /// unchecked, as before platform rules.
    struct Policy {
        mapping(bytes32 => Rule) rules;
    }

    /// Clears the platform's rule when `allowedTcbStatuses` is empty.
    function set(
        Policy storage policy,
        string calldata teeVariant,
        string[] calldata allowedTcbStatuses,
        string[] calldata allowedAdvisoryIds
    )
        internal
    {
        require(TeeVariantPolicy.isKnown(teeVariant), "unknown TEE variant");
        require(allowedTcbStatuses.length != 0 || allowedAdvisoryIds.length == 0, "advisories without statuses");
        Rule storage rule = policy.rules[keccak256(bytes(teeVariant))];
        _copy(rule.allowedTcbStatuses, allowedTcbStatuses);
        _copy(rule.allowedAdvisoryIds, allowedAdvisoryIds);
    }

    function get(
        Policy storage policy,
        string calldata teeVariant
    )
        internal
        view
        returns (string[] memory allowedTcbStatuses, string[] memory allowedAdvisoryIds)
    {
        Rule storage rule = policy.rules[keccak256(bytes(teeVariant))];
        return (rule.allowedTcbStatuses, rule.allowedAdvisoryIds);
    }

    /// Whether the platform's rule accepts the status and every advisory.
    function admits(
        Policy storage policy,
        string memory teeVariant,
        string memory tcbStatus,
        string[] memory advisoryIds
    )
        internal
        view
        returns (bool)
    {
        Rule storage rule = policy.rules[keccak256(bytes(teeVariant))];
        if (rule.allowedTcbStatuses.length == 0) return keccak256(bytes(tcbStatus)) == keccak256("UpToDate");
        if (!_contains(rule.allowedTcbStatuses, tcbStatus)) return false;
        for (uint256 i = 0; i < advisoryIds.length; ++i) {
            if (!_contains(rule.allowedAdvisoryIds, advisoryIds[i])) return false;
        }
        return true;
    }

    function _copy(string[] storage dst, string[] calldata src) private {
        while (dst.length != 0) {
            dst.pop();
        }
        for (uint256 i = 0; i < src.length; ++i) {
            dst.push(src[i]);
        }
    }

    function _contains(string[] storage list, string memory value) private view returns (bool) {
        bytes32 key = keccak256(bytes(value));
        for (uint256 i = 0; i < list.length; ++i) {
            if (keccak256(bytes(list[i])) == key) return true;
        }
        return false;
    }
}
