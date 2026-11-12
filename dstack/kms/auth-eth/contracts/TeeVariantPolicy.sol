// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.24;

/// The TEE platforms a policy admits, named as the KMS reports them in
/// `AuthorizationRequest.teeVariant`. It covers every epoch: which platforms may hold keys
/// is a trust decision, not a property of a key generation.
library TeeVariantPolicy {
    /// Zero-initialized as unrestricted, so proxies upgraded from before platform
    /// policies keep their decisions. Bit `n` of `allowed` admits `names()[n]`.
    struct Policy {
        bool restricted;
        uint64 allowed;
    }

    uint256 private constant COUNT = 5;

    /// The platforms a policy can list, in the order of dstack's `TeeVariant`.
    /// Append new ones (and bump COUNT); a restricted policy refuses names it
    /// does not know.
    function names() internal pure returns (string[COUNT] memory) {
        return ["dstack-tdx", "dstack-gcp-tdx", "dstack-nitro-enclave", "dstack-amd-sev-snp", "dstack-aws-nitro-tpm"];
    }

    function admits(Policy storage policy, string calldata teeVariant) internal view returns (bool) {
        if (!policy.restricted) return true;
        (bool known, uint8 index) = _indexOf(teeVariant);
        return known && (policy.allowed >> index) & 1 == 1;
    }

    /// Returns the stored mask, a canonical value for audit events.
    function setAllowed(Policy storage policy, string[] calldata teeVariants) internal returns (uint64) {
        uint64 allowed = 0;
        for (uint256 i = 0; i < teeVariants.length; ++i) {
            (bool known, uint8 index) = _indexOf(teeVariants[i]);
            require(known, "unknown TEE variant");
            allowed |= uint64(1) << index;
        }
        policy.allowed = allowed;
        return allowed;
    }

    function allowedNames(Policy storage policy) internal view returns (string[] memory list) {
        string[COUNT] memory all = names();
        uint64 allowed = policy.allowed;
        list = new string[](_popcount(allowed));
        uint256 n = 0;
        for (uint256 i = 0; i < all.length; ++i) {
            if ((allowed >> i) & 1 == 1) list[n++] = all[i];
        }
    }

    function _indexOf(string calldata teeVariant) private pure returns (bool, uint8) {
        bytes32 key = keccak256(bytes(teeVariant));
        string[COUNT] memory all = names();
        for (uint8 i = 0; i < all.length; ++i) {
            if (keccak256(bytes(all[i])) == key) return (true, i);
        }
        return (false, 0);
    }

    function _popcount(uint64 bits) private pure returns (uint256 count) {
        for (; bits != 0; bits &= bits - 1) {
            ++count;
        }
    }
}
