/*
 * SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";

// Pre-epoch KMS storage and identity setter, for migration tests. Keep the
// original storage layout independent of DstackKms so upgrades validate it.
contract LegacyDstackKms is Ownable2StepUpgradeable, UUPSUpgradeable, ERC165Upgradeable {
    struct KmsInfo {
        bytes k256Pubkey;
        bytes caPubkey;
        bytes quote;
        bytes eventlog;
    }

    KmsInfo public kmsInfo;
    string public tproxyAppId;
    mapping(address => bool) public registeredApps;
    mapping(bytes32 => bool) public kmsAllowedAggregatedMrs;
    mapping(bytes32 => bool) public kmsAllowedDeviceIds;
    mapping(bytes32 => bool) public allowedOsImages;
    address public appImplementation;
    uint256[50] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner, address implementation) public initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        __ERC165_init();
        appImplementation = implementation;
    }

    function setKmsInfo(KmsInfo memory info) external onlyOwner {
        kmsInfo = info;
    }

    function _authorizeUpgrade(address) internal override onlyOwner { }
}
