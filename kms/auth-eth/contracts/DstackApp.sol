/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "./IAppAuth.sol";
import "./IAppAuthBasicManagement.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";

contract DstackApp is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ERC165Upgradeable,
    IAppAuth,
    IAppAuthBasicManagement
{
    // Mapping of allowed compose hashes for this app
    mapping(bytes32 => bool) public allowedComposeHashes;

    // State variable to track if upgrades are disabled
    bool private _upgradesDisabled;

    // Whether allow any device to boot this app or only allow devices
    bool public allowAnyDevice;

    // Mapping of allowed device IDs for this app
    mapping(bytes32 => bool) public allowedDeviceIds;

    // Additional events specific to DstackApp
    event UpgradesDisabled();
    event AllowAnyDeviceSet(bool allowAny);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Initialize the contract
    function initialize(
        address initialOwner,
        bool _disableUpgrades,
        bool _allowAnyDevice,
        bytes32 initialDeviceId,
        bytes32 initialComposeHash
    )
        public
        initializer
    {
        require(initialOwner != address(0), "invalid owner address");

        _upgradesDisabled = _disableUpgrades;
        allowAnyDevice = _allowAnyDevice;

        // Add initial device if provided
        if (initialDeviceId != bytes32(0)) {
            allowedDeviceIds[initialDeviceId] = true;
            emit DeviceAdded(initialDeviceId);
        }

        // Add initial compose hash if provided
        if (initialComposeHash != bytes32(0)) {
            allowedComposeHashes[initialComposeHash] = true;
            emit ComposeHashAdded(initialComposeHash);
        }

        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        __ERC165_init();
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     * @notice Returns true if this contract implements the interface defined by interfaceId
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return True if the contract implements `interfaceId`
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165Upgradeable, IERC165)
        returns (bool)
    {
        return interfaceId == 0x1e079198 // IAppAuth
            || interfaceId == 0x8fd37527 // IAppAuthBasicManagement
            || super.supportsInterface(interfaceId);
    }

    // Function to authorize upgrades (required by UUPSUpgradeable)
    function _authorizeUpgrade(address) internal view override onlyOwner {
        require(!_upgradesDisabled, "Upgrades are permanently disabled");
    }

    // Add a compose hash to allowed list
    function addComposeHash(bytes32 composeHash) external onlyOwner {
        allowedComposeHashes[composeHash] = true;
        emit ComposeHashAdded(composeHash);
    }

    // Remove a compose hash from allowed list
    function removeComposeHash(bytes32 composeHash) external onlyOwner {
        allowedComposeHashes[composeHash] = false;
        emit ComposeHashRemoved(composeHash);
    }

    // Set whether any device is allowed to boot this app
    function setAllowAnyDevice(bool _allowAnyDevice) external onlyOwner {
        allowAnyDevice = _allowAnyDevice;
        emit AllowAnyDeviceSet(_allowAnyDevice);
    }

    // Add a device ID to allowed list
    function addDevice(bytes32 deviceId) external onlyOwner {
        allowedDeviceIds[deviceId] = true;
        emit DeviceAdded(deviceId);
    }

    // Remove a device ID from allowed list
    function removeDevice(bytes32 deviceId) external onlyOwner {
        allowedDeviceIds[deviceId] = false;
        emit DeviceRemoved(deviceId);
    }

    // Check if an app is allowed to boot
    function isAppAllowed(IAppAuth.AppBootInfo calldata bootInfo)
        external
        view
        override
        returns (bool isAllowed, string memory reason)
    {
        // Check if compose hash is allowed
        if (!allowedComposeHashes[bootInfo.composeHash]) {
            return (false, "Compose hash not allowed");
        }

        // Check if device is allowed (when device restriction is enabled)
        if (!allowAnyDevice && !allowedDeviceIds[bootInfo.deviceId]) {
            return (false, "Device not allowed");
        }

        return (true, "");
    }

    // Function to permanently disable upgrades
    function disableUpgrades() external onlyOwner {
        _upgradesDisabled = true;
        emit UpgradesDisabled();
    }

    // Add storage gap for upgradeable contracts
    uint256[50] private __gap;
}
