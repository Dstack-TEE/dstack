// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "./IAppAuth.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract AppAuth is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    IAppAuth
{
    // App ID this contract is managing
    address public appId;

    // Mapping of allowed compose hashes for this app
    mapping(bytes32 => bool) public allowedComposeHashes;

    // State variable to track if upgrades are disabled
    bool private _upgradesDisabled;

    // Whether allow any device to boot this app or only allow devices
    bool public allowAnyDevice;

    // Mapping of allowed device IDs for this app
    mapping(bytes32 => bool) public allowedDeviceIds;

    // Events
    event ComposeHashAdded(bytes32 composeHash);
    event ComposeHashRemoved(bytes32 composeHash);
    event UpgradesDisabled();
    event DeviceAdded(bytes32 deviceId);
    event DeviceRemoved(bytes32 deviceId);
    event AllowAnyDeviceSet(bool allowAny);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Initialize the contract
    function initialize(
        address initialOwner,
        address _appId,
        bool _disableUpgrades,
        bool _allowAnyDevice
    ) public initializer {
        require(initialOwner != address(0), "Invalid owner address");
        require(_appId != address(0), "Invalid app ID");
        appId = _appId;
        _upgradesDisabled = _disableUpgrades;
        allowAnyDevice = _allowAnyDevice;
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
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
    function isAppAllowed(
        IAppAuth.AppBootInfo calldata bootInfo
    ) external view override returns (bool isAllowed, string memory reason) {
        // Check if this controller is responsible for the app
        if (bootInfo.appId != appId) {
            return (false, "Wrong app controller");
        }

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
