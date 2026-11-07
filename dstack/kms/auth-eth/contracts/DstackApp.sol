/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "./IAppAuth.sol";
import "./IAppEpoch.sol";
import "./IAppEpochAuth.sol";
import "./IAppAuthBasicManagement.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";

contract DstackApp is
    Initializable,
    Ownable2StepUpgradeable,
    UUPSUpgradeable,
    ERC165Upgradeable,
    IAppAuth,
    IAppAuthBasicManagement,
    IAppEpoch,
    IAppEpochAuth
{
    // Mapping of allowed compose hashes for this app
    mapping(bytes32 => bool) public allowedComposeHashes;

    // State variable to track if upgrades are disabled
    bool private _upgradesDisabled;

    // Whether allow any device to boot this app or only allow devices
    bool public allowAnyDevice;

    // Mapping of allowed device IDs for this app
    mapping(bytes32 => bool) public allowedDeviceIds;

    // Whether to require TCB status to be UpToDate
    bool public requireTcbUpToDate;

    uint256 public override currentAppEpoch;
    event AppEpochAdvanced(uint256 indexed epoch);

    // Epoch zero continues to use the original fields above after an upgrade.
    mapping(uint256 => mapping(bytes32 => bool)) private _composeHashesByEpoch;
    mapping(uint256 => mapping(bytes32 => bool)) private _deviceIdsByEpoch;
    mapping(uint256 => bool) private _allowAnyDeviceByEpoch;

    event EpochPolicyChanged(bytes32 indexed policy, bytes32 indexed value, uint256 indexed epoch, bool enabled);

    // Additional events specific to DstackApp
    event UpgradesDisabled();
    event AllowAnyDeviceSet(bool allowAny);
    event RequireTcbUpToDateSet(bool requireUpToDate);
    /// @notice Additive audit event for reconstructing authorization policy.
    event PolicyChanged(address indexed actor, bytes32 indexed policy, bytes32 indexed value, bool enabled);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Old initialize — preserved for upgrade compatibility
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
        _initializeCommon(initialOwner, _disableUpgrades, _allowAnyDevice, initialDeviceId, initialComposeHash);
    }

    // New initialize — includes requireTcbUpToDate
    function initialize(
        address initialOwner,
        bool _disableUpgrades,
        bool _requireTcbUpToDate,
        bool _allowAnyDevice,
        bytes32 initialDeviceId,
        bytes32 initialComposeHash
    )
        public
        initializer
    {
        requireTcbUpToDate = _requireTcbUpToDate;
        _initializeCommon(initialOwner, _disableUpgrades, _allowAnyDevice, initialDeviceId, initialComposeHash);
    }

    function _initializeCommon(
        address initialOwner,
        bool _disableUpgrades,
        bool _allowAnyDevice,
        bytes32 initialDeviceId,
        bytes32 initialComposeHash
    )
        internal
    {
        require(initialOwner != address(0), "invalid owner address");

        _upgradesDisabled = _disableUpgrades;
        allowAnyDevice = _allowAnyDevice;

        // Add initial device if provided
        if (initialDeviceId != bytes32(0)) {
            allowedDeviceIds[initialDeviceId] = true;
            emit DeviceAdded(initialDeviceId);
            _emitPolicy("device", initialDeviceId, true);
        }

        // Add initial compose hash if provided
        if (initialComposeHash != bytes32(0)) {
            allowedComposeHashes[initialComposeHash] = true;
            emit ComposeHashAdded(initialComposeHash);
            _emitPolicy("compose-hash", initialComposeHash, true);
        }

        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        __ERC165_init();
    }

    function version() public pure returns (uint256) {
        return 2;
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
        return interfaceId == type(IAppEpochAuth).interfaceId || interfaceId == type(IAppEpoch).interfaceId
            || interfaceId == 0x1e079198 // IAppAuth
            || interfaceId == 0x8fd37527 // IAppAuthBasicManagement
            || super.supportsInterface(interfaceId);
    }

    // Function to authorize upgrades (required by UUPSUpgradeable)
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        require(!_upgradesDisabled, "Upgrades are permanently disabled");
        _emitPolicy("implementation-upgrade", bytes32(uint256(uint160(newImplementation))), true);
    }

    function _emitPolicy(string memory policy, bytes32 value, bool enabled) internal {
        emit PolicyChanged(msg.sender, keccak256(bytes(policy)), value, enabled);
    }

    function allowedComposeHashesAtEpoch(uint256 epoch, bytes32 composeHash) public view returns (bool) {
        return epoch == 0 ? allowedComposeHashes[composeHash] : _composeHashesByEpoch[epoch][composeHash];
    }

    function allowedDeviceIdsAtEpoch(uint256 epoch, bytes32 deviceId) public view returns (bool) {
        return epoch == 0 ? allowedDeviceIds[deviceId] : _deviceIdsByEpoch[epoch][deviceId];
    }

    function allowAnyDeviceAtEpoch(uint256 epoch) public view returns (bool) {
        return epoch == 0 ? allowAnyDevice : _allowAnyDeviceByEpoch[epoch];
    }

    function addComposeHash(bytes32 composeHash) external {
        addComposeHashAtEpoch(currentAppEpoch, composeHash);
    }

    function addComposeHashAtEpoch(uint256 epoch, bytes32 composeHash) public onlyOwner {
        require(composeHash != bytes32(0), "invalid compose hash");
        _setComposeHash(epoch, composeHash, true);
    }

    function removeComposeHash(bytes32 composeHash) external {
        removeComposeHashAtEpoch(currentAppEpoch, composeHash);
    }

    function removeComposeHashAtEpoch(uint256 epoch, bytes32 composeHash) public onlyOwner {
        _setComposeHash(epoch, composeHash, false);
    }

    function _setComposeHash(uint256 epoch, bytes32 composeHash, bool allowed) private {
        require(epoch <= currentAppEpoch, "Unknown app epoch");
        if (epoch == 0) {
            allowedComposeHashes[composeHash] = allowed;
            if (allowed) emit ComposeHashAdded(composeHash);
            else emit ComposeHashRemoved(composeHash);
            _emitPolicy("compose-hash", composeHash, allowed);
        } else {
            _composeHashesByEpoch[epoch][composeHash] = allowed;
        }
        emit EpochPolicyChanged(keccak256("compose-hash"), composeHash, epoch, allowed);
    }

    function setAllowAnyDevice(bool allowed) external {
        setAllowAnyDeviceAtEpoch(currentAppEpoch, allowed);
    }

    function setAllowAnyDeviceAtEpoch(uint256 epoch, bool allowed) public onlyOwner {
        require(epoch <= currentAppEpoch, "Unknown app epoch");
        if (epoch == 0) {
            allowAnyDevice = allowed;
            emit AllowAnyDeviceSet(allowed);
            _emitPolicy("allow-any-device", bytes32(0), allowed);
        } else {
            _allowAnyDeviceByEpoch[epoch] = allowed;
        }
        emit EpochPolicyChanged(keccak256("allow-any-device"), bytes32(0), epoch, allowed);
    }

    // Set whether TCB status must be UpToDate to boot this app
    function setRequireTcbUpToDate(bool _requireUpToDate) external onlyOwner {
        requireTcbUpToDate = _requireUpToDate;
        emit RequireTcbUpToDateSet(_requireUpToDate);
        _emitPolicy("require-tcb-up-to-date", bytes32(0), _requireUpToDate);
    }

    function addDevice(bytes32 deviceId) external {
        addDeviceAtEpoch(currentAppEpoch, deviceId);
    }

    function addDeviceAtEpoch(uint256 epoch, bytes32 deviceId) public onlyOwner {
        require(deviceId != bytes32(0), "invalid device ID");
        _setDevice(epoch, deviceId, true);
    }

    function removeDevice(bytes32 deviceId) external {
        removeDeviceAtEpoch(currentAppEpoch, deviceId);
    }

    function removeDeviceAtEpoch(uint256 epoch, bytes32 deviceId) public onlyOwner {
        _setDevice(epoch, deviceId, false);
    }

    function _setDevice(uint256 epoch, bytes32 deviceId, bool allowed) private {
        require(epoch <= currentAppEpoch, "Unknown app epoch");
        if (epoch == 0) {
            allowedDeviceIds[deviceId] = allowed;
            if (allowed) emit DeviceAdded(deviceId);
            else emit DeviceRemoved(deviceId);
            _emitPolicy("device", deviceId, allowed);
        } else {
            _deviceIdsByEpoch[epoch][deviceId] = allowed;
        }
        emit EpochPolicyChanged(keccak256("device"), deviceId, epoch, allowed);
    }

    // Legacy callers authorize the current epoch, never an older policy implicitly.
    function isAppAllowed(IAppAuth.AppInfo calldata bootInfo)
        external
        view
        override
        returns (bool isAllowed, string memory reason)
    {
        return _isAppAllowedAtEpoch(bootInfo, currentAppEpoch);
    }

    function isAppAllowedAtEpoch(
        IAppAuth.AppInfo calldata bootInfo,
        uint256 appEpoch
    )
        external
        view
        override
        returns (bool isAllowed, string memory reason)
    {
        return _isAppAllowedAtEpoch(bootInfo, appEpoch);
    }

    function _isAppAllowedAtEpoch(
        IAppAuth.AppInfo calldata bootInfo,
        uint256 appEpoch
    )
        private
        view
        returns (bool, string memory)
    {
        if (appEpoch > currentAppEpoch) return (false, "Requested app epoch is not active");
        // Optionally require TCB status to be up to date
        if (
            requireTcbUpToDate
                && keccak256(abi.encodePacked(bootInfo.tcbStatus)) != keccak256(abi.encodePacked("UpToDate"))
        ) {
            return (false, "TCB status is not up to date");
        }

        // Check if compose hash is allowed
        if (!allowedComposeHashesAtEpoch(appEpoch, bootInfo.composeHash)) {
            return (false, "Compose hash not allowed");
        }

        // Check if device is allowed (when device restriction is enabled)
        if (!allowAnyDeviceAtEpoch(appEpoch) && !allowedDeviceIdsAtEpoch(appEpoch, bootInfo.deviceId)) {
            return (false, "Device not allowed");
        }

        return (true, "");
    }

    /// Advance only from the epoch the owner intended, rejecting stale transactions.
    function advanceAppEpoch(uint256 expectedCurrentEpoch) external onlyOwner {
        require(currentAppEpoch == expectedCurrentEpoch, "App epoch changed");
        require(currentAppEpoch < type(uint32).max, "App epoch exhausted");
        currentAppEpoch++;
        emit AppEpochAdvanced(currentAppEpoch);
        _emitPolicy("app-epoch", bytes32(currentAppEpoch), true);
    }

    // Function to permanently disable upgrades
    function disableUpgrades() external onlyOwner {
        _upgradesDisabled = true;
        emit UpgradesDisabled();
        _emitPolicy("upgrades-disabled", bytes32(0), true);
    }

    // Add storage gap for upgradeable contracts
    uint256[45] private __gap;
}
