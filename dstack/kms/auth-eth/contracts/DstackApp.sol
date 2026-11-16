/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "./IAppAuth.sol";
import "./AuthorizationOperation.sol";
import "./IAppEpochAuth.sol";
import "./TeeVariantPolicy.sol";
import "./IAppEpochManagement.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract DstackApp is
    Initializable,
    Ownable2StepUpgradeable,
    UUPSUpgradeable,
    ERC165Upgradeable,
    IAppAuth,
    IAppEpochAuth,
    IAppEpochManagement
{
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @notice Allowed compose hashes for this app. Epoch 0 only; for other epochs use the *AtEpoch getters and
    /// EpochPolicyChanged.
    mapping(bytes32 => bool) public allowedComposeHashes;

    // State variable to track if upgrades are disabled
    bool private _upgradesDisabled;

    /// @notice Whether any device may boot this app, at every app epoch.
    bool public allowAnyDevice;

    /// @notice Allowed device IDs for this app. Epoch 0 only; for other epochs use the *AtEpoch getters and
    /// EpochPolicyChanged.
    mapping(bytes32 => bool) public allowedDeviceIds;

    // Whether to require TCB status to be UpToDate
    bool public requireTcbUpToDate;

    uint256 public override currentAppEpoch;
    event AppEpochAdvanced(uint256 indexed epoch);

    // Epoch zero continues to use the original fields above after an upgrade.
    mapping(uint256 => mapping(bytes32 => bool)) private _composeHashesByEpoch;
    mapping(uint256 => mapping(bytes32 => bool)) private _deviceIdsByEpoch;

    // The TEE platforms this app may run on.
    TeeVariantPolicy.Policy private _teeVariants;

    /// @notice Whether a boot must present an allowed launch ticket, at every app epoch.
    bool public requireLaunchTicket;
    // Allowed launch tickets, by sha256("dstack-launch-ticket/v1:" || ticket), at every app epoch.
    EnumerableSet.Bytes32Set private _launchTickets;

    event EpochPolicyChanged(bytes32 indexed policy, bytes32 indexed value, uint256 indexed epoch, bool enabled);

    /// @notice Legacy material events. Epoch 0 only; for other epochs use the *AtEpoch getters and EpochPolicyChanged.
    event ComposeHashAdded(bytes32 composeHash);
    event ComposeHashRemoved(bytes32 composeHash);
    event DeviceAdded(bytes32 deviceId);
    event DeviceRemoved(bytes32 deviceId);
    event UpgradesDisabled();
    /// @notice Covers every app epoch; there is no EpochPolicyChanged counterpart.
    event AllowAnyDeviceSet(bool allowAny);
    event AllowAnyTeeVariantSet(bool allowAny);
    event AllowedTeeVariantsSet(string[] teeVariants);
    event RequireTcbUpToDateSet(bool requireUpToDate);
    event RequireLaunchTicketSet(bool required);
    event LaunchTicketAdded(bytes32 indexed ticketHash, string label);
    event LaunchTicketRemoved(bytes32 indexed ticketHash);
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
        return interfaceId == type(IAppEpochAuth).interfaceId || interfaceId == type(IAppEpochManagement).interfaceId
            || interfaceId == 0x1e079198 // IAppAuth
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

    // A request may select any app epoch up to the current one and is decided
    // on that epoch's row, so revoking a value takes every row that allows it:
    // 0 through currentAppEpoch.
    function _setAtEpochs(
        function(uint256, bytes32, bool) internal setter,
        uint256 fromEpoch,
        uint256 toEpoch,
        bytes32 value,
        bool allowed
    )
        private
    {
        require(fromEpoch <= toEpoch, "Invalid app epoch range");
        for (uint256 epoch = fromEpoch; epoch <= toEpoch; ++epoch) {
            setter(epoch, value, allowed);
        }
    }

    function addComposeHashAtEpoch(uint256 epoch, bytes32 composeHash) public onlyOwner {
        require(composeHash != bytes32(0), "invalid compose hash");
        _setComposeHash(epoch, composeHash, true);
    }

    function addComposeHashAtEpochs(uint256 fromEpoch, uint256 toEpoch, bytes32 composeHash) external onlyOwner {
        require(composeHash != bytes32(0), "invalid compose hash");
        _setAtEpochs(_setComposeHash, fromEpoch, toEpoch, composeHash, true);
    }

    function removeComposeHashAtEpoch(uint256 epoch, bytes32 composeHash) public onlyOwner {
        _setComposeHash(epoch, composeHash, false);
    }

    function removeComposeHashAtEpochs(uint256 fromEpoch, uint256 toEpoch, bytes32 composeHash) external onlyOwner {
        _setAtEpochs(_setComposeHash, fromEpoch, toEpoch, composeHash, false);
    }

    function _requireWritableEpoch(uint256 epoch) private view {
        require(epoch <= currentAppEpoch + 1, "Unknown app epoch");
    }

    function _setComposeHash(uint256 epoch, bytes32 composeHash, bool allowed) private {
        _requireWritableEpoch(epoch);
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

    // Covers every app epoch: restricting devices is a decision about hosts, not
    // key generations, and must not leave an older epoch open to any host.
    function setAllowAnyDevice(bool allowed) external onlyOwner {
        allowAnyDevice = allowed;
        emit AllowAnyDeviceSet(allowed);
        _emitPolicy("allow-any-device", bytes32(0), allowed);
    }

    /// @notice Whether this app may run on any TEE platform, rather than only on
    /// {allowedTeeVariants}. Covers every app epoch.
    function allowAnyTeeVariant() public view returns (bool) {
        return !_teeVariants.restricted;
    }

    /// @notice The TEE platforms, named as the KMS reports them, this app may run on
    /// unless {allowAnyTeeVariant}.
    function allowedTeeVariants() external view returns (string[] memory) {
        return TeeVariantPolicy.allowedNames(_teeVariants);
    }

    function setAllowAnyTeeVariant(bool allowed) external onlyOwner {
        _teeVariants.restricted = !allowed;
        emit AllowAnyTeeVariantSet(allowed);
        _emitPolicy("allow-any-tee-variant", bytes32(0), allowed);
    }

    function setAllowedTeeVariants(string[] calldata teeVariants) external onlyOwner {
        uint64 mask = TeeVariantPolicy.setAllowed(_teeVariants, teeVariants);
        emit AllowedTeeVariantsSet(teeVariants);
        _emitPolicy("allowed-tee-variants", bytes32(uint256(mask)), true);
    }

    // Set whether TCB status must be UpToDate to boot this app
    function setRequireTcbUpToDate(bool _requireUpToDate) external onlyOwner {
        requireTcbUpToDate = _requireUpToDate;
        emit RequireTcbUpToDateSet(_requireUpToDate);
        _emitPolicy("require-tcb-up-to-date", bytes32(0), _requireUpToDate);
    }

    function setRequireLaunchTicket(bool required) external onlyOwner {
        requireLaunchTicket = required;
        emit RequireLaunchTicketSet(required);
        _emitPolicy("require-launch-ticket", bytes32(0), required);
    }

    /// @notice Allow a launch ticket. The label is public and only logged.
    function addLaunchTicket(bytes32 ticketHash, string calldata label) external onlyOwner {
        require(ticketHash != bytes32(0), "invalid launch ticket hash");
        _launchTickets.add(ticketHash);
        emit LaunchTicketAdded(ticketHash, label);
        _emitPolicy("launch-ticket", ticketHash, true);
    }

    function removeLaunchTicket(bytes32 ticketHash) external onlyOwner {
        _launchTickets.remove(ticketHash);
        emit LaunchTicketRemoved(ticketHash);
        _emitPolicy("launch-ticket", ticketHash, false);
    }

    /// @notice The allowed launch tickets; their labels are in {LaunchTicketAdded}.
    function launchTickets() external view returns (bytes32[] memory) {
        return _launchTickets.values();
    }

    function addDeviceAtEpoch(uint256 epoch, bytes32 deviceId) public onlyOwner {
        require(deviceId != bytes32(0), "invalid device ID");
        _setDevice(epoch, deviceId, true);
    }

    function addDeviceAtEpochs(uint256 fromEpoch, uint256 toEpoch, bytes32 deviceId) external onlyOwner {
        require(deviceId != bytes32(0), "invalid device ID");
        _setAtEpochs(_setDevice, fromEpoch, toEpoch, deviceId, true);
    }

    function removeDeviceAtEpoch(uint256 epoch, bytes32 deviceId) public onlyOwner {
        _setDevice(epoch, deviceId, false);
    }

    function removeDeviceAtEpochs(uint256 fromEpoch, uint256 toEpoch, bytes32 deviceId) external onlyOwner {
        _setAtEpochs(_setDevice, fromEpoch, toEpoch, deviceId, false);
    }

    function _setDevice(uint256 epoch, bytes32 deviceId, bool allowed) private {
        _requireWritableEpoch(epoch);
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

    // Legacy callers derive epoch-zero keys from this bool, so once the app epoch
    // advances they are refused rather than handed keys the owner is retiring.
    function isAppAllowed(IAppAuth.AppInfo calldata bootInfo)
        external
        view
        override
        returns (bool isAllowed, string memory reason)
    {
        if (currentAppEpoch != 0) return (false, "App epoch requires epoch-aware authorization");
        // Legacy callers report no platform and no launch ticket, so only a policy
        // restricting neither admits them.
        return _authorizeApp(bootInfo, allowAnyTeeVariant(), 0, bytes32(0));
    }

    /// Decide the request at the selected app epoch; the KMS fills gateway and root fields.
    function authorizeApp(AuthorizationRequest calldata request)
        external
        view
        override
        returns (AuthorizationResult memory result)
    {
        result.currentAppEpoch = currentAppEpoch;
        if (!AuthorizationOperation.isApp(request.operation)) {
            result.rejectionReason = "Invalid authorization operation";
            return result;
        }
        uint256 appEpoch = request.requestedAppEpoch.isSet ? request.requestedAppEpoch.value : currentAppEpoch;
        (result.authorized, result.rejectionReason) = _authorizeApp(
            request.appInfo,
            TeeVariantPolicy.admits(_teeVariants, request.teeVariant),
            appEpoch,
            request.launchTicketHash
        );
    }

    function _authorizeApp(
        IAppAuth.AppInfo calldata bootInfo,
        bool teeVariantAllowed,
        uint256 appEpoch,
        bytes32 launchTicketHash
    )
        private
        view
        returns (bool, string memory)
    {
        if (requireLaunchTicket && !_launchTickets.contains(launchTicketHash)) {
            return (false, "Invalid launch ticket");
        }
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
        if (!allowAnyDevice && !allowedDeviceIdsAtEpoch(appEpoch, bootInfo.deviceId)) {
            return (false, "Device not allowed");
        }

        if (!teeVariantAllowed) {
            return (false, "TEE variant not allowed");
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
    uint256[42] private __gap;
}
