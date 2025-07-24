// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "../IAppAuth.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";

contract DstackKmsV1 is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ERC165Upgradeable,
    IAppAuth
{
    // Struct for KMS information
    struct KmsInfo {
        bytes k256Pubkey;
        bytes caPubkey;
        bytes quote;
        bytes eventlog;
    }

    // KMS information
    KmsInfo public kmsInfo;

    // The dstack-gateway App ID
    string public gatewayAppId;

    // Mapping of registered apps
    mapping(address => bool) public registeredApps;

    // Mapping of allowed aggregated MR measurements for running KMS
    mapping(bytes32 => bool) public kmsAllowedAggregatedMrs;

    // Mapping of allowed KMS device IDs
    mapping(bytes32 => bool) public kmsAllowedDeviceIds;

    // Mapping of allowed image measurements
    mapping(bytes32 => bool) public allowedOsImages;

    // Events
    event AppRegistered(address appId);
    event KmsInfoSet(bytes k256Pubkey);
    event KmsAggregatedMrAdded(bytes32 mrAggregated);
    event KmsAggregatedMrRemoved(bytes32 mrAggregated);
    event KmsDeviceAdded(bytes32 deviceId);
    event KmsDeviceRemoved(bytes32 deviceId);
    event OsImageHashAdded(bytes32 osImageHash);
    event OsImageHashRemoved(bytes32 osImageHash);
    event GatewayAppIdSet(string gatewayAppId);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Initialize the contract with the owner wallet address
    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        __ERC165_init();
    }

    function isContract(address addr) internal view returns (bool){
        uint32 size;
        assembly {
            size := extcodesize(addr)
        }
        return (size > 0);
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165Upgradeable, IERC165)
        returns (bool)
    {
        return
            interfaceId == 0x1e079198 || // IAppAuth
            super.supportsInterface(interfaceId);
    }

    // Function to authorize upgrades (required by UUPSUpgradeable)
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // Function to set KMS information
    function setKmsInfo(KmsInfo memory info) external onlyOwner {
        kmsInfo = info;
        emit KmsInfoSet(info.k256Pubkey);
    }

    // Function to set trusted Gateway App ID
    function setGatewayAppId(string memory appId) external onlyOwner {
        gatewayAppId = appId;
        emit GatewayAppIdSet(appId);
    }

    // Function to register an app
    function registerApp(address appId) public {
        require(appId != address(0), "Invalid app ID");
        registeredApps[appId] = true;
        emit AppRegistered(appId);
    }

    // Function to register an aggregated MR measurement
    function addKmsAggregatedMr(bytes32 mrAggregated) external onlyOwner {
        kmsAllowedAggregatedMrs[mrAggregated] = true;
        emit KmsAggregatedMrAdded(mrAggregated);
    }

    // Function to deregister an aggregated MR measurement
    function removeKmsAggregatedMr(bytes32 mrAggregated) external onlyOwner {
        kmsAllowedAggregatedMrs[mrAggregated] = false;
        emit KmsAggregatedMrRemoved(mrAggregated);
    }

    // Function to register a KMS device ID
    function addKmsDevice(bytes32 deviceId) external onlyOwner {
        kmsAllowedDeviceIds[deviceId] = true;
        emit KmsDeviceAdded(deviceId);
    }

    // Function to deregister a KMS device ID
    function removeKmsDevice(bytes32 deviceId) external onlyOwner {
        kmsAllowedDeviceIds[deviceId] = false;
        emit KmsDeviceRemoved(deviceId);
    }

    // Function to register an image measurement
    function addOsImageHash(bytes32 osImageHash) external onlyOwner {
        allowedOsImages[osImageHash] = true;
        emit OsImageHashAdded(osImageHash);
    }

    // Function to deregister an image measurement
    function removeOsImageHash(bytes32 osImageHash) external onlyOwner {
        allowedOsImages[osImageHash] = false;
        emit OsImageHashRemoved(osImageHash);
    }

    // Function to check if an app is allowed to boot
    function isAppAllowed(
        AppBootInfo calldata bootInfo
    ) external view override returns (bool isAllowed, string memory reason) {
        // Check if app is registered
        if (!registeredApps[bootInfo.appId]) {
            return (false, "App not registered");
        }
        // Check if the OS image is allowed
        if (!allowedOsImages[bootInfo.osImageHash]) {
            return (false, "OS image is not allowed");
        }

        // Check if the contract exists at the appId address
        if (!isContract(bootInfo.appId)) {
            return (false, "App not deployed or invalid address");
        }

        // Call the app's isAppAllowed function
        return IAppAuth(bootInfo.appId).isAppAllowed(bootInfo);
    }

    // Add storage gap for upgradeable contracts
    uint256[50] private __gap;
}