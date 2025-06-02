// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "./IAppAuth.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract KmsAuth is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
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
    /// @custom:oz-renamed-from tproxyAppId
    string public gatewayAppId;

    // Struct to store App configuration
    struct AppConfig {
        bool isRegistered;
        address controller;
    }

    // Mapping of registered apps
    mapping(address => AppConfig) public apps;

    // Mapping of allowed aggregated MR measurements for running KMS
    mapping(bytes32 => bool) public kmsAllowedAggregatedMrs;

    // Mapping of allowed KMS device IDs
    mapping(bytes32 => bool) public kmsAllowedDeviceIds;

    // Mapping of allowed image measurements
    mapping(bytes32 => bool) public allowedOsImages;

    // Sequence number for app IDs - per user
    mapping(address => uint256) public nextAppSequence;

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

    // Function to set KMS quote
    function setKmsQuote(bytes memory quote) external onlyOwner {
        kmsInfo.quote = quote;
    }

    // Function to set KMS eventlog
    function setKmsEventlog(bytes memory eventlog) external onlyOwner {
        kmsInfo.eventlog = eventlog;
    }

    // Function to set trusted Gateway App ID
    function setGatewayAppId(string memory appId) external onlyOwner {
        gatewayAppId = appId;
        emit GatewayAppIdSet(appId);
    }

    // View next app id
    function nextAppId() public view returns (address appId) {
        bytes32 fullHash = keccak256(
            abi.encodePacked(
                address(this),
                msg.sender,
                nextAppSequence[msg.sender]
            )
        );
        return address(uint160(uint256(fullHash)));
    }

    // Function to register an app
    function registerApp(address controller) external {
        require(controller != address(0), "Invalid controller address");
        address appId = nextAppId();
        require(!apps[appId].isRegistered, "App already registered");
        apps[appId].isRegistered = true;
        apps[appId].controller = controller;
        nextAppSequence[msg.sender]++;
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

    // Function to check if KMS is allowed to boot
    function isKmsAllowed(
        AppBootInfo calldata bootInfo
    ) external view returns (bool isAllowed, string memory reason) {
        // Check if the TCB status is up to date
        if (
            keccak256(abi.encodePacked(bootInfo.tcbStatus)) !=
            keccak256(abi.encodePacked("UpToDate"))
        ) {
            return (false, "TCB status is not up to date");
        }

        // Check if the OS image is allowed
        if (!allowedOsImages[bootInfo.osImageHash]) {
            return (false, "OS image is not allowed");
        }

        // Check if the aggregated MR is allowed
        if (!kmsAllowedAggregatedMrs[bootInfo.mrAggregated]) {
            return (false, "Aggregated MR not allowed");
        }

        // Check if the KMS device ID is allowed
        if (!kmsAllowedDeviceIds[bootInfo.deviceId]) {
            return (false, "KMS is not allowed to boot on this device");
        }

        return (true, "");
    }

    // Function to check if an app is allowed to boot
    function isAppAllowed(
        AppBootInfo calldata bootInfo
    ) external view override returns (bool isAllowed, string memory reason) {
        // Check if app is registered
        if (!apps[bootInfo.appId].isRegistered) {
            return (false, "App not registered");
        }

        // Check aggregated MR and image measurements
        if (!allowedOsImages[bootInfo.osImageHash]) {
            return (false, "OS image is not allowed");
        }

        // Ask the app controller if the app is allowed to boot
        address controller = apps[bootInfo.appId].controller;
        if (controller == address(0)) {
            return (false, "App controller not set");
        }
        return IAppAuth(controller).isAppAllowed(bootInfo);
    }

    // Add storage gap for upgradeable contracts
    uint256[50] private __gap;
}
