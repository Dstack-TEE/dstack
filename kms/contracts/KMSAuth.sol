// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract KMSAuth {
    // Contract owner
    address public owner;

    struct KmsInfo {
        // App ID of the KMS
        address appId;
        // Root Certificate of the KMS in PEM format
        string rootCert;
        // Root key of the KMS
        bytes32 publicKey;
        // The remote attestation report of the cert and key
        string raReport;
    }

    // KMS information
    KmsInfo public kmsInfo;

    // Struct to store App configuration
    struct AppConfig {
        bool isRegistered;
        mapping(bytes32 => bool) allowedComposeHashes;
        mapping(bytes32 => bool) allowedDeviceIds;
        mapping(bytes32 => bool) allowedImageHashes;
        mapping(bytes32 => bool) allowedMrtds;
    }

    // Mapping of allowed MRTD and image hashes
    mapping(bytes => bool) public allowedMrtds;
    mapping(bytes32 => bool) public allowedImages;
    // Mapping of app ID to its configuration
    mapping(address => AppConfig) public apps;

    // Events
    event MrtdRegistered(bytes indexed mrtd);
    event MrtdDeregistered(bytes indexed mrtd);
    event ImageRegistered(bytes32 indexed imageHash);
    event ImageDeregistered(bytes32 indexed imageHash);
    event AppRegistered(address indexed appId);
    event ComposeHashAdded(address indexed appId, bytes32 composeHash);
    event InstanceIdAdded(address indexed appId, address instanceId);
    event DeviceIdAdded(address indexed appId, bytes32 deviceId);
    event KmsInfoSet(address indexed appId, bytes32 publicKey);

    constructor() {
        owner = msg.sender;
    }

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Set KMS information
    function setKmsInfo(
        address appId,
        string memory rootCert,
        bytes32 publicKey,
        string memory raReport
    ) external onlyOwner {
        kmsInfo.appId = appId;
        kmsInfo.rootCert = rootCert;
        kmsInfo.publicKey = publicKey;
        kmsInfo.raReport = raReport;
        // allow the app id to run
        apps[appId].isRegistered = true;
        emit KmsInfoSet(appId, publicKey);
    }

    // Register a new MRTD
    function registerMrtd(bytes memory mrtd) external onlyOwner {
        allowedMrtds[mrtd] = true;
        emit MrtdRegistered(mrtd);
    }

    // Deregister an MRTD
    function deregisterMrtd(bytes memory mrtd) external onlyOwner {
        allowedMrtds[mrtd] = false;
        emit MrtdDeregistered(mrtd);
    }

    // Register a new image hash
    function registerImage(bytes32 imageHash) external onlyOwner {
        allowedImages[imageHash] = true;
        emit ImageRegistered(imageHash);
    }

    // Deregister an image hash
    function deregisterImage(bytes32 imageHash) external onlyOwner {
        allowedImages[imageHash] = false;
        emit ImageDeregistered(imageHash);
    }

    // Register a new app
    function registerApp(bytes32 salt) external onlyOwner {
        bytes32 fullHash = keccak256(abi.encodePacked(msg.sender, salt));
        address appId = address(uint160(uint256(fullHash))); // Convert to address
        require(!apps[appId].isRegistered, "App already registered");
        apps[appId].isRegistered = true;
        emit AppRegistered(appId);
    }

    // Add allowed compose hash
    function addComposeHash(
        address appId,
        bytes32 composeHash
    ) external onlyOwner {
        require(apps[appId].isRegistered, "App not registered");
        apps[appId].allowedComposeHashes[composeHash] = true;
        emit ComposeHashAdded(appId, composeHash);
    }

    // Add allowed device ID
    function addDeviceId(address appId, bytes32 deviceId) external onlyOwner {
        require(apps[appId].isRegistered, "App not registered");
        apps[appId].allowedDeviceIds[deviceId] = true;
        emit DeviceIdAdded(appId, deviceId);
    }

    // Check if app is allowed to run
    function isAppAllowed(
        address appId,
        bytes32 composeHash,
        address _instanceId,
        bytes32 deviceId,
        bytes32 imageHash,
        bytes memory mrtd,
        bytes memory rtmr0,
        bytes memory rtmr1,
        bytes memory rtmr2,
        bytes memory rtmr3
    ) external view returns (bool allowed, string memory reason) {
        if (!allowedMrtds[mrtd]) {
            return (false, "MRTD not allowed");
        }

        if (!allowedImages[imageHash]) {
            return (false, "Image hash not allowed");
        }

        AppConfig storage app = apps[appId];

        if (!app.isRegistered) {
            return (false, "App not registered");
        }

        if (!app.allowedComposeHashes[composeHash]) {
            return (false, "Compose hash not allowed");
        }

        if (!app.allowedDeviceIds[deviceId]) {
            return (false, "Device ID not allowed");
        }

        return (true, "");
    }

    // Transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner address");
        owner = newOwner;
    }
}
