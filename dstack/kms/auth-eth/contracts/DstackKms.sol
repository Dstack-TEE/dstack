/*
 * SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "./IAppAuth.sol";
import "./AuthorizationOperation.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DstackKms is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable, ERC165Upgradeable, IAppAuth {
    struct OptionalUint256 {
        bool isSet;
        uint256 value;
    }

    struct AuthorizationRequest {
        AppInfo appInfo;
        bytes32 operation;
        // Reserved for application key rotation; only zero is currently supported.
        OptionalUint256 requestedAppEpoch;
        OptionalUint256 requestedRootEpoch;
    }

    struct AuthorizationResult {
        bool isAllowed;
        string rejectionReason;
        string gatewayAppId;
        uint256 currentRootEpoch;
        bytes32 currentRootEpochHash;
        uint256 currentAppEpoch;
    }

    // Struct for KMS information
    struct KmsInfo {
        bytes k256Pubkey;
        bytes caPubkey;
        bytes quote;
        bytes eventlog;
    }

    // Retained for proxy storage compatibility and legacy readers. Only root
    // epoch registration and activation may update this identity.
    KmsInfo public kmsInfo;

    // The dstack-gateway App ID
    /// @custom:oz-renamed-from tproxyAppId
    string public gatewayAppId;

    // Mapping of registered apps
    mapping(address => bool) public registeredApps;

    // Mapping of allowed aggregated MR measurements for running KMS
    mapping(bytes32 => bool) public kmsAllowedAggregatedMrs;

    // Mapping of allowed KMS device IDs
    mapping(bytes32 => bool) public kmsAllowedDeviceIds;

    // Mapping of allowed image measurements
    mapping(bytes32 => bool) public allowedOsImages;

    // DstackApp implementation contract address for factory deployment
    address public appImplementation;

    // DER SubjectPublicKeyInfo prefix of a P-256 key with an uncompressed point;
    // the 64 bytes of the point follow.
    bytes27 private constant P256_SPKI_PREFIX = 0x3059301306072a8648ce3d020106082a8648ce3d03010703420004;

    struct RootEpoch {
        bytes caPubkey;
        bytes k256Pubkey;
        // Where to fetch the generating KMS's attestation. Its report data binds
        // the epoch and both public keys, so the evidence proves itself: anyone
        // can check the keys came from an approved KMS in a TEE.
        string evidenceUrl;
        // Commits to the public keys of this epoch and every earlier one:
        // keccak256(previous chainHash || keccak256(caPubkey) ||
        // keccak256(k256Pubkey)), with a zero previous hash for epoch 0.
        bytes32 chainHash;
    }

    // Root keys of each KMS root epoch, indexed by epoch; epoch 0 is the
    // original roots. Append-only: a registered epoch is never changed.
    RootEpoch[] private _rootEpochs;

    // The epoch KMS instances serve. Registering epoch 0 makes it current;
    // later epochs take effect only when activated, one at a time.
    uint256 private _currentRootEpoch;

    // Events
    // appId is unindexed for backward compatibility with deployed log indexers.
    // slither-disable-next-line unindexed-event-address
    event AppRegistered(address appId);
    event KmsInfoSet(bytes k256Pubkey);
    event KmsAggregatedMrAdded(bytes32 mrAggregated);
    event KmsAggregatedMrRemoved(bytes32 mrAggregated);
    event KmsDeviceAdded(bytes32 deviceId);
    event KmsDeviceRemoved(bytes32 deviceId);
    event OsImageHashAdded(bytes32 osImageHash);
    event OsImageHashRemoved(bytes32 osImageHash);
    event GatewayAppIdSet(string gatewayAppId);
    // slither-disable-next-line unindexed-event-address
    event AppImplementationSet(address implementation);
    event RootEpochRegistered(
        uint256 indexed epoch, bytes32 chainHash, bytes caPubkey, bytes k256Pubkey, string evidenceUrl
    );
    event RootEpochActivated(uint256 indexed epoch);
    event RootEpochPopped(uint256 indexed epoch, bytes32 chainHash);
    event RootEpochEvidenceUrlSet(uint256 indexed epoch, string evidenceUrl);
    event AppDeployedViaFactory(address indexed appId, address indexed deployer);
    /// @notice Additive audit event for reconstructing authorization policy.
    /// @dev `value` is the affected bytes32 value, address, or hash of dynamic public data.
    event PolicyChanged(address indexed actor, bytes32 indexed policy, bytes32 indexed value, bool enabled);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Initialize the contract with the owner wallet address and optionally set DstackApp implementation
    function initialize(address initialOwner, address _appImplementation) public initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        __ERC165_init();

        // Set DstackApp implementation if provided
        if (_appImplementation != address(0)) {
            appImplementation = _appImplementation;
            emit AppImplementationSet(_appImplementation);
            _emitPolicy("app-implementation", bytes32(uint256(uint160(_appImplementation))), true);
        }
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
            || super.supportsInterface(interfaceId);
    }

    // Function to authorize upgrades (required by UUPSUpgradeable)
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        _emitPolicy("implementation-upgrade", bytes32(uint256(uint160(newImplementation))), true);
    }

    function _emitPolicy(string memory policy, bytes32 value, bool enabled) internal {
        emit PolicyChanged(msg.sender, keccak256(bytes(policy)), value, enabled);
    }

    // Register the root public keys of the next KMS root epoch, with where to
    // fetch the attestation proving where they were generated. It is not served until
    // activated, except epoch 0, which is current from the start and must be
    // the kmsInfo keys when those are set.
    function registerRootEpoch(
        // P-256 DER SubjectPublicKeyInfo, uncompressed (91 bytes)
        bytes calldata caPubkey,
        // secp256k1 SEC1 compressed (33 bytes)
        bytes calldata k256Pubkey,
        string calldata evidenceUrl
    )
        external
        onlyOwner
        returns (uint256 epoch)
    {
        require(caPubkey.length == 91 && bytes27(caPubkey[:27]) == P256_SPKI_PREFIX, "Invalid epoch CA public key");
        require(
            k256Pubkey.length == 33 && (k256Pubkey[0] == 0x02 || k256Pubkey[0] == 0x03), "Invalid epoch k256 public key"
        );
        require(bytes(evidenceUrl).length > 0, "Empty epoch evidence URL");
        epoch = _rootEpochs.length;
        if (epoch == 0 && kmsInfo.k256Pubkey.length > 0) {
            require(
                keccak256(caPubkey) == keccak256(kmsInfo.caPubkey)
                    && keccak256(k256Pubkey) == keccak256(kmsInfo.k256Pubkey),
                "Epoch 0 keys differ from kmsInfo"
            );
        }
        bytes32 previous = epoch == 0 ? bytes32(0) : _rootEpochs[epoch - 1].chainHash;
        bytes32 chainHash = keccak256(abi.encodePacked(previous, keccak256(caPubkey), keccak256(k256Pubkey)));
        _rootEpochs.push(RootEpoch(caPubkey, k256Pubkey, evidenceUrl, chainHash));
        emit RootEpochRegistered(epoch, chainHash, caPubkey, k256Pubkey, evidenceUrl);
        _emitPolicy("root-epoch", chainHash, true);
        if (epoch == 0) {
            _useRootEpoch(0);
        }
    }

    // Make the next registered root epoch the one KMS instances serve. Bind
    // activation to its chain hash in case a pending epoch has been replaced.
    function activateRootEpoch(uint256 epoch, bytes32 chainHash) external onlyOwner {
        require(epoch == _currentRootEpoch + 1 && epoch < _rootEpochs.length, "Invalid root epoch activation");
        require(_rootEpochs[epoch].chainHash == chainHash, "root epoch chain hash mismatch");
        _currentRootEpoch = epoch;
        _useRootEpoch(epoch);
        _emitPolicy("root-epoch-activated", bytes32(epoch), true);
    }

    // Point kmsInfo at the keys of the now current epoch, for readers of the
    // legacy KMS identity. Its quote and event log described the previous keys;
    // the epoch's evidence is at its evidenceUrl.
    function _useRootEpoch(uint256 epoch) private {
        RootEpoch storage keys = _rootEpochs[epoch];
        kmsInfo.caPubkey = keys.caPubkey;
        kmsInfo.k256Pubkey = keys.k256Pubkey;
        delete kmsInfo.quote;
        delete kmsInfo.eventlog;
        emit KmsInfoSet(keys.k256Pubkey);
        emit RootEpochActivated(epoch);
    }

    // Point an epoch at a new copy of its evidence, for when the old location
    // goes away. The evidence proves itself, so only its location changes.
    function setRootEpochEvidenceUrl(uint256 epoch, string calldata evidenceUrl) external onlyOwner {
        require(epoch < _rootEpochs.length, "Unknown root epoch");
        require(bytes(evidenceUrl).length > 0, "Empty epoch evidence URL");
        _rootEpochs[epoch].evidenceUrl = evidenceUrl;
        emit RootEpochEvidenceUrlSet(epoch, evidenceUrl);
    }

    // Drop the last registered epoch while it is still pending, for when the
    // nodes holding it are lost before enough others have onboarded it. The
    // epoch is named by number and chain hash, so a stale call cannot drop a
    // later registration of the same number.
    function popRootEpoch(uint256 epoch, bytes32 chainHash) external onlyOwner {
        require(epoch + 1 == _rootEpochs.length && epoch > _currentRootEpoch, "Not the pending root epoch");
        require(_rootEpochs[epoch].chainHash == chainHash, "Root epoch chain hash mismatch");
        _rootEpochs.pop();
        emit RootEpochPopped(epoch, chainHash);
        _emitPolicy("root-epoch", chainHash, false);
    }

    function rootEpochCount() external view returns (uint256) {
        return _rootEpochs.length;
    }

    // The root epoch KMS instances serve and its chain hash
    function currentRootEpoch() external view returns (uint256 epoch, bytes32 chainHash) {
        require(_rootEpochs.length > 0, "No root epoch registered");
        epoch = _currentRootEpoch;
        chainHash = _rootEpochs[epoch].chainHash;
    }

    function rootEpoch(uint256 epoch)
        external
        view
        returns (bytes memory caPubkey, bytes memory k256Pubkey, string memory evidenceUrl, bytes32 chainHash)
    {
        require(epoch < _rootEpochs.length, "Unknown root epoch");
        RootEpoch storage keys = _rootEpochs[epoch];
        return (keys.caPubkey, keys.k256Pubkey, keys.evidenceUrl, keys.chainHash);
    }

    // Function to set trusted Gateway App ID
    function setGatewayAppId(string memory appId) external onlyOwner {
        gatewayAppId = appId;
        emit GatewayAppIdSet(appId);
        _emitPolicy("gateway-app-id", keccak256(bytes(appId)), true);
    }

    /// @notice Register an app address as known to this KMS.
    /// @dev Intentionally permissionless: any caller can mark any non-zero
    ///      address as registered. This is the factory hook used by
    ///      {deployAndRegisterApp}, and direct external registration is
    ///      also a supported use case (e.g. third parties bootstrapping
    ///      their own DstackApp under this KMS). Authorization is gated
    ///      downstream by the owner-controlled {allowedOsImages} whitelist
    ///      and by the registered app's own {IAppAuth-isAppAllowed}, so
    ///      registration alone confers no privilege.
    function registerApp(address appId) public {
        require(appId != address(0), "Invalid app ID");
        registeredApps[appId] = true;
        emit AppRegistered(appId);
        _emitPolicy("registered-app", bytes32(uint256(uint160(appId))), true);
    }

    // Function to set DstackApp implementation contract address
    function setAppImplementation(address _implementation) external onlyOwner {
        require(_implementation != address(0), "Invalid implementation address");
        appImplementation = _implementation;
        emit AppImplementationSet(_implementation);
        _emitPolicy("app-implementation", bytes32(uint256(uint160(_implementation))), true);
    }

    // Factory method: Deploy and register DstackApp in single transaction
    function deployAndRegisterApp(
        address initialOwner,
        bool disableUpgrades,
        bool requireTcbUpToDate,
        bool allowAnyDevice,
        bytes32 initialDeviceId,
        bytes32 initialComposeHash
    )
        public
        returns (address appId)
    {
        require(appImplementation != address(0), "DstackApp implementation not set");
        require(initialOwner != address(0), "Invalid owner address");

        bytes memory initData = abi.encodeWithSelector(
            bytes4(keccak256("initialize(address,bool,bool,bool,bytes32,bytes32)")),
            initialOwner,
            disableUpgrades,
            requireTcbUpToDate,
            allowAnyDevice,
            initialDeviceId,
            initialComposeHash
        );

        // The ERC1967Proxy constructor delegatecalls into `appImplementation`'s
        // initializer. The owner sets `appImplementation` via
        // setAppImplementation; safety here rests on owner trust, not on a
        // structural reentrancy impossibility — a malicious owner could in
        // principle install an impl whose `initialize` reenters this contract.
        // See docs/specification.md §1 for the owner trust scope and §6.1 for
        // the malicious-registered-app threat model.
        // slither-disable-next-line reentrancy-benign,reentrancy-events
        appId = address(new ERC1967Proxy(appImplementation, initData));
        registerApp(appId);
        emit AppDeployedViaFactory(appId, msg.sender);
    }

    // Backward compatible factory method for old SDK callers (pre TCB flag)
    function deployAndRegisterApp(
        address initialOwner,
        bool disableUpgrades,
        bool allowAnyDevice,
        bytes32 initialDeviceId,
        bytes32 initialComposeHash
    )
        external
        returns (address appId)
    {
        return deployAndRegisterApp(
            initialOwner, disableUpgrades, false, allowAnyDevice, initialDeviceId, initialComposeHash
        );
    }

    // Function to register an aggregated MR measurement
    function addKmsAggregatedMr(bytes32 mrAggregated) external onlyOwner {
        kmsAllowedAggregatedMrs[mrAggregated] = true;
        emit KmsAggregatedMrAdded(mrAggregated);
        _emitPolicy("kms-aggregated-mr", mrAggregated, true);
    }

    // Function to deregister an aggregated MR measurement
    function removeKmsAggregatedMr(bytes32 mrAggregated) external onlyOwner {
        kmsAllowedAggregatedMrs[mrAggregated] = false;
        emit KmsAggregatedMrRemoved(mrAggregated);
        _emitPolicy("kms-aggregated-mr", mrAggregated, false);
    }

    // Function to register a KMS device ID
    function addKmsDevice(bytes32 deviceId) external onlyOwner {
        kmsAllowedDeviceIds[deviceId] = true;
        emit KmsDeviceAdded(deviceId);
        _emitPolicy("kms-device", deviceId, true);
    }

    // Function to deregister a KMS device ID
    function removeKmsDevice(bytes32 deviceId) external onlyOwner {
        kmsAllowedDeviceIds[deviceId] = false;
        emit KmsDeviceRemoved(deviceId);
        _emitPolicy("kms-device", deviceId, false);
    }

    // Function to register an image measurement
    function addOsImageHash(bytes32 osImageHash) external onlyOwner {
        allowedOsImages[osImageHash] = true;
        emit OsImageHashAdded(osImageHash);
        _emitPolicy("os-image", osImageHash, true);
    }

    // Function to deregister an image measurement
    function removeOsImageHash(bytes32 osImageHash) external onlyOwner {
        allowedOsImages[osImageHash] = false;
        emit OsImageHashRemoved(osImageHash);
        _emitPolicy("os-image", osImageHash, false);
    }

    /// Authorize an attested identity and return the root epoch from the same state.
    /// The caller selects KMS or app policy; KMS authorization requires the proxy app ID.
    function authorizeKms(AuthorizationRequest calldata request) external view returns (AuthorizationResult memory) {
        return _checkAuthorization(request, true);
    }

    function authorizeApp(AuthorizationRequest calldata request) external view returns (AuthorizationResult memory) {
        return _checkAuthorization(request, false);
    }

    function _checkAuthorization(
        AuthorizationRequest calldata request,
        bool isKms
    )
        private
        view
        returns (AuthorizationResult memory result)
    {
        result.gatewayAppId = gatewayAppId;
        if (!(isKms
                    ? AuthorizationOperation.isKms(request.operation)
                    : AuthorizationOperation.isApp(request.operation))) {
            result.rejectionReason = "Invalid authorization operation";
            return result;
        }
        if (_rootEpochs.length == 0) {
            if (request.operation != AuthorizationOperation.KMS_BOOTSTRAP) {
                result.rejectionReason = "Root epoch not registered";
                return result;
            }
        } else {
            result.currentRootEpoch = _currentRootEpoch;
            result.currentRootEpochHash = _rootEpochs[_currentRootEpoch].chainHash;
        }
        if (request.requestedRootEpoch.isSet && request.requestedRootEpoch.value > _currentRootEpoch) {
            result.rejectionReason = "Requested root epoch is not active";
            return result;
        }
        if (request.requestedAppEpoch.isSet && request.requestedAppEpoch.value != 0) {
            result.rejectionReason = "Requested app epoch must be zero";
            return result;
        }
        AppInfo calldata appInfo = request.appInfo;
        AppInfo memory bootInfo = AppInfo({
            appId: appInfo.appId,
            composeHash: appInfo.composeHash,
            instanceId: appInfo.instanceId,
            deviceId: appInfo.deviceId,
            mrAggregated: appInfo.mrAggregated,
            mrSystem: appInfo.mrSystem,
            osImageHash: appInfo.osImageHash,
            tcbStatus: appInfo.tcbStatus,
            advisoryIds: appInfo.advisoryIds
        });
        if (isKms) {
            (result.isAllowed, result.rejectionReason) = _isKmsAllowed(bootInfo);
        } else {
            (result.isAllowed, result.rejectionReason) = _isAppAllowed(bootInfo);
        }
    }

    // Function to check if KMS is allowed to boot
    function isKmsAllowed(AppInfo calldata bootInfo) external view returns (bool isAllowed, string memory reason) {
        return _isKmsAllowed(bootInfo);
    }

    function _isKmsAllowed(AppInfo memory bootInfo) private view returns (bool, string memory) {
        // Check if the TCB status is up to date
        if (keccak256(abi.encodePacked(bootInfo.tcbStatus)) != keccak256(abi.encodePacked("UpToDate"))) {
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
    function isAppAllowed(AppInfo calldata bootInfo)
        external
        view
        override
        returns (bool isAllowed, string memory reason)
    {
        return _isAppAllowed(bootInfo);
    }

    function _isAppAllowed(AppInfo memory bootInfo) private view returns (bool, string memory) {
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

        // Call the app's isAppAllowed function. The tuple is forwarded as the
        // function's return value; the slither detector trips on the named
        // return + forward pattern but the value is actually used.
        // slither-disable-next-line unused-return
        return IAppAuth(bootInfo.appId).isAppAllowed(bootInfo);
    }

    // Add storage gap for upgradeable contracts
    uint256[48] private __gap;
}

function isContract(address addr) view returns (bool) {
    uint32 size;
    assembly {
        size := extcodesize(addr)
    }
    return (size > 0);
}
