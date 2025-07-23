// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";

contract SetKmsInfo is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address kmsAddress = vm.envAddress("KMS_CONTRACT_ADDRESS");
        
        bytes memory k256Pubkey = vm.envBytes("K256_PUBKEY");
        bytes memory caPubkey = vm.envBytes("CA_PUBKEY");
        bytes memory quote = vm.envBytes("QUOTE");
        bytes memory eventlog = vm.envOr("EVENTLOG", bytes(""));
        
        vm.startBroadcast(deployerPrivateKey);
        
        DstackKms kms = DstackKms(kmsAddress);
        kms.setKmsInfo(DstackKms.KmsInfo({
            k256Pubkey: k256Pubkey,
            caPubkey: caPubkey,
            quote: quote,
            eventlog: eventlog
        }));
        
        vm.stopBroadcast();
        
        console.log("KMS info set successfully");
    }
}

contract AddKmsAggregatedMr is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address kmsAddress = vm.envAddress("KMS_CONTRACT_ADDRESS");
        bytes32 mr = vm.envBytes32("AGGREGATED_MR");
        
        vm.startBroadcast(deployerPrivateKey);
        
        DstackKms kms = DstackKms(kmsAddress);
        kms.addKmsAggregatedMr(mr);
        
        vm.stopBroadcast();
        
        console.log("KMS aggregated MR added");
        console.logBytes32(mr);
    }
}

contract DeployApp is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address kmsAddress = vm.envAddress("KMS_CONTRACT_ADDRESS");
        
        bool allowAnyDevice = vm.envOr("ALLOW_ANY_DEVICE", false);
        bytes32 deviceId = vm.envOr("DEVICE_ID", bytes32(0));
        bytes32 composeHash = vm.envOr("COMPOSE_HASH", bytes32(0));
        
        vm.startBroadcast(deployerPrivateKey);
        
        DstackKms kms = DstackKms(kmsAddress);
        address appId = kms.deployAndRegisterApp(
            deployer,
            false, // disableUpgrades
            allowAnyDevice,
            deviceId,
            composeHash
        );
        
        vm.stopBroadcast();
        
        console.log("App deployed and registered:");
        console.log("- App ID:", appId);
        console.log("- Owner:", deployer);
        console.log("- Allow any device:", allowAnyDevice);
        if (deviceId != bytes32(0)) {
            console.log("- Initial device ID:");
            console.logBytes32(deviceId);
        }
        if (composeHash != bytes32(0)) {
            console.log("- Initial compose hash:");
            console.logBytes32(composeHash);
        }
    }
}