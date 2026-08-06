/*
 * SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "openzeppelin-foundry-upgrades/Upgrades.sol";
import "../contracts/DstackKms.sol";
import "../contracts/DstackApp.sol";

contract EventAuditTest is Test {
    bytes32 private constant AUDIT_TOPIC = keccak256("PolicyChanged(address,bytes32,bytes32,bool)");

    address private owner;
    address private outsider;
    DstackKms private kms;
    DstackApp private app;

    function setUp() public {
        owner = makeAddr("audit-owner");
        outsider = makeAddr("audit-outsider");
        vm.startPrank(owner);
        DstackApp appImplementation = new DstackApp();
        kms = DstackKms(
            Upgrades.deployUUPSProxy(
                "DstackKms.sol", abi.encodeCall(DstackKms.initialize, (owner, address(appImplementation)))
            )
        );
        app = DstackApp(
            Upgrades.deployUUPSProxy(
                "DstackApp.sol",
                abi.encodeWithSignature(
                    "initialize(address,bool,bool,bool,bytes32,bytes32)",
                    owner,
                    false,
                    false,
                    false,
                    bytes32(0),
                    bytes32(0)
                )
            )
        );
        vm.stopPrank();
    }

    function test_KmsPolicyEventsReconstructQueriedState() public {
        bytes32 mr = keccak256("audit-mr");
        bytes32 device = keccak256("audit-device");
        bytes32 image = keccak256("audit-image");
        string memory gateway = "audit-gateway";

        vm.recordLogs();
        vm.startPrank(owner);
        kms.addKmsAggregatedMr(mr);
        kms.addKmsDevice(device);
        kms.addOsImageHash(image);
        kms.setGatewayAppId(gateway);
        kms.registerApp(address(app));
        kms.removeKmsAggregatedMr(mr);
        vm.stopPrank();
        Vm.Log[] memory logs = vm.getRecordedLogs();

        _assertAudit(logs, owner, "kms-aggregated-mr", mr, true);
        _assertAudit(logs, owner, "kms-device", device, true);
        _assertAudit(logs, owner, "os-image", image, true);
        _assertAudit(logs, owner, "gateway-app-id", keccak256(bytes(gateway)), true);
        _assertAudit(logs, owner, "registered-app", bytes32(uint256(uint160(address(app)))), true);
        _assertAudit(logs, owner, "kms-aggregated-mr", mr, false);

        assertFalse(kms.kmsAllowedAggregatedMrs(mr));
        assertTrue(kms.kmsAllowedDeviceIds(device));
        assertTrue(kms.allowedOsImages(image));
        assertEq(kms.gatewayAppId(), gateway);
        assertTrue(kms.registeredApps(address(app)));
    }

    function test_AppPolicyEventsReconstructQueriedState() public {
        bytes32 composeHash = keccak256("audit-compose");
        bytes32 device = keccak256("audit-app-device");

        vm.recordLogs();
        vm.startPrank(owner);
        app.addComposeHash(composeHash);
        app.addDevice(device);
        app.setAllowAnyDevice(true);
        app.setRequireTcbUpToDate(true);
        app.removeDevice(device);
        app.disableUpgrades();
        vm.stopPrank();
        Vm.Log[] memory logs = vm.getRecordedLogs();

        _assertAudit(logs, owner, "compose-hash", composeHash, true);
        _assertAudit(logs, owner, "device", device, true);
        _assertAudit(logs, owner, "allow-any-device", bytes32(0), true);
        _assertAudit(logs, owner, "require-tcb-up-to-date", bytes32(0), true);
        _assertAudit(logs, owner, "device", device, false);
        _assertAudit(logs, owner, "upgrades-disabled", bytes32(0), true);

        assertTrue(app.allowedComposeHashes(composeHash));
        assertFalse(app.allowedDeviceIds(device));
        assertTrue(app.allowAnyDevice());
        assertTrue(app.requireTcbUpToDate());
    }

    function test_InvalidMutationEmitsNoAuditAndLeavesNoPartialState() public {
        bytes32 image = keccak256("unauthorized-image");
        vm.recordLogs();
        vm.prank(outsider);
        vm.expectRevert();
        kms.addOsImageHash(image);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_auditCount(logs), 0);
        assertFalse(kms.allowedOsImages(image));
    }

    function test_ReorgDropsOrphanEventAndCanonicalEventRebuildsState() public {
        bytes32 orphaned = keccak256("orphaned-compose");
        bytes32 canonical = keccak256("canonical-compose");
        uint256 snapshot = vm.snapshotState();

        vm.recordLogs();
        vm.prank(owner);
        app.addComposeHash(orphaned);
        Vm.Log[] memory orphanLogs = vm.getRecordedLogs();
        _assertAudit(orphanLogs, owner, "compose-hash", orphaned, true);
        assertTrue(app.allowedComposeHashes(orphaned));

        assertTrue(vm.revertToState(snapshot));
        assertFalse(app.allowedComposeHashes(orphaned));

        vm.recordLogs();
        vm.prank(owner);
        app.addComposeHash(canonical);
        Vm.Log[] memory canonicalLogs = vm.getRecordedLogs();
        _assertAudit(canonicalLogs, owner, "compose-hash", canonical, true);
        assertEq(_auditCount(canonicalLogs), 1);
        assertTrue(app.allowedComposeHashes(canonical));
        assertFalse(app.allowedComposeHashes(orphaned));
    }

    function test_UpgradeAuditIncludesActorAndImplementation() public {
        vm.startPrank(owner);
        DstackApp replacement = new DstackApp();
        vm.recordLogs();
        app.upgradeToAndCall(address(replacement), "");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        vm.stopPrank();

        _assertAudit(logs, owner, "implementation-upgrade", bytes32(uint256(uint160(address(replacement)))), true);
        assertEq(Upgrades.getImplementationAddress(address(app)), address(replacement));
    }

    function _assertAudit(
        Vm.Log[] memory logs,
        address actor,
        string memory policy,
        bytes32 value,
        bool enabled
    )
        private
        pure
    {
        bytes32 actorTopic = bytes32(uint256(uint160(actor)));
        bytes32 policyTopic = keccak256(bytes(policy));
        for (uint256 i = 0; i < logs.length; ++i) {
            Vm.Log memory entry = logs[i];
            if (
                entry.topics.length == 4 && entry.topics[0] == AUDIT_TOPIC && entry.topics[1] == actorTopic
                    && entry.topics[2] == policyTopic && entry.topics[3] == value
                    && abi.decode(entry.data, (bool)) == enabled
            ) {
                return;
            }
        }
        revert("expected policy audit event not found");
    }

    function _auditCount(Vm.Log[] memory logs) private pure returns (uint256 count) {
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics.length == 4 && logs[i].topics[0] == AUDIT_TOPIC) ++count;
        }
    }
}
