/*
 * SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "openzeppelin-foundry-upgrades/Upgrades.sol";
import "../script/Manage.s.sol";

contract ManageScriptTest is Test {
    function deployApp(string memory release, address owner) internal returns (address) {
        return Upgrades.deployUUPSProxy(
            release,
            abi.encodeWithSignature(
                "initialize(address,bool,bool,bytes32,bytes32)", owner, false, false, bytes32(0), bytes32(0)
            )
        );
    }

    function addComposeHash(address app) internal returns (AddComposeHash script) {
        vm.setEnv("APP_CONTRACT_ADDR", vm.toString(app));
        script = new AddComposeHash();
        script.setUp();
    }

    // Environment variables persist across tests, so the cases run in order.
    function test_AppScriptsUseTheSettersTheAppHas() public {
        (address owner, uint256 key) = makeAddrAndKey("owner");
        address legacy = deployApp("DstackAppV060.sol:DstackApp", owner);
        address current = deployApp("DstackApp.sol", owner);
        bytes32 composeHash = bytes32(uint256(0xc0));
        vm.setEnv("KMS_CONTRACT_ADDR", vm.toString(address(1)));
        vm.setEnv("PRIVATE_KEY", vm.toString(key));
        vm.setEnv("COMPOSE_HASH", vm.toString(composeHash));

        // A legacy app takes its epoch-less setter, which writes app epoch 0.
        addComposeHash(legacy).run();
        assertTrue(DstackApp(legacy).allowedComposeHashes(composeHash));
        // An epoch-aware app needs its rows named.
        AddComposeHash script = addComposeHash(current);
        vm.expectRevert(bytes("set APP_EPOCH, or FROM_APP_EPOCH and TO_APP_EPOCH"));
        script.run();

        vm.setEnv("APP_EPOCH", "1");
        addComposeHash(current).run();
        assertFalse(DstackApp(current).allowedComposeHashesAtEpoch(0, composeHash));
        assertTrue(DstackApp(current).allowedComposeHashesAtEpoch(1, composeHash));
        script = addComposeHash(legacy);
        vm.expectRevert(bytes("this app predates app epochs: only APP_EPOCH=0 applies"));
        script.run();

        // TEE variant policies take `any` or names, and exist only in current apps.
        vm.setEnv("APP_EPOCH", "0");
        vm.setEnv("APP_CONTRACT_ADDR", vm.toString(current));
        vm.setEnv("TEE_VARIANTS", "dstack-tdx,dstack-gcp-tdx");
        SetTeeVariants teeScript = new SetTeeVariants();
        teeScript.setUp();
        teeScript.run();
        assertFalse(DstackApp(current).allowAnyTeeVariant());
        string[] memory names = DstackApp(current).allowedTeeVariants();
        assertEq(names.length, 2);
        assertEq(names[1], "dstack-gcp-tdx");
        vm.setEnv("TEE_VARIANTS", "any");
        teeScript.run();
        assertTrue(DstackApp(current).allowAnyTeeVariant());
        // An unset or empty TEE_VARIANTS must not lock everything out.
        vm.setEnv("TEE_VARIANTS", "");
        vm.expectRevert(bytes("set TEE_VARIANTS to any or platform names"));
        teeScript.run();
        assertTrue(DstackApp(current).allowAnyTeeVariant());
        vm.setEnv("TEE_VARIANTS", "any");
        vm.setEnv("APP_CONTRACT_ADDR", vm.toString(legacy));
        teeScript = new SetTeeVariants();
        teeScript.setUp();
        vm.expectRevert(bytes("this app predates TEE variant policies"));
        teeScript.run();
    }
}
