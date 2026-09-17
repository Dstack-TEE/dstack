<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-compute-ne-001"></a>
# TC-VMM-COMPUTE-NE-001: User and bridge multi-NIC lifecycle

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-compute-ne-001](../../../../catalog/feature-audit.md#req-vmm-compute-ne-001)
- Risks: [risk-vmm-compute-ne-001](../../../../catalog/feature-audit.md#risk-vmm-compute-ne-001)
- Source: `dstack/vmm/src/app/network.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify the current user and bridge networking paths across multi-NIC command
generation and QEMU lifecycle. The integration path uses a development image and
the TEE simulator; it is not evidence for TDX or SNP attestation.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.
3. The host has the `virbr0` bridge, `/usr/sbin/ip`, `/usr/bin/virsh`, and non-interactive `sudo -n` for starting the case-owned `dstack-vmm netd` as root.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-compute-ne-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for user bridge and custom networking.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-compute-ne-001-step-02"></a>
### Step 2: Exercise the behavior

Deploy a two-NIC user-network simulator VM through the VMM API, then materialize,
start, and stop a two-NIC bridge launch through the same public contract.

**Expected results:**

- Both simulator NICs have distinct deterministic MAC addresses and ordered QEMU
  netdev/device pairs. User and bridge requests retain their selected modes.
- Invalid mode/bridge combinations fail closed without affecting VMM availability.

<a id="tc-vmm-compute-ne-001-step-03"></a>
### Step 3: Verify crash restart and service recovery

Force QEMU to exit after network preparation and verify automatic restart. Restart
VMM independently and re-query the persisted launch and process state.

**Expected results:**

- A QEMU runtime crash preserves the resolved network launch and automatic restart
  replaces the process; Stop/Remove subsequently cleans the VM state.
- Existing guests survive VMM restart, invalid adjacent requests remain isolated,
  and removal cleans all case-owned resources.

## Post-baseline regression coverage (PR #1145, PR #1214, PR #1217, PR #1179)

The case starts its own VMM with `cvm.instance_id = "dtnet-<run key>"`, `[netd].socket` inside its private 0700 runtime directory, and `XDG_RUNTIME_DIR` pointing at a directory outside `/run/user`.

- PR #1145/#1214: bridge NICs are built by netd on every node; `qemu-bridge-helper` is no longer used. Before netd runs, `StartVm` on the stopped two-bridge VM fails with an error containing `run dstack-vmm netd`, starts no QEMU, and leaves no `.netd-pending` marker, while the VMM stays available.
- After the case-owned `sudo -n dstack-vmm --config <case vmm.toml> netd` serves its socket, the same `StartVm` succeeds. The QEMU command line carries two `-netdev tap,id=netN,ifname=<tap>,...,vhost=off` entries (node default `vhost = false`) and no `bridge,id=net` netdev; both TAPs exist and are enslaved to `virbr0`; `dstack-vmm netd list --instance <instance_id>` (PR #1217 pRPC surface `Netd.ListInterfaces`) reports exactly those two TAPs as kind `tap`, VM `<bridge VM ID>`, NIC `0` and `1`; the VM directory holds `.netd-pending`; and `Status` reports `running=true` with two `tap_bridge` interfaces whose `vhost=false` and `queues=1`.
- `StopVm` releases the interfaces (`Netd.RemoveVm`): `netd list --instance` becomes empty, both TAPs disappear from the host, and `.netd-pending` is cleared. The two-NIC user-mode VM creates no netd interface, and after every VM is removed netd holds nothing for the instance. netd is stopped only after that removal, because removal waits for netd to confirm the release.
- PR #1179: with `XDG_RUNTIME_DIR` set to the case directory, `vmm-cli.py vmm ls --json` lists exactly one registration for this case's config file whose `pid` is the VMM process and whose `address` is `127.0.0.1:18481`; the same command without `XDG_RUNTIME_DIR` does not list it; after the VMM restart it lists only the new VMM process.

## Postconditions

Remove run-scoped objects and restore changed configuration. Stop the case-owned netd after every VM is removed and verify no TAP it created remains. Preserve logs and responses in the result artifacts.
