<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-compute-ne-001"></a>
# TC-VMM-COMPUTE-NE-001: Bridge networking and libvirt network filtering

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-compute-ne-001](../../../feature-audit.md#req-vmm-compute-ne-001)
- Risks: [risk-vmm-compute-ne-001](../../../feature-audit.md#risk-vmm-compute-ne-001)
- Source: `dstack/vmm/src/app/network.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify the optional libvirt network-filter path without delegating QEMU lifecycle
management to libvirt. The integration path uses a development image and the TEE
simulator; it is not evidence for TDX or SNP attestation.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

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

Deploy a two-NIC simulator VM through the VMM API. In addition, run two isolated
VMM instances against one netd and exercise filtered interfaces concurrently.

**Expected results:**

- Both simulator NICs have distinct MAC addresses, TAPs, and libvirt nwfilter
  bindings. Concurrent instances cannot remove each other's deterministic TAPs.
- Normal DHCP and guest traffic passes, while forged Ethernet source MAC, IPv4
  source address, and ARP sender identity traffic is dropped.

<a id="tc-vmm-compute-ne-001-step-03"></a>
### Step 3: Verify crash restart and service recovery

Force QEMU to exit after network preparation and verify automatic restart. Restart
VMM, netd, and libvirtd independently, then perform a host-reboot-equivalent
cycle by stopping all case-owned processes, removing ephemeral network state,
and restarting from persisted VMM state.

**Expected results:**

- A QEMU runtime crash retains or re-prepares its deterministic TAP and nwfilter
  binding for automatic restart; Stop/Remove subsequently cleans both.
- Existing guests survive VMM, netd, and libvirtd restart where applicable; new
  operations work after restart.
- The reboot-equivalent cycle recreates both TAPs and bindings and removal cleans
  all case-owned resources.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
