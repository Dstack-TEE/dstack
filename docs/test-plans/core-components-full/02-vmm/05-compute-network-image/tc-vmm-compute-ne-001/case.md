<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-compute-ne-001"></a>
# TC-VMM-COMPUTE-NE-001: User and bridge multi-NIC lifecycle

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

Verify the current user and bridge networking paths across multi-NIC command
generation and QEMU lifecycle. The integration path uses a development image and
the TEE simulator; it is not evidence for TDX or SNP attestation.

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

Deploy a two-NIC user-network simulator VM through the VMM API and materialize a
stopped two-NIC bridge launch through the same public contract.

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

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
