<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-gpupolicy-007"></a>
# TC-GOS-GPUPOLICY-007: GPU attestation proxy nonce claim and Rego policy enforcement

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-gpupolicy-007](../../../feature-audit.md#req-gos-gpupolicy-007)
- Risks: [risk-gos-gpupolicy-007](../../../feature-audit.md#risk-gos-gpupolicy-007)
- Source: `dstack/dstack-util/src/system_setup.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Read `values.gpu_inventory` from `DSTACK_TEST_CASE_MANIFEST` before running
  the matrix. This case requires a fixture-owned supported NVIDIA
  confidential-computing GPU that can be attached to the guest. If the
  manifest records `available: false`, finalize all steps as BLOCKED from that
  single authoritative observation; CPU-only or simulated guests cannot
  confirm GPU claim, nonce, proxy, or Rego enforcement behavior.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify gpu attestation proxy nonce claim and rego policy enforcement using the complete source-defined decision matrix and independently observable output.

## Preconditions

1. A fixture-owned supported NVIDIA confidential-computing GPU is available
   for attachment; record candidate and pinned historical image/compose/config
   versions plus baseline identity, measurements, processes, files and public
   status.
2. Use isolated run-scoped inputs and retain native redacted output.

## Test Data

Build a table with one row for every condition named in Step 1, including each condition alone and security-relevant conflicting combinations.

## Steps

<a id="tc-gos-gpupolicy-007-step-01"></a>
### Step 1: Execute the full decision matrix

Exercise NVIDIA/non-NVIDIA inventory, OCSP/RIM proxy routing, fresh/replayed/wrong nonce, incomplete/multiple GPU claims, devtools and CC claims, basic policy opt-ins, custom Rego true/false/error/timeout and raw policy measurement.

**Expected results:**

- Every expected NVIDIA GPU supplies a fresh validated claim, proxy only reaches allowed evidence endpoints, basic/custom policy must explicitly pass within timeout, and complete raw evidence is measured without accepting missing/extra devices.

<a id="tc-gos-gpupolicy-007-step-02"></a>
### Step 2: Verify the selected state end to end

Compare parser/validation output, persisted manifest/config, generated measurement inputs, launch arguments, guest-visible state and public status for every accepted row.

**Expected results:**

- Every representation agrees with the selected row, no rejected value is partially persisted or launched, and unrelated inputs do not change measured identity.

<a id="tc-gos-gpupolicy-007-step-03"></a>
### Step 3: Verify failure recovery and version compatibility

Restart after accepted/rejected rows, replay applicable v0.5.4/v0.5.8/v0.5.11 inputs, and retry after correcting one invalid field.

**Expected results:**

- Supported historical defaults remain stable, unsupported combinations fail before secret/device consumption, restart reconstructs the same decision and corrected retry succeeds without stale state.

## Postconditions

Remove run-scoped VMs/files/devices and verify baseline restoration.
