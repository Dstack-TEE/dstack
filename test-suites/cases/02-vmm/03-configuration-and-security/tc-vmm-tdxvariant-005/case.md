<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-tdxvariant-005"></a>
# TC-VMM-TDXVARIANT-005: TDX legacy lite and auto variant resolution matrix

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-vmm-tdxvariant-005](../../../../catalog/feature-audit.md#req-vmm-tdxvariant-005)
- Risks: [risk-vmm-tdxvariant-005](../../../../catalog/feature-audit.md#risk-vmm-tdxvariant-005)
- Source: `dstack/vmm/src/app.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The fixture starts a case-owned VMM whose isolated image store exposes the prepared candidate and pinned `0.5.4`, `0.5.8`, and `0.5.11` image artifacts read-only. Use `values.vmm.test_input.vm_configuration` as the base request, exact VMM routes, unique names, and the fixture-listed image names. Register every returned VM ID before further actions. Persisted VM state, QEMU command lines, and cleanup must remain under the lease-owned VMM workspace; never operate on an existing shared VMM or VM.

## Objective

Verify tdx legacy lite and auto variant resolution matrix using the complete source-defined decision matrix and independently observable output.

## Preconditions

1. Record candidate and pinned historical image/compose/config versions plus baseline identity, measurements, processes, files and public status.
2. Use isolated run-scoped inputs and retain native redacted output.

## Test Data

Build a table with one row for every condition named in Step 1, including each condition alone and security-relevant conflicting combinations.

## Steps

<a id="tc-vmm-tdxvariant-005-step-01"></a>
### Step 1: Execute the full decision matrix

Cross explicit legacy/lite/auto with memory below/equal/above 2 GiB, image lite capability, `requirements.tdx_measure_acpi_tables` true/false/omitted, pinned old images and KMS-onboard mode.

**Expected results:**

- Explicit requirements take documented precedence, auto chooses lite only for supported 2-GiB-compatible rows, otherwise legacy; vm_config/event expectations match, and old-source KMS targets remain forced legacy.

<a id="tc-vmm-tdxvariant-005-step-02"></a>
### Step 2: Verify the selected state end to end

Compare parser/validation output, persisted manifest/config, generated measurement inputs, launch arguments, guest-visible state and public status for every accepted row.

**Expected results:**

- Every representation agrees with the selected row, no rejected value is partially persisted or launched, and unrelated inputs do not change measured identity.

<a id="tc-vmm-tdxvariant-005-step-03"></a>
### Step 3: Verify failure recovery and version compatibility

Restart after accepted/rejected rows, replay applicable v0.5.4/v0.5.8/v0.5.11 inputs, and retry after correcting one invalid field.

**Expected results:**

- Supported historical defaults remain stable, unsupported combinations fail before secret/device consumption, restart reconstructs the same decision and corrected retry succeeds without stale state.

## Postconditions

Remove run-scoped VMs/files/devices and verify baseline restoration.
