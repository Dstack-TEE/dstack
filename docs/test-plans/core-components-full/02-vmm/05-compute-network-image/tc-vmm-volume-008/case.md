<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-volume-008"></a>
# TC-VMM-VOLUME-008: Measured verity volume extraction resolution and path safety

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-volume-008](../../../feature-audit.md#req-vmm-volume-008)
- Risks: [risk-vmm-volume-008](../../../feature-audit.md#risk-vmm-volume-008)
- Source: `dstack/vmm/src/main_service.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The VMM-recognized app-compose field is exactly `verity_volumes`, not `volumes`. Each entry contains `source`, a 64-hex-character `verity_root`, and an absolute guest `target`. Use `values.vmm.test_input.verity_volume_matrix` for the configured volume root, valid sources, escape/metacharacter sources, and public test roots; do not invent host paths or alternate field names.
- `CreateVm` must reject malformed/missing-length roots, duplicate guest targets, non-bare sources, symlink escapes, and QEMU delimiter paths. A different well-formed 32-byte root is still a valid measured identity at VMM creation time; it is not a host-side content hash check. Grade guest dm-verity activation separately when the case-owned guest reaches that stage.

## Objective

Verify measured verity volume extraction resolution and path safety using the complete source-defined decision matrix and independently observable output.

## Preconditions

1. Record candidate and pinned historical image/compose/config versions plus baseline identity, measurements, processes, files and public status.
2. Use isolated run-scoped inputs and retain native redacted output.

## Test Data

Build a table with one row for every condition named in Step 1, including each condition alone and security-relevant conflicting combinations.

## Steps

<a id="tc-vmm-volume-008-step-01"></a>
### Step 1: Execute the full decision matrix

Exercise zero/one/multiple/duplicate verity volumes, relative and absolute sources, symlink escape, `..`, QEMU metacharacters, missing/wrong hash, update and rollback.

**Expected results:**

- Only measured sources inside configured volume roots attach once, volume count/content bind measurement config, traversal/metachar/missing/hash mismatch fails before QEMU, and unrelated compose fields remain opaque.

<a id="tc-vmm-volume-008-step-02"></a>
### Step 2: Verify the selected state end to end

Compare parser/validation output, persisted manifest/config, generated measurement inputs, launch arguments, guest-visible state and public status for every accepted row.

**Expected results:**

- Every representation agrees with the selected row, no rejected value is partially persisted or launched, and unrelated inputs do not change measured identity.

<a id="tc-vmm-volume-008-step-03"></a>
### Step 3: Verify failure recovery and version compatibility

Restart after accepted/rejected rows, replay applicable v0.5.4/v0.5.8/v0.5.11 inputs, and retry after correcting one invalid field.

**Expected results:**

- Supported historical defaults remain stable, unsupported combinations fail before secret/device consumption, restart reconstructs the same decision and corrected retry succeeds without stale state.

## Postconditions

Remove run-scoped VMs/files/devices and verify baseline restoration.
