<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-compose-006"></a>
# TC-GOS-COMPOSE-006: App manifest version feature and launch-requirement policy

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-compose-006](../../../../catalog/feature-audit.md#req-gos-compose-006)
- Risks: [risk-gos-compose-006](../../../../catalog/feature-audit.md#risk-gos-compose-006)
- Source: `dstack/dstack-util/src/system_setup.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify app manifest version feature and launch-requirement policy using the complete source-defined decision matrix and independently observable output.

## Preconditions

1. Record candidate and pinned historical image/compose/config versions plus baseline identity, measurements, processes, files and public status.
2. Use isolated run-scoped inputs and retain native redacted output.

## Test Data

Build a table with one row for every condition named in Step 1, including each condition alone and security-relevant conflicting combinations.

## Steps

<a id="tc-gos-compose-006-step-01"></a>
### Step 1: Execute the full decision matrix

Exercise manifest versions and maximum supported version; OS semver ranges; platform list omitted/empty/matching/mismatching/invalid; `tdx_measure_acpi_tables`; launch-token hash/user token; runner/snapshotter compatibility; empty and unknown requirements.

**Expected results:**

- V1/V2/V3 gates match documented feature introduction, OS/platform/ACPI/token requirements fail closed exactly, runner/snapshotter combinations are enforced, and accepted policy is measured into app identity as defined.

<a id="tc-gos-compose-006-step-02"></a>
### Step 2: Verify the selected state end to end

Compare parser/validation output, persisted manifest/config, generated measurement inputs, launch arguments, guest-visible state and public status for every accepted row.

**Expected results:**

- Every representation agrees with the selected row, no rejected value is partially persisted or launched, and unrelated inputs do not change measured identity.

<a id="tc-gos-compose-006-step-03"></a>
### Step 3: Verify failure recovery and version compatibility

Restart after accepted/rejected rows, replay applicable v0.5.4/v0.5.8/v0.5.11 inputs, and retry after correcting one invalid field.

**Expected results:**

- Supported historical defaults remain stable, unsupported combinations fail before secret/device consumption, restart reconstructs the same decision and corrected retry succeeds without stale state.

## Post-baseline regression coverage (PRs #1083, #1092, #1124)

- Run compose-hash compatibility inputs with omitted, empty, and byte-valued manifest fields through the candidate guest and supported SDK clients.
- Confirm nerdctl 2.3.5 starts the same compose workload and rejects a malformed manifest without changing the accepted compose hash.

## Postconditions

Remove run-scoped VMs/files/devices and verify baseline restoration.
