<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-input-plat-005"></a>
# TC-INT-INPUT-PLAT-005: SEV-SNP certificate and report verification

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-ver-input-plat-005](../../../../catalog/feature-audit.md#req-ver-input-plat-005)
- Risks: [risk-ver-input-plat-005](../../../../catalog/feature-audit.md#risk-ver-input-plat-005)
- Source: `dstack/verifier/src/verification.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Build and operate the simulated row as documented in [`simulator-test-environment.md`](../../../../simulator-test-environment.md).
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify sev-snp certificate and report verification across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-ver-input-plat-005-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for sev-snp certificate and report verification.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-ver-input-plat-005-step-02"></a>
### Step 2: Exercise the behavior

Verify fixture/hardware across VCEK chain, chip ID, TCB, policy, measurement, report data, and debug/migration flags.

**Expected results:**

- Trusted AMD chain and policy are enforced and each altered field produces a specific non-PASS result.

<a id="tc-ver-input-plat-005-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PRs #1248, #1252, #1275, and #1279)

Step 2 also runs these exact tests; each must pass by name:

- #1248: `sev-snp-qvl` `tests::overlapping_certificate_table_entries_are_not_copied` -- kernel certificate-table entries are borrowed and overlapping entries are rejected rather than copied.
- #1279: `sev-snp-qvl` `tests::a_short_report_without_a_cert_chain_is_rejected_rather_than_parsed`, and the `dstack-attest` integration test `sev_snp_verify::an_empty_snp_report_from_the_verify_body_is_rejected_rather_than_parsed`. An empty SNP report in a `/verify` body fails with `invalid amd sev-snp report length` instead of aborting the verifier process.
- #1275: `dstack-mr` `sev::tests::verify_sev_launch_rejects_a_consistent_debugswap_guest`, `sev::tests::rejects_guest_features_outside_the_launch_allowlist`, and `sev::tests::a_duplicated_rootfs_hash_is_not_silently_resolved`. Only `SNPActive` is accepted in `SEV_FEATURES`, and a command line with two `dstack.rootfs_hash` values is rejected.
- #1252: `dstack-mr` `sev::tests::page_budget_rejects_old_ceiling_and_admits_real_table`. The SEV-SNP metadata page budget is 65536 pages.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
