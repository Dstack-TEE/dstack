<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-input-plat-006"></a>
# TC-INT-INPUT-PLAT-006: Cloud TDX and Nitro TPM verification

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-ver-input-plat-006](../../../../catalog/feature-audit.md#req-ver-input-plat-006)
- Risks: [risk-ver-input-plat-006](../../../../catalog/feature-audit.md#risk-ver-input-plat-006)
- Source: `dstack/verifier/src/verification.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Build and operate both simulated cloud rows as documented in [`simulator-test-environment.md`](../../../../simulator-test-environment.md).
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify cloud tdx and nitro tpm verification across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-ver-input-plat-006-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for cloud tdx and nitro tpm verification.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-ver-input-plat-006-step-02"></a>
### Step 2: Exercise the behavior

Verify GCP TDX and AWS Nitro TPM evidence with cloud metadata, measured boot, PCR/event logs, nonce, and vendor/product.

**Expected results:**

- Cloud chain, freshness, identity, PCR replay and config binding are all required; cross-cloud substitution fails.

<a id="tc-ver-input-plat-006-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PRs #1238, #1267, #1275, #1338, and #1404)

- The container controls run the product e2e attestation suite, whose verifier configuration now sets `attestation.allowed_collateral_hosts = ["127.0.0.1"]` for its local collateral service. The GCP control therefore also shows that an allowlisted host is fetched from.
- Step 2 also runs these exact tests; each must pass by name:
  - `tpm-qvl` `verify::tests::rejects_pcr_values_whose_lengths_do_not_match_the_attested_bank` and `verify::tests::rejects_pcr_values_that_misname_the_attested_bank` (#1275): every quoted PCR value must be a 32-byte `sha256` value.
  - `tpm-qvl` `verify::tests::rejects_duplicate_pcr_indices` (#1267).
  - `tpm-qvl` `verify::tests::event_log_keeps_only_quoted_pcrs` (#1338): the verified report exposes only event-log entries of quoted PCRs, all of which were replayed, and the GCP image check reads from that report.
  - `pki-fetch` `tests::request_count_is_bounded`, `tests::downloaded_bytes_are_bounded`, and `tests::total_time_is_bounded` (#1238): collateral fetching from certificate-named URLs has a fixed request, byte, and time budget.
  - `pki-fetch` `tests::only_allowed_hosts_are_contacted` and `tests::host_patterns_match_within_one_label` (#1404): a host outside the allowlist is refused before any request is made, and `*` matches within one DNS label only.
- The CLI side of #1404 (`dstack-util tpm-verify --allowed-collateral-host`) is covered in TC-GOS-SETUP-022, and the configuration key in TC-VER-BUILD-002.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
