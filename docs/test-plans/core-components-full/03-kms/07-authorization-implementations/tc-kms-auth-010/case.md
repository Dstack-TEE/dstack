<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-auth-010"></a>
# TC-KMS-AUTH-010: Authorization decision freshness and scope isolation

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-auth-010](../../../feature-audit.md#req-kms-auth-010)
- Risks: [risk-kms-auth-010](../../../feature-audit.md#risk-kms-auth-010)
- Source: `dstack/kms/src/main_service/upgrade_authority.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify the KMS deliberately retains no authorization decisions: identical and identity-mutated app/KMS requests reach the configured backend again, dependency uncertainty fails closed, and recovery plus process restart retain no prior allow.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-kms-auth-010-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-kms-auth-010-step-02"></a>
### Step 2: Exercise supported and boundary paths

Send identical requests across an allow-to-deny backend transition, then send distinct app/KMS requests whose app, node, image, measurement, compose, instance, and device fields differ.

**Expected results:**

- Both identical requests reach the backend and observe its current decision; app/KMS routes and every identity field remain distinct, with no KMS-local cache key, TTL, or cross-identity reuse.

<a id="tc-kms-auth-010-step-03"></a>
### Step 3: Exercise failure and recovery

Return one malformed backend response, then restore a valid response and repeat the same request.

**Expected results:**

- Malformed backend state returns an error rather than an allow, creates no retained decision, and the next request reaches the recovered backend and succeeds.

<a id="tc-kms-auth-010-step-04"></a>
### Step 4: Verify isolation and persistence

Execute the exact Rust matrix in a second fresh test process and compare bounded counts and output hashes.

**Expected results:**

- Both processes pass every exact row; no authorization decision survives restart, and evidence retains only counts, durations, coverage labels, and hashes.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
