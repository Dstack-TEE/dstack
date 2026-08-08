<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-auth-007"></a>
# TC-KMS-AUTH-007: Ethereum finalized snapshot and reorg refresh

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-auth-007](../../../feature-audit.md#req-kms-auth-007)
- Risks: [risk-kms-auth-007](../../../feature-audit.md#risk-kms-auth-007)
- Source: `dstack/kms/auth-eth-bun/index.ts`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify Ethereum authorization reads one confirmation-depth snapshot on the expected chain, refreshes the snapshot for every request, and fails closed across uncertain-head, wrong-chain, dependency-failure, recovery, and process-restart boundaries.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-kms-auth-007-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-kms-auth-007-step-02"></a>
### Step 2: Exercise supported and boundary paths

Configure an expected chain and confirmation depth, then exercise a finalized allow, a changed canonical decision at the next finalized height, wrong-chain routing, a head below the configured depth, and a head-query timeout.

**Expected results:**

- The decision and gateway identity use the same explicit finalized block; every request recomputes that block without a decision cache, uncertain state fails closed, and the next canonical snapshot is observed after recovery.

<a id="tc-kms-auth-007-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-kms-auth-007-step-04"></a>
### Step 4: Verify isolation and persistence

Run the exact matrix in a second fresh authorization process and compare its bounded result counts and output digest.

**Expected results:**

- No authorization decision survives process restart, both processes pass all exact rows, and retained evidence contains only counts and output hashes rather than endpoint credentials or request payloads.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
