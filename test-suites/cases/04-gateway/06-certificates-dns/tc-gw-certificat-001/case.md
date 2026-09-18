<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-certificat-001"></a>
# TC-GW-CERTIFICAT-001: ACME account bootstrap and persistence

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-certificat-001](../../../../catalog/feature-audit.md#req-gw-certificat-001)
- Risks: [risk-gw-certificat-001](../../../../catalog/feature-audit.md#risk-gw-certificat-001)
- Source: `dstack/gateway/src/distributed_certbot.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify ACME account bootstrap, administrative credential rotation, account-bound CAA re-pinning, cluster convergence, and persistence across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gw-certificat-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for acme account bootstrap and persistence.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gw-certificat-001-step-02"></a>
### Step 2: Exercise the behavior

Initialize an account, rotate it through the authenticated Admin API, verify CAA re-pinning and cross-node adoption, reject an unauthorized rotation, restart a node, and attempt an invalid directory state.

**Expected results:**

- The new account differs from the old account, every node converges on it, `issue`/`issuewild` CAA records bind the new account, restart preserves it, unauthorized rotation is rejected, and an ACME directory mismatch fails safely without silently creating another account.

<a id="tc-gw-certificat-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PR #1138)

- Rotation, CAA reconciliation, and first-use ACME account registration now share one cluster-wide lock stored in WaveKV, and first-use registration re-reads the credentials under that lock and adopts an account another node already registered.
- With the case-owned Cloudflare API blocked, call `Admin.RotateAcmeCredentials` on node 1 and wait until its DNS-provider preflight reaches the API. After 3 seconds, which covers WaveKV replication at the fixture's 1-second sync interval, call `Admin.SetCaa` on node 2. Expected: node 2 answers with HTTP status 400 or higher naming the `shared ACME lock`, and sends no Cloudflare API request. After the block is released, the rotation completes, and the existing rotation expectations hold: every node reports the new account and the CAA records are re-pinned to it.
- Every node still reports the same `account_uri` after the initial issuance, which shows the cluster registered a single shared account.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
