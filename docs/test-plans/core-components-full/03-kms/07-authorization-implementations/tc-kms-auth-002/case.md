<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-auth-002"></a>
# TC-KMS-AUTH-002: Mock authorization safety boundary

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-kms-auth-002](../../../feature-audit.md#req-kms-auth-002)
- Risks: [risk-kms-auth-002](../../../feature-audit.md#risk-kms-auth-002)
- Source: `dstack/kms/auth-mock`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The behavior under test is the standalone `dstack/kms/auth-mock` service, not the KMS `[core.auth_api] type = "dev"` shortcut. Exercise the candidate auth-mock implementation and its native test suite directly.
- Its native runner is Bun, not Cargo or an unprepared global Vitest command. From `dstack/kms/auth-mock`, run `bun install --frozen-lockfile` when `node_modules` is absent, then execute `bun run test:run`; preserve the package directory as the working directory and ensure Bun's bin directory is on `PATH`.
- Vitest 4 requires Node 20 or newer. Resolve the prepared Node executable once, prepend its containing directory plus `node_modules/.bin` to `PATH`, and record only the version and exit status; do not fall back to the host Node 18 executable.
- The service entrypoint is the package-root `index.ts` (also exposed by `bun run start`), not `src/index.ts`. For lifecycle and recovery probes, run `bun run index.ts` from `dstack/kms/auth-mock` with the case-owned `PORT`.
- For the production-boundary row, start auth-mock itself with an explicit production marker such as `NODE_ENV=production`; the expected rejection must come from auth-mock policy. A KMS startup failure caused by missing certificates, occupied ports, unrelated self-authorization, or malformed configuration does not prove this requirement.

## Objective

Verify mock authorization safety boundary with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-kms-auth-002-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-kms-auth-002-step-02"></a>
### Step 2: Exercise supported and boundary paths

Run mock auth in development and attempt the same configuration in a production-marked deployment.

**Expected results:**

- Mock decisions are deterministic for tests, visibly identify development mode, and production startup or policy rejects mock authorization.

<a id="tc-kms-auth-002-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-kms-auth-002-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
