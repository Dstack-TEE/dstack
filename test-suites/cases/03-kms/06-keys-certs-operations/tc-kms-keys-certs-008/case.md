<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-keys-certs-008"></a>
# TC-KMS-KEYS-CERTS-008: Metrics metadata and failure diagnostics

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-keys-certs-008](../../../../catalog/feature-audit.md#req-kms-keys-certs-008)
- Risks: [risk-kms-keys-certs-008](../../../../catalog/feature-audit.md#risk-kms-keys-certs-008)
- Source: `dstack/kms/src/config.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify metrics metadata and failure diagnostics across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-kms-keys-certs-008-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for metrics metadata and failure diagnostics.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-kms-keys-certs-008-step-02"></a>
### Step 2: Exercise the behavior

Exercise GetMeta/health and metrics before/after authorization success, denial, cache use, and backend failure.

**Expected results:**

- Non-secret configuration and counters are accurate; error classes are actionable without evidence, key, token, or CSR secret leakage.

<a id="tc-kms-keys-certs-008-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PRs #1311, #1312, #1365)

- `GetMetaResponse.os_image_verification` (field 10, optional bool) reports `[core.image] verify`. The fixture sets `verify = false`, so it must be `false`, and the KMS log must carry the startup warning `os image verification is disabled; os_image_hash is caller-supplied and unverified`. Clients must not treat an unset field (an older KMS) as `true` (#1312).
- `core.auth_api.webhook.timeout` (default `60s`, connect timeout fixed at 5s) bounds every auth API call. Restart the KMS with a webhook that accepts the connection and never answers and `timeout = "2s"`: an unauthenticated `GetMeta` must fail within 10 seconds instead of hanging (#1365).
- The auth API info behind `GetMeta` is reused for one second and concurrent callers share one upstream request. Restart the KMS with a counting webhook that answers `GET /` after 300 ms, send 16 concurrent unauthenticated `GetMeta` calls, and expect all 16 to succeed with at most 2 upstream requests; after 1.5 s one more `GetMeta` must reach the webhook exactly once (#1311).

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
