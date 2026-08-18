<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-keys-certs-006"></a>
# TC-KMS-KEYS-CERTS-006: Image measurement cache clear and refill

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-keys-certs-006](../../../../catalog/feature-audit.md#req-kms-keys-certs-006)
- Risks: [risk-kms-keys-certs-006](../../../../catalog/feature-audit.md#risk-kms-keys-certs-006)
- Source: `dstack/kms/src/admin_service.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify image measurement cache clear and refill across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-kms-keys-certs-006-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for image measurement cache clear and refill.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-kms-keys-certs-006-step-02"></a>
### Step 2: Exercise the behavior

Populate positive/negative image/config cache, clear specific/all selectors with admin auth, then reverify.

**Expected results:**

- Only selected entries disappear, next verification recomputes, and unauthorized clear has no effect.

<a id="tc-kms-keys-certs-006-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
