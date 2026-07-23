<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-auth-010"></a>
# TC-KMS-AUTH-010: Authorization cache scope and invalidation

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-auth-010](../../../feature-audit.md#req-kms-auth-010)
- Risks: [risk-kms-auth-010](../../../feature-audit.md#risk-kms-auth-010)
- Source: `dstack/kms/src/main_service/upgrade_authority.rs`

## Objective

Verify authorization cache scope and invalidation with explicit success, boundary, failure, restart, and isolation observations.

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

Authorize multiple apps/nodes, change contract/config policy, revoke one identity, expire TTL, and restart KMS.

**Expected results:**

- Cache keys include chain/contract/app/node/image/config and policy version; targeted changes invalidate affected decisions without cross-app reuse.

<a id="tc-kms-auth-010-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-kms-auth-010-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
