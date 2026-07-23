<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-auth-003"></a>
# TC-KMS-AUTH-003: Ethereum authorization request signatures and replay

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-auth-003](../../../feature-audit.md#req-kms-auth-003)
- Risks: [risk-kms-auth-003](../../../feature-audit.md#risk-kms-auth-003)
- Source: `dstack/kms/auth-eth-bun/index.ts`

## Objective

Verify ethereum authorization request signatures and replay with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-kms-auth-003-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-kms-auth-003-step-02"></a>
### Step 2: Exercise supported and boundary paths

Submit valid and altered app/KMS authorization payloads, signer, chain ID, contract address, nonce/timestamp, duplicate, and replayed requests.

**Expected results:**

- Only domain-separated fresh authorized signatures are accepted and replay/cross-chain/cross-contract substitutions fail.

<a id="tc-kms-auth-003-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-kms-auth-003-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
