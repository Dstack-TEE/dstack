<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-int-end-to-end-002"></a>
# TC-INT-END-TO-END-002: Application upgrade trust continuity

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-int-end-to-end-002](../../../feature-audit.md#req-int-end-to-end-002)
- Risks: [risk-int-end-to-end-002](../../../feature-audit.md#risk-int-end-to-end-002)
- Source: `dstack/tests/e2e`

## Objective

Verify application upgrade trust continuity across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-int-end-to-end-002-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for application upgrade trust continuity.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-int-end-to-end-002-step-02"></a>
### Step 2: Exercise the behavior

Upgrade compose/image through authorized policy while retaining protected data and rotating derived artifacts as specified.

**Expected results:**

- Authorized continuity works without exposing old secrets; unauthorized rollback/cross-app upgrade is rejected at VMM/KMS/gateway/verifier boundaries.

<a id="tc-int-end-to-end-002-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
