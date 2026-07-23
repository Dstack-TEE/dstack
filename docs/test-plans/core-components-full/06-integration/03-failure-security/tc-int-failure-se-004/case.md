<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-int-failure-se-004"></a>
# TC-INT-FAILURE-SE-004: Certificate and clock boundary behavior

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-int-failure-se-004](../../../feature-audit.md#req-int-failure-se-004)
- Risks: [risk-int-failure-se-004](../../../feature-audit.md#risk-int-failure-se-004)
- Source: `dstack/tests/e2e`

## Objective

Verify certificate and clock boundary behavior across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-int-failure-se-004-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for certificate and clock boundary behavior.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-int-failure-se-004-step-02"></a>
### Step 2: Exercise the behavior

Skew clocks across guest/KMS/gateway/verifier around certificate, signature timestamp, ACME, and collateral boundaries.

**Expected results:**

- Defined tolerance is consistent; expired/not-yet-valid material fails and recovery after time correction requires no trust reset.

<a id="tc-int-failure-se-004-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
