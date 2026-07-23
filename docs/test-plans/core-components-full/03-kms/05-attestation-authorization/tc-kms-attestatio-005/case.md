<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-attestatio-005"></a>
# TC-KMS-ATTESTATIO-005: Authorization backend matrix

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-attestatio-005](../../../feature-audit.md#req-kms-attestatio-005)
- Risks: [risk-kms-attestatio-005](../../../feature-audit.md#risk-kms-attestatio-005)
- Source: `dstack/kms/auth-simple/index.ts`

## Objective

Verify authorization backend matrix across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

The `kms` portion of [`configuration-inventory.json`](../../../configuration-inventory.json) is mandatory test data. Exercise every listed field at its implicit default, an explicit valid value, boundary-invalid values, an unknown sibling field, and after restart.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-kms-attestatio-005-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for authorization backend matrix.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-kms-attestatio-005-step-02"></a>
### Step 2: Exercise the behavior

Run mock, simple, Ethereum/Bun, and contract-backed authorization allow/deny/error/timeouts.

**Expected results:**

- Each backend maps identical app/KMS facts consistently, fails closed on malformed/timeout responses, and reports configured metadata.

<a id="tc-kms-attestatio-005-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
