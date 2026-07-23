<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-int-end-to-end-004"></a>
# TC-INT-END-TO-END-004: Gateway certificate attestation verification

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-int-end-to-end-004](../../../feature-audit.md#req-int-end-to-end-004)
- Risks: [risk-int-end-to-end-004](../../../feature-audit.md#risk-int-end-to-end-004)
- Source: `dstack/tests/e2e`

## Objective

Verify gateway certificate attestation verification across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-int-end-to-end-004-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for gateway certificate attestation verification.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-int-end-to-end-004-step-02"></a>
### Step 2: Exercise the behavior

Issue gateway certificate, retrieve its history, and verify chain/attestation/image using verifier.

**Expected results:**

- Public certificate key and domain bind to valid gateway evidence and current trusted image across rotation.

<a id="tc-int-end-to-end-004-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
