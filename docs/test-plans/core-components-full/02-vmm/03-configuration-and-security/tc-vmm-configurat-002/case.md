<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-configurat-002"></a>
# TC-VMM-CONFIGURAT-002: External API authentication and listener separation

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-configurat-002](../../../feature-audit.md#req-vmm-configurat-002)
- Risks: [risk-vmm-configurat-002](../../../feature-audit.md#risk-vmm-configurat-002)
- Source: `dstack/vmm/src/main.rs`

## Objective

Verify external api authentication and listener separation across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-configurat-002-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for external api authentication and listener separation.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-configurat-002-step-02"></a>
### Step 2: Exercise the behavior

Call public VMM, host, UI, and log endpoints with valid, missing, expired, and wrong credentials.

**Expected results:**

- Only the intended surfaces are public; protected calls reject invalid credentials and host APIs remain bound to their private transport.

<a id="tc-vmm-configurat-002-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
