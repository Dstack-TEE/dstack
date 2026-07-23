<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-int-compatibil-002"></a>
# TC-INT-COMPATIBIL-002: Rolling VMM upgrade with running mixed guests

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-int-compatibil-002](../../../feature-audit.md#req-int-compatibil-002)
- Risks: [risk-int-compatibil-002](../../../feature-audit.md#risk-int-compatibil-002)
- Source: `dstack/vmm/src/app.rs`

## Objective

Verify rolling vmm upgrade with running mixed guests across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-int-compatibil-002-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for rolling vmm upgrade with running mixed guests.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-int-compatibil-002-step-02"></a>
### Step 2: Exercise the behavior

Upgrade VMM around running/stopped previous/new guests and persisted workdirs.

**Expected results:**

- Running service impact matches policy, reload preserves state/config, and all supported control operations remain compatible.

<a id="tc-int-compatibil-002-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
