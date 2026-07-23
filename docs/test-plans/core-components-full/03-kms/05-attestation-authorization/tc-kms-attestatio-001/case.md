<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-attestatio-001"></a>
# TC-KMS-ATTESTATIO-001: TDX full and lite app authorization

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-kms-attestatio-001](../../../feature-audit.md#req-kms-attestatio-001)
- Risks: [risk-kms-attestatio-001](../../../feature-audit.md#risk-kms-attestatio-001)
- Source: `dstack/kms/src/main_service.rs`

## Objective

Verify tdx full and lite app authorization across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-kms-attestatio-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for tdx full and lite app authorization.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-kms-attestatio-001-step-02"></a>
### Step 2: Exercise the behavior

Request app keys with valid and altered quote/event log/vm_config/image/compose inputs.

**Expected results:**

- Only evidence whose measurements and policy match is authorized; every altered binding is rejected before key derivation.

<a id="tc-kms-attestatio-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
