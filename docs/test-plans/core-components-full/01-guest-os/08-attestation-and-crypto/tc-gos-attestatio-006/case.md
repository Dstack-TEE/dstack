<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-attestatio-006"></a>
# TC-GOS-ATTESTATIO-006: GPU boot attestation exposure

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-attestatio-006](../../../feature-audit.md#req-gos-attestatio-006)
- Risks: [risk-gos-attestatio-006](../../../feature-audit.md#risk-gos-attestatio-006)
- Source: `dstack/guest-agent/src/rpc_service.rs`

## Objective

Verify gpu boot attestation exposure across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-attestatio-006-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for gpu boot attestation exposure.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-attestatio-006-step-02"></a>
### Step 2: Exercise the behavior

Boot with and without supported GPUs and query GpuInfo.

**Expected results:**

- Collected nvattest JSON is returned unchanged for GPUs; the no-GPU response is empty and does not fail guest startup.

<a id="tc-gos-attestatio-006-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
