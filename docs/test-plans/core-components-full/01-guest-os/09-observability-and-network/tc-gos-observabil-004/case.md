<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-observabil-004"></a>
# TC-GOS-OBSERVABIL-004: System network and resource telemetry

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-observabil-004](../../../feature-audit.md#req-gos-observabil-004)
- Risks: [risk-gos-observabil-004](../../../feature-audit.md#risk-gos-observabil-004)
- Source: `dstack/guest-agent/src/guest_api_service.rs`

## Objective

Verify system network and resource telemetry across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-observabil-004-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for system network and resource telemetry.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-observabil-004-step-02"></a>
### Step 2: Exercise the behavior

Change interfaces, routes, DNS, load, memory, disk, swap, and container set.

**Expected results:**

- GuestApi reports complete current values with correct units, prefixes, counters, and disappearance of removed resources.

<a id="tc-gos-observabil-004-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
