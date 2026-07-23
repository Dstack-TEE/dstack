<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-proxy-prot-006"></a>
# TC-GW-PROXY-PROT-006: Connection limits timeouts and recycling

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-proxy-prot-006](../../../feature-audit.md#req-gw-proxy-prot-006)
- Risks: [risk-gw-proxy-prot-006](../../../feature-audit.md#risk-gw-proxy-prot-006)
- Source: `dstack/gateway/src/proxy/io_bridge.rs`

## Objective

Verify connection limits timeouts and recycling across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gw-proxy-prot-006-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for connection limits timeouts and recycling.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gw-proxy-prot-006-step-02"></a>
### Step 2: Exercise the behavior

Exhaust global/per-host connections, idle/handshake timeouts, half-close, and recycle intervals.

**Expected results:**

- Limits reject excess predictably, counters return to baseline, half-close drains correctly, and no task/socket leak remains.

<a id="tc-gw-proxy-prot-006-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
