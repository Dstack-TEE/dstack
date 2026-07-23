<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-ui-observa-005"></a>
# TC-VMM-UI-OBSERVA-005: Web UI deployment workflows

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-ui-observa-005](../../../feature-audit.md#req-vmm-ui-observa-005)
- Risks: [risk-vmm-ui-observa-005](../../../feature-audit.md#risk-vmm-ui-observa-005)
- Source: `dstack/vmm/ui/src`

## Objective

Verify web ui deployment workflows across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-ui-observa-005-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for web ui deployment workflows.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-ui-observa-005-step-02"></a>
### Step 2: Exercise the behavior

Use UI to create, inspect, update, start/stop, resize, view logs, select simulated platform, networking, GPU, and images.

**Expected results:**

- UI payloads match RPC schema, display server errors/status accurately, preserve unset-vs-default fields, and remain keyboard usable.

<a id="tc-vmm-ui-observa-005-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
