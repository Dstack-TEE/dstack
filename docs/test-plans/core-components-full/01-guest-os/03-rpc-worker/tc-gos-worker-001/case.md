<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-worker-001"></a>
# TC-GOS-WORKER-001: Worker.Info

## Metadata

- Priority: P1
- Type: Functional, API, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-worker-001](../../../feature-audit.md#req-gos-worker-001)
- Risks: [risk-gos-worker-001](../../../feature-audit.md#risk-gos-worker-001)
- Source: `dstack/guest-agent/rpc/proto/agent_rpc.proto:255`

## Objective

Verify the complete request, response, authorization, state transition, and error contract of `Worker.Info`.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

The `Worker.Info` entry in [`api-inventory.json`](../../../api-inventory.json) is mandatory test data. Exercise every request field and every recursively referenced message field as absent/default, valid, boundary-invalid and combined with an unknown field; validate every response field, nested message field, and presence bit.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-worker-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for worker.info.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-worker-001-step-02"></a>
### Step 2: Exercise the behavior

Invoke `Worker.Info` with a valid `google.protobuf.Empty` request using valid service-specific authentication and attestation context; capture the binary and JSON pRPC representations. Then send a schema-invalid request and, where protected, omit the credential.

**Expected results:**

- The valid call returns `AppInfo` with every documented field and exhibits the documented `Info` state and side effects; invalid framing or fields return a structured error, and protected calls reject missing credentials.

<a id="tc-gos-worker-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
