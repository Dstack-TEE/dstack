<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-admin-035"></a>
# TC-GW-ADMIN-035: Admin.ListRejectedInstances

## Metadata

- Priority: P0
- Type: Functional, API, Security, Recovery, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-admin-035](../../../feature-audit.md#req-gw-admin-035)
- Risks: [risk-gw-admin-035](../../../feature-audit.md#risk-gw-admin-035)
- Source: `dstack/gateway/rpc/proto/gateway_rpc.proto`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its candidate gateway, admin endpoint, credentials, and lease-owned state.
- The authoritative wire contract is the `Admin.ListRejectedInstances` entry in [`api-inventory.json`](../../../api-inventory.json).
- Never remove production or pre-existing records. All mutation targets must be created inside the case lease or be deliberately unknown sentinel identifiers.

## Objective

Verify the complete request, response, authorization, idempotency, failure-atomicity, and operator-recovery contract of `Admin.ListRejectedInstances`.

## Preconditions

1. A lease-owned candidate Gateway is healthy on separate public and authenticated admin listeners.
2. Baseline WaveKV, rejected-record, local data-plane, and sync-peer state is captured.

## Test Data

Exercise empty, unusable-record, conflict-loser, active-local, and recovered-record states, unknown protobuf fields, JSON and protobuf encodings, and missing admin credentials. The deterministic smoke payload is `{}`.

## Steps

<a id="tc-gw-admin-035-step-01"></a>
### Step 1: Verify the baseline and authorization boundary

Query health and bounded admin state, then invoke `Admin.ListRejectedInstances` without credentials and with malformed framing.

**Expected results:**

- The healthy baseline is unchanged; unauthenticated and malformed requests are rejected without disclosing records or mutating WaveKV, routing, or peer state.

<a id="tc-gw-admin-035-step-02"></a>
### Step 2: Exercise valid, absent, boundary, and repeated operations

Invoke `Admin.ListRejectedInstances` over JSON and protobuf with the case matrix, repeat each idempotent operation, and capture native responses.

**Expected results:**

- The response lists only rejected records with bounded reasons, rejection class, and local-active state; an empty baseline is valid.
- JSON and protobuf responses agree structurally, retries converge, and unknown fields do not weaken validation.

<a id="tc-gw-admin-035-step-03"></a>
### Step 3: Verify replicated recovery and isolation

Where the method mutates state, create the affected lease-owned record on one node, execute the recovery action, observe replication on a peer, restart the acting node, and repeat the request.

**Expected results:**

- Tombstones prevent resurrection, routing and peer membership converge, unrelated instances/nodes remain unchanged, and bounded diagnostics identify rejected state without secrets.

## Postconditions

Remove lease-owned records and verify WaveKV, local routing, sync peers, logs, and metrics return to the captured baseline.
