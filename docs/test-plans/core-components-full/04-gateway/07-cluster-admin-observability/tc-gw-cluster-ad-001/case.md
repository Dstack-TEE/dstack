<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-cluster-ad-001"></a>
# TC-GW-CLUSTER-AD-001: WaveKV bootstrap replication and convergence

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-cluster-ad-001](../../../feature-audit.md#req-gw-cluster-ad-001)
- Risks: [risk-gw-cluster-ad-001](../../../feature-audit.md#risk-gw-cluster-ad-001)
- Source: `dstack/gateway/src/kv/sync_service.rs`

## Objective

Verify wavekv bootstrap replication and convergence across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gw-cluster-ad-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for wavekv bootstrap replication and convergence.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gw-cluster-ad-001-step-02"></a>
### Step 2: Exercise the behavior

Bootstrap 1→3 nodes, partition, concurrent updates, reconnect, and restart.

**Expected results:**

- Peer/node/instance/domain/cert state converges deterministically, tombstones prevent resurrection, and self identity remains stable.

<a id="tc-gw-cluster-ad-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
