<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-select-007"></a>
# TC-GW-SELECT-007: Top-N backend selection DNS cache and failover

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-select-007](../../../feature-audit.md#req-gw-select-007)
- Risks: [risk-gw-select-007](../../../feature-audit.md#risk-gw-select-007)
- Source: `dstack/gateway/src/main_service.rs`

## Objective

Verify top-n backend selection dns cache and failover against each source-defined branch and trust assertion.

## Preconditions

1. Prepare isolated valid evidence and one-field mutations for each named platform/version/state.
2. Record trust roots, image/config/app identifiers, policy and dependency baseline without private material.

## Test Data

Use a decision table containing every condition in Step 1, relevant conflicting combinations, boundary lengths and a pinned historical-format row.

## Steps

<a id="tc-gw-select-007-step-01"></a>
### Step 1: Execute the decision table

Register many same-app instances across nodes with controlled DNS/handshake/connection state; exercise connect_top_n/cache_top_n, repeated selection, stale/down/full hosts, concurrent removal and recovery.

**Expected results:**

- Candidate sets contain only matching allowed healthy instances, cache and randomization remain bounded/fair, stale/full/removed hosts are excluded promptly and retry never crosses app or port policy.

<a id="tc-gw-select-007-step-02"></a>
### Step 2: Verify independent trust bindings and side effects

Independently decode/verify evidence and compare policy inputs, cache/state mutation, returned public material and persisted artifacts for each row.

**Expected results:**

- Every accepted row satisfies all named bindings, rejected rows create no trusted cache/key/cert/route state, and output identifies the exact failed assertion.

<a id="tc-gw-select-007-step-03"></a>
### Step 3: Verify outage, restart, and cross-identity isolation

Interrupt the external verifier/auth/image/network dependency, restart after accepted/rejected rows, and replay evidence under another app/node identity.

**Expected results:**

- Uncertainty fails closed, recovery does not reuse stale decisions, accepted state survives only as documented, and cross-identity replay or substitution fails.

## Postconditions

Remove run-scoped evidence/state and restore trust, cache, routing and dependency baselines.
