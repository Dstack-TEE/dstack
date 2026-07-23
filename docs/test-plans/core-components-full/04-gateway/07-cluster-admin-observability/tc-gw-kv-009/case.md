<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-kv-009"></a>
# TC-GW-KV-009: WaveKV key encoding corruption persistence and watch semantics

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-kv-009](../../../feature-audit.md#req-gw-kv-009)
- Risks: [risk-gw-kv-009](../../../feature-audit.md#risk-gw-kv-009)
- Source: `dstack/gateway/src/kv/mod.rs`

## Objective

Verify wavekv key encoding corruption persistence and watch semantics against each source-defined branch and trust assertion.

## Preconditions

1. Prepare isolated valid evidence and one-field mutations for each named platform/version/state.
2. Record trust roots, image/config/app identifiers, policy and dependency baseline without private material.

## Test Data

Use a decision table containing every condition in Step 1, relevant conflicting combinations, boundary lengths and a pinned historical-format row.

## Steps

<a id="tc-gw-kv-009-step-01"></a>
### Step 1: Execute the decision table

Write/read/delete every instance/node/status/connection/handshake/peer/DNS/domain/cert/lock/attestation key family; inject malformed encoded values, partial persistence, tombstones, duplicate timestamps and watcher bursts.

**Expected results:**

- Key namespaces parse without collision, malformed values are isolated/reported, persistent and ephemeral data follow policy, tombstones prevent resurrection, locks/history order correctly and watchers coalesce without missing final state.

<a id="tc-gw-kv-009-step-02"></a>
### Step 2: Verify independent trust bindings and side effects

Independently decode/verify evidence and compare policy inputs, cache/state mutation, returned public material and persisted artifacts for each row.

**Expected results:**

- Every accepted row satisfies all named bindings, rejected rows create no trusted cache/key/cert/route state, and output identifies the exact failed assertion.

<a id="tc-gw-kv-009-step-03"></a>
### Step 3: Verify outage, restart, and cross-identity isolation

Interrupt the external verifier/auth/image/network dependency, restart after accepted/rejected rows, and replay evidence under another app/node identity.

**Expected results:**

- Uncertainty fails closed, recovery does not reuse stale decisions, accepted state survives only as documented, and cross-identity replay or substitution fails.

## Postconditions

Remove run-scoped evidence/state and restore trust, cache, routing and dependency baselines.
