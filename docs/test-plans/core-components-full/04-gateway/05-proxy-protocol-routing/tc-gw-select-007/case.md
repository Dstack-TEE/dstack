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

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify source-defined Top-N backend selection, handshake health filtering, cache stability and invalidation, identity isolation, live routing, and recovery.

## Preconditions

1. Start a case-owned Gateway, registered simulator identity, assigned address, and backend.
2. Use deterministic in-process instance and handshake state for branches that cannot be observed safely through a public API.

## Test Data

Use healthy, stale, missing-handshake, cached, newly added, removed, direct-instance, unknown-app, and cross-app rows.

## Steps

<a id="tc-gw-select-007-step-01"></a>
### Step 1: Execute the decision table

Populate controlled same-app instance and handshake state; exercise connect_top_n/cache_top_n, repeated selection, stale and missing handshakes, addition/removal invalidation, direct-instance lookup, and unknown-app rejection.

**Expected results:**

- Candidate sets contain only matching healthy instances, cached selection is stable within its TTL, state mutation invalidates the cache, and selection never crosses app identity.

<a id="tc-gw-select-007-step-02"></a>
### Step 2: Verify independent trust bindings and side effects

Run the same identity through the real Gateway listener and case-owned backend, then mutate the app identity and repeat the route.

**Expected results:**

- Valid TLS passthrough reaches only the registered backend, the cross-app mutation is rejected without backend traffic, and bounded evidence retains no identity or endpoint.

<a id="tc-gw-select-007-step-03"></a>
### Step 3: Verify outage, restart, and cross-identity isolation

Repeat the valid live route after the rejected identity mutation and inspect exact backend connection counts and cleanup.

**Expected results:**

- The valid route recovers, exactly two backend sessions occur, every ClientHello is preserved, and lease cleanup releases the assigned address and processes.

## Postconditions

Remove run-scoped evidence/state and restore trust, cache, routing and dependency baselines.
