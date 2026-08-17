<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-009"></a>
# TC-GOS-SETUP-009: Gateway registration refresh and key-store persistence

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gos-setup-009](../../../feature-audit.md#req-gos-setup-009)
- Risks: [risk-gos-setup-009](../../../feature-audit.md#risk-gos-setup-009)
- Source: `dstack/dstack-util/src/system_setup.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify single- and multi-cluster gateway registration refresh and key-store
persistence for documented success, boundary, failure, concurrency, and
recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include legacy `gateway_urls`, grouped `gateway_clusters`, simultaneous legacy
and grouped configuration, valid and duplicate cluster names, multiple URLs in
one cluster, two independent clusters, malformed input, duplicate invocation,
a per-cluster dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-setup-009-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Register and refresh across multiple failover URLs in one cluster and across a
second independently operated cluster. Verify persisted per-cluster WireGuard
keys, distinct interfaces and listen ports, changed instance policy, wrong
identity, and repeated boot. Configure both `gateway_urls` and
`gateway_clusters` at the VMM boundary and through a guest sys-config input.

**Expected results:**

- URLs grouped under one cluster behave only as failover endpoints and produce
  one local cluster configuration.
- Independent clusters use distinct WireGuard keys, interfaces, caches, and
  listen ports while registering the same CVM identity.
- The VMM rejects simultaneous non-empty `gateway_urls` and
  `gateway_clusters`; a guest receiving both prefers `gateway_clusters` and
  emits a warning.
- Stable per-cluster key material and instance identity are reused securely,
  configuration updates atomically, and invalid gateway responses never
  replace working state.

<a id="tc-gos-setup-009-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt one cluster before and after its commit point while leaving the other
cluster healthy. Issue duplicate and concurrent requests, fail an apply after
the replacement configuration is written, restore the dependency, and retry.

**Expected results:**

- A failed cluster retains its last-known-good interface and configuration;
  successful clusters update independently in the same refresh.
- A first-time apply failure removes its false configuration marker, and a
  replacement apply failure restores the previous working configuration.
- Uncertain input fails closed, no partial trusted output is consumed, retry
  converges once, and diagnostics identify the exact cluster and phase without
  secrets.

<a id="tc-gos-setup-009-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Reordering or retrying does not cause clusters to share cached private keys;
  the adjacent identity is unchanged, no credential is exposed, and files,
  mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
