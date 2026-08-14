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

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify WaveKV key namespaces, encoding and corruption isolation, persistent/ephemeral boundaries, watch final-state delivery, deletion persistence, certificate ordering/locks, and live cluster visibility.

## Preconditions

1. Start a case-owned three-node Gateway cluster and isolated temporary WaveKV stores.
2. Keep raw values, credentials, identifiers, and node endpoints out of retained evidence.

## Test Data

Use every source-defined persistent and ephemeral key family, valid updates/deletes, malformed CBOR, duplicate attestation timestamps, lock contention, watcher bursts, restart, and tombstone rows.

## Steps

<a id="tc-gw-kv-009-step-01"></a>
### Step 1: Execute the decision table

Write/read/update/delete instance, node, status, connection, handshake, last-seen, peer, DNS, domain, certificate, lock, and attestation families; inject malformed values, duplicate timestamps, and watcher bursts.

**Expected results:**

- Key namespaces do not collide, malformed values are skipped without poisoning adjacent data, persistent values survive restart, ephemeral values do not, deletion survives restart, lock/history ordering is deterministic, and a coalesced watcher observes final state.

<a id="tc-gw-kv-009-step-02"></a>
### Step 2: Verify independent trust bindings and side effects

Reopen the isolated store after persistence, compare each persistent family, verify ephemeral absence, then reopen again after deletion.

**Expected results:**

- Reopened state matches the last committed persistent values, corrupted neighbors remain isolated, DNS credentials round-trip, and deleted instances do not resurrect.

<a id="tc-gw-kv-009-step-03"></a>
### Step 3: Verify outage, restart, and cross-identity isolation

Query each live Gateway debug interface and compare bounded peer and node visibility counts.

**Expected results:**

- All three nodes expose the expected cluster membership and peer visibility; cleanup removes every case-owned process and data directory.

## Post-baseline regression matrix

Inject corrupt global and per-record values, future timestamps, key/value identity mismatch, self-referential peers, replicated tombstones, IP/key conflicts, and unreadable certbot state. Verify global corruption fails boot closed, record-local corruption is quarantined without collateral loss, and operator removal prevents resurrection.

## Postconditions

Remove run-scoped evidence/state and restore trust, cache, routing and dependency baselines.
