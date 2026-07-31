<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-010"></a>
# TC-GOS-SETUP-010: Host API notify and sealing-key client

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-setup-010](../../../feature-audit.md#req-gos-setup-010)
- Risks: [risk-gos-setup-010](../../../feature-audit.md#risk-gos-setup-010)
- Source: `dstack/dstack-util/src/host_api.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify direct and best-effort Host API notification plus fail-closed sealing-key retrieval through the source-defined URL, quote, collateral, and key-binding paths.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Use a lease-owned real-TDX local-provider guest, host-originated invalid requests, wrong-typed and unknown fields/routes, and redacted public lifecycle evidence.

## Steps

<a id="tc-gos-setup-010-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Resolve the fixture Host API and PCCS dependencies, boot one real-TDX local-provider guest, observe guest-originated notifications, and retrieve its sealing key.

**Expected results:**

- Direct notification reaches the VM identity while best-effort notification never invents durable queue semantics; sealing succeeds only after quote, collateral, TCB, encrypted-key hash, and sealed-box checks.

<a id="tc-gos-setup-010-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Send empty, wrong-typed, unknown-field, unknown-route, and host-originated requests after the successful guest flow, then re-query guest state.

**Expected results:**

- Invalid requests fail closed, cannot bypass the guest CID binding, expose no usable key material, and do not disturb the successfully sealed guest.

<a id="tc-gos-setup-010-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Compare the lease baseline and final VM inventory, inspect bounded public events/logs for sealing failure, and remove the case-owned guest.

**Expected results:**

- The case-owned guest is absent after cleanup, unrelated baseline identities remain present, and no quote, encrypted key, provider quote, sealing key, or raw provider response is persisted.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
