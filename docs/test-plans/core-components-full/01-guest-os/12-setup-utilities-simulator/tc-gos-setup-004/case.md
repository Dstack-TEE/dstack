<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-004"></a>
# TC-GOS-SETUP-004: Staged system setup idempotence and config identity

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-setup-004](../../../feature-audit.md#req-gos-setup-004)
- Risks: [risk-gos-setup-004](../../../feature-audit.md#risk-gos-setup-004)
- Source: `dstack/dstack-util/src/system_setup.rs`

## Objective

Verify staged system setup idempotence and config identity for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-setup-004-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Run stage0/filesystem/stage1 setup twice, force and non-force, with identical and changed config IDs and an interrupted stage boundary.

**Expected results:**

- Identical rerun is idempotent, changed security config is verified/reprovisioned according to policy, and incomplete stages cannot be mistaken for ready.

<a id="tc-gos-setup-004-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-setup-004-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
