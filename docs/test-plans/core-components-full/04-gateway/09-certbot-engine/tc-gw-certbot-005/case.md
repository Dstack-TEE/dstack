<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-certbot-005"></a>
# TC-GW-CERTBOT-005: Certbot workdir archive live and rollback layout

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-certbot-005](../../../feature-audit.md#req-gw-certbot-005)
- Risks: [risk-gw-certbot-005](../../../feature-audit.md#risk-gw-certbot-005)
- Source: `dstack/certbot/src/workdir.rs`

## Objective

Verify certbot workdir archive live and rollback layout for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gw-certbot-005-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Create successive cert generations, inspect live/archive links/permissions, interrupt each write/rename, corrupt current link and recover.

**Expected results:**

- Generations are immutable and ordered, live points atomically to complete matching key/cert, private files are restricted and prior valid generation supports rollback.

<a id="tc-gw-certbot-005-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gw-certbot-005-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
