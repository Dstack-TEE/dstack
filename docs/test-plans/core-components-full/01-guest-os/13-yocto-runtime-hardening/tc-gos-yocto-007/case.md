<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-yocto-007"></a>
# TC-GOS-YOCTO-007: Reproducible Yocto build and artifact export

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-gos-yocto-007](../../../feature-audit.md#req-gos-yocto-007)
- Risks: [risk-gos-yocto-007](../../../feature-audit.md#risk-gos-yocto-007)
- Source: `os/yocto/repro-build`

## Objective

Verify reproducible yocto build and artifact export for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-yocto-007-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Build twice in clean environments, export artifacts/SBOM/manifests, compare hashes and run the reproducibility checker with one changed source.

**Expected results:**

- Unchanged outputs are reproducible or documented nondeterminism is normalized; changed source changes declared artifacts and all exports match manifests.

<a id="tc-gos-yocto-007-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-yocto-007-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
