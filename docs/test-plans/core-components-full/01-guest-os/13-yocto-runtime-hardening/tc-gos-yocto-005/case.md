<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-yocto-005"></a>
# TC-GOS-YOCTO-005: Sysbox runtime services and nested-container boundary

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-yocto-005](../../../feature-audit.md#req-gos-yocto-005)
- Risks: [risk-gos-yocto-005](../../../feature-audit.md#risk-gos-yocto-005)
- Source: `os/yocto/layers/meta-dstack/recipes-core/dstack-sysbox`

## Objective

Verify sysbox runtime services and nested-container boundary for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-yocto-005-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Start/stop/restart sysbox services and run nested workloads requesting host mounts, proc/sys, devices, cgroups and privilege escalation.

**Expected results:**

- Supported nested containers work while host kernel/files/devices/agent sockets remain protected; service failure affects only selected workloads.

<a id="tc-gos-yocto-005-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-yocto-005-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
