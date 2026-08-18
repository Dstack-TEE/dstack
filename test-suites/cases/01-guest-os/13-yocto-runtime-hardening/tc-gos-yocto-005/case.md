<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-yocto-005"></a>
# TC-GOS-YOCTO-005: Sysbox runtime services and nested-container boundary

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: mkosi guest with Sysbox
- Automation: Yes
- Requirements: [req-gos-yocto-005](../../../../catalog/feature-audit.md#req-gos-yocto-005)
- Risks: [risk-gos-yocto-005](../../../../catalog/feature-audit.md#risk-gos-yocto-005)
- Source: `os/mkosi/components/sysbox`, `os/mkosi/parity.json`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

- Execute image behavior only when the fixture-provided image provenance reports `builder: mkosi`; an older Yocto image with the same `dstack-0.6.0` or `dstack-dev-0.6.0` name is not valid evidence for this run.

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

Start/stop/restart Sysbox services, verify UID/GID remapping, and run a pinned Docker-in-Docker workload that requests mounts, proc/sys, devices, and cgroups from its outer Sysbox container.

**Expected results:**

- Supported nested containers work while the physical host, VMM control plane, agent sockets, `/dev/kvm`, and resources outside the outer Sysbox container remain protected.
- `/dev/tdx_guest` and virtual disks belong to the lease-owned guest and are not physical-host devices; their presence alone is not a boundary failure.

<a id="tc-gos-yocto-005-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-yocto-005-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning services, re-query affected state and adjacent VM inventory, and perform documented cleanup. A VM reboot is not required because this case exercises runtime lifecycle rather than image construction or boot correctness.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
