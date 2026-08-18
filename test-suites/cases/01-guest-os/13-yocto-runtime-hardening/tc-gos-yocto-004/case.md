<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-yocto-004"></a>
# TC-GOS-YOCTO-004: Containerd stargz snapshotter integrity and fallback

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gos-yocto-004](../../../../catalog/feature-audit.md#req-gos-yocto-004)
- Risks: [risk-gos-yocto-004](../../../../catalog/feature-audit.md#risk-gos-yocto-004)
- Source: `os/mkosi/components/container-stack`, `os/mkosi/parity.json`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The guest image is BusyBox based: it does not provide an in-guest `timeout` command, GNU short `head -8` syntax, or procps `ps -p`. Apply timeouts around each host-side invocation of `values.ssh_argv`; inside the guest use BusyBox-compatible `head -n 8`, `ps -o`, `systemctl`, `ctr`, `nerdctl`, and `containerd-stargz-grpc` commands. A missing convenience utility or incompatible probe syntax is a test-probe defect and must be corrected before grading the candidate. Stop/start only lease-owned guest services and restore their configuration.

- Execute image behavior only when the fixture-provided image provenance reports `builder: mkosi`; an older Yocto image with the same `dstack-0.6.0` or `dstack-dev-0.6.0` name is not valid evidence for this run.

## Objective

Verify containerd stargz snapshotter integrity and fallback for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-yocto-004-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Pull and run OCI-digest-verified normal and lazy images, then exercise corrupted content, an unavailable registry, snapshotter restart, cache reuse, concurrency, and explicit overlay fallback.

**Expected results:**

- OCI digest-verified content runs with the selected snapshotter, corrupt layers never execute, the explicit caller-selected overlay fallback follows policy, and cache/restart preserves isolation; no silent automatic fallback is claimed.

<a id="tc-gos-yocto-004-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-yocto-004-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
