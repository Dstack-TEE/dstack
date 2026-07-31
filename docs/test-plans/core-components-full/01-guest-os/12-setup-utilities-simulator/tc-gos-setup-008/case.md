<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-008"></a>
# TC-GOS-SETUP-008: Swap file and ZFS zvol setup

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-setup-008](../../../feature-audit.md#req-gos-setup-008)
- Risks: [risk-gos-setup-008](../../../feature-audit.md#risk-gos-setup-008)
- Source: `dstack/dstack-util/src/system_setup.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The `guest-readonly` fixture's `ssh_argv` and lease-owned persistent data
  disk are the complete swap/ZFS controls. `destructive_actions_allowed=true`
  applies only to this VM. Discover zvol/swap paths inside the guest with
  bounded `zfs`, `zpool`, `swapon`, `findmnt`, and `lsblk` queries; do not
  require preconstructed path or fault-controller fields in the manifest.
- Record the baseline, exercise idempotent setup and size boundaries, perform
  one lease-owned service interruption, restore it, and verify the original
  pool/dataset and non-case VMM inventory projection. Abort polling as soon as
  a command returns a definitive unsupported or corruption error.

## Objective

Verify swap file and zfs zvol setup for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-setup-008-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Configure disabled/file/zvol swap at size boundaries, repeat setup, exhaust disk, use existing wrong-size object and reboot.

**Expected results:**

- Exactly the configured encrypted-safe swap becomes active, duplicate setup is idempotent, invalid storage fails clearly and no stale swap remains.

<a id="tc-gos-setup-008-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-setup-008-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
