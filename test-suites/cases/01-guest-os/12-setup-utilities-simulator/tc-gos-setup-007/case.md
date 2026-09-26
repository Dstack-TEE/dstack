<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-007"></a>
# TC-GOS-SETUP-007: Data disk encryption filesystem repair and mount

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-setup-007](../../../../catalog/feature-audit.md#req-gos-setup-007)
- Risks: [risk-gos-setup-007](../../../../catalog/feature-audit.md#risk-gos-setup-007)
- Source: `dstack/dstack-util/src/system_setup.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The `guest-readonly` fixture exposes a lease-owned guest through `ssh_argv`;
  its persistent `/dev/vdb` data disk, mounts, and filesystems are the required
  matrix controls. `destructive_actions_allowed=true` permits mutation of that
  VM and disk only. Do not require a separate block-device or fault-controller
  object in the manifest, and never inspect or modify host disks.
- Capture `lsblk --json`, `findmnt --json`, LUKS metadata, filesystem state,
  and service state before mutation. Stop application services before bounded
  corruption/repair probes, restore them afterward, and stop immediately on a
  non-lease device identity. Treat an explicit filesystem/tool error as an
  early terminal observation rather than waiting out a generic timeout.

## Objective

Verify data disk encryption filesystem repair and mount for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-setup-007-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Provision fresh/existing encrypted data disks, wrong key, corrupt filesystem, failed fsck, full disk, device replacement, remount and reboot.

**Expected results:**

- Correct key mounts the intended filesystem with data continuity; wrong/corrupt devices fail before app start, repair policy is explicit, and keys never enter process lists/logs.

<a id="tc-gos-setup-007-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-setup-007-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Post-baseline regression coverage (PR #1175)

The lease compose selects `storage_fs: "ext4"` and omits `storage_discard`, so discard must default on for the product data disk.

- Before the first mutation and again after the lease reboot (existing-disk mount path), `/sys/block/vdb/queue/discard_max_bytes` is greater than 0, `cryptsetup status dstack_data_disk` reports `flags: discards`, and the `/dstack/persistent` mount options include `discard`. Automated in `run.py` (exit 95 on mismatch).
- Not automated (needs a second lease guest): an app compose with `storage_discard: false` must open the LUKS volume without `--allow-discards`, mount ext4 without `discard`, and change the compose hash relative to the default manifest; the VMM side of the opt-out (`discard=ignore`) is covered in the VMM chapter.

## Post-baseline regression coverage (PR #1339)

- `luksFormat` now labels a new data disk `dstack-initializing`, and setup
  clears the label only after the filesystem exists; a disk that still carries
  it is treated as interrupted and initialized again instead of failing header
  validation. Before the first mutation and after the lease reboot, the LUKS
  header behind `dstack_data_disk` must report `Label: (no label)` (exit 96
  otherwise), and the case-owned files under `/dstack/persistent` must survive
  the reboot.
- Not automated: interrupting the first-boot initialization between
  `luksFormat` and filesystem creation needs a guest killed mid-setup. The
  header parser's acceptance of the label is exercised by the `system_setup`
  unit filter in
  [tc-gos-setup-004](../tc-gos-setup-004/case.md#tc-gos-setup-004).

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
