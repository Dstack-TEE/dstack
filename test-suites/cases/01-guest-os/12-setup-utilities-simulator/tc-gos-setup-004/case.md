<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-004"></a>
# TC-GOS-SETUP-004: Staged system setup idempotence and config identity

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-setup-004](../../../../catalog/feature-audit.md#req-gos-setup-004)
- Risks: [risk-gos-setup-004](../../../../catalog/feature-audit.md#risk-gos-setup-004)
- Source: `dstack/dstack-util/src/system_setup.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The `no-tee-guest-lifecycle` fixture is deliberately returned while setup is
  in progress. Its `vm_id`, `vmm_cli_argv`, `serial_log_refresh_argv`, and
  `boot_observation` are the complete controls for this case; do not require a
  preconstructed matrix, block device handle, SSH session, or separate fault
  controller. Refresh the serial log and poll `info --json` together.
- Treat one complete boot followed by two lease-owned `stop --force` / `start`
  cycles with unchanged configuration as the stage idempotence matrix. Record
  the ordered prepare/stage/ready messages and stable app/instance identity.
  Use `update-user-config` with valid JSON and then malformed JSON as the
  changed/non-committing input boundary, restore the original valid file, and
  start once more. Never modify the host, shared VMM configuration, or another
  VM. The pre-test `lsvm --json` snapshot is the adjacent-identity baseline;
  every non-case VM must remain byte-for-byte unchanged in the projected
  identity/status fields.
- Run the candidate `dstack-util` `system_setup` and
  `system_setup::config_id_verifier` test filters from the shared target for
  the pure config-ID mismatch and malformed-boundary matrix that cannot safely
  be injected after guest provisioning. Do not grade the absence of a
  separately named test as a product result.

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
