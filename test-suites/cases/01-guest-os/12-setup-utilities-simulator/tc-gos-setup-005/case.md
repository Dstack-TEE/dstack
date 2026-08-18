<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-005"></a>
# TC-GOS-SETUP-005: MR config ID verification before provisioning

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-setup-005](../../../../catalog/feature-audit.md#req-gos-setup-005)
- Risks: [risk-gos-setup-005](../../../../catalog/feature-audit.md#risk-gos-setup-005)
- Source: `dstack/dstack-util/src/system_setup/config_id_verifier.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Use the lease-owned hardware guest as the matching-ID integration row: it
  must reach `boot_progress=done` before any provisioned key/service state is
  accepted. The fixture's `ssh_argv`, `vmm_cli_argv`, identity fields, and
  serial log are sufficient; do not require a preconstructed platform matrix
  or external fault controller.
- Exercise matching, malformed, and field-specific mismatch behavior with the
  exact candidate `dstack-util` filter
  `system_setup::config_id_verifier::tests` from the shared Cargo target. These
  tests cover TDX v1/v3, non-TDX handling, compose/app/instance/GPU-policy/key
  provider bindings, failure-before-provisioning, and valid retry without
  consuming a live KMS/local-provider key. Run the filter concurrently only
  through Cargo's normal test scheduler; the verifier is pure and owns no
  service or persistent state.
- Grade verifier behavior, not the number or names of checked-in tests. Its
  field scope is compose hash, optional GPU-policy hash, app ID, instance ID,
  key-provider kind, and key-provider ID. Image, CPU, and general `vm_config`
  measurement belong to dedicated measurement cases. Non-TDX modes follow
  the explicit no-TDX-MR-config policy rather than a synthetic TDX ID.

## Objective

Verify mr config id verification before provisioning for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-setup-005-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Verify matching, mismatching, and malformed TDX v1/v3 MR config IDs, the explicit non-TDX policy, and independent changes to every v3-bound field.

**Expected results:**

- Only the exact expected ID permits provisioning; mismatch identifies bound input and no KMS/local key is consumed.

<a id="tc-gos-setup-005-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Run valid and invalid verifier inputs concurrently, then retry a valid value after every mismatch class.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-setup-005-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Confirm the live matching-ID guest reaches ready, re-query its identity, and verify the pure verifier created no persistent state.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
