<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-build-002"></a>
# TC-VER-BUILD-002: Verifier default configuration and CLI override precedence

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-ver-build-002](../../../feature-audit.md#req-ver-build-002)
- Risks: [risk-ver-build-002](../../../feature-audit.md#risk-ver-build-002)
- Source: `dstack/verifier/dstack-verifier.toml`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The verifier CLI exposes `--config`, `--verify`, and `--verify-cert`; it does
  not expose one CLI flag per configuration field. Effective field precedence
  is embedded defaults, then the file selected by `--config`, then
  `DSTACK_VERIFIER_` environment variables. Test that supported interface and
  do not fail because image/cache/trust fields have no direct CLI flags.

## Objective

Verify verifier default configuration and cli override precedence for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Use the prepared verifier binary, checked-in full-TDX request, and manifest-declared extracted image in case-owned caches.
2. Every service uses an ephemeral loopback port and subprocess-only `DSTACK_VERIFIER_` overrides. Native outputs remain in the retained debug workspace on failure; evidence records only hashes and bounded status fields.

## Test Data

The `verifier` portion of [`configuration-inventory.json`](../../../configuration-inventory.json) is mandatory test data. Exercise every listed field at its implicit default, an explicit valid value, boundary-invalid values, an unknown sibling field, and after restart.

Include valid file values, top-level and nested environment overrides, zero/empty/malformed/unknown values, `--verify` and `--verify-cert`, concurrent duplicate verification, an image dependency outage followed by recovery, restart, and an adjacent service port.

## Steps

<a id="tc-ver-build-002-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Run embedded-default, `--config`-selected file, and `DSTACK_VERIFIER_`
environment combinations for image URL/cache/trust/collateral/ACPI/timeouts,
with unknown and invalid values. Exercise `--verify` and `--verify-cert` mode
selection separately from field precedence.

**Expected results:**

- Precedence is deterministic and observable, unsafe/missing required trust config fails at startup, and overrides cannot silently disable required verification.

<a id="tc-ver-build-002-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Interrupt each external dependency before and after its commit point, issue a duplicate/concurrent request, restore the dependency, and retry.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-ver-build-002-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Restart the owning service or VM where permitted, re-query all affected state, test the adjacent identity, and perform documented cleanup.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
