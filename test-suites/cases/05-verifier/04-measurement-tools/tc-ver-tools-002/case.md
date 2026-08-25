<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-tools-002"></a>
# TC-VER-TOOLS-002: dstack-mr boot artifact and cmdline boundaries

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-ver-tools-002](../../../../catalog/feature-audit.md#req-ver-tools-002)
- Risks: [risk-ver-tools-002](../../../../catalog/feature-audit.md#risk-ver-tools-002)
- Source: `dstack/dstack-mr/src`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify dstack-mr boot artifact and cmdline boundaries with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The prepared `dstack-mr` candidate binary and manifest-declared extracted full-TDX image are available.
2. The case uses a run-scoped shared matrix cache keyed by run ID and candidate commit; the first of these two cases executes the matrix under a file lock and the second reuses the exact result.
3. Every artifact mutation occurs in a reflink/copy of the prepared image. This case consumes an image and does not test mkosi or Yocto construction.

## Test Data

Use the prepared 0.5.4.1 image, QEMU 8.x/9.x/10.x rows, every CLI configuration field, isolated artifact copies, malformed/missing inputs, and output hashes rather than raw boot artifacts.

## Steps

<a id="tc-ver-tools-002-step-01"></a>
### Step 1: Establish the baseline

Validate the prepared CLI hash, removed legacy version flag rejection, image manifest identity, and empty case workspace.

**Expected results:**

- The candidate CLI accepts the historical image version, emits four 48-byte measurements, and starts without case-owned output or mutation state.

<a id="tc-ver-tools-002-step-02"></a>
### Step 2: Exercise supported and boundary paths

Vary firmware, kernel, initrd, rootfs, cmdline ordering/quoting, CPU/QEMU version, and missing artifact inputs.

**Expected results:**

- Only measured changes alter defined registers; canonical cmdline rules match VMM and missing/ambiguous artifacts fail.

<a id="tc-ver-tools-002-step-03"></a>
### Step 3: Exercise failure and recovery

Run supported hugepage/NUMA plus unsupported old-QEMU, swtpm, invalid-version, malformed-metadata, and missing-artifact rows; then repeat the valid baseline.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-ver-tools-002-step-04"></a>
### Step 4: Verify isolation and persistence

Repeat measurement from an adjacent isolated image copy and compare it byte-for-byte with the baseline; verify the CLI leaves no persistent runtime state.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
