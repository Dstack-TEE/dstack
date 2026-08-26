<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-entry-003"></a>
# TC-GOS-ENTRY-003: Dashboard and metrics model escaping and units

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-entry-003](../../../../catalog/feature-audit.md#req-gos-entry-003)
- Risks: [risk-gos-entry-003](../../../../catalog/feature-audit.md#risk-gos-entry-003)
- Source: `dstack/guest-agent/src/models.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify dashboard and metrics model escaping and units exactly matches the source-defined behavior across normal, boundary, concurrent, failure, and restart paths.

## Preconditions

1. Use the checked-in deterministic render harness against the exact candidate `models.rs`, `dashboard.html`, and `metrics.tpl` files.
2. Do not retain rendered hostile text; retain only assertion booleans, lengths, and hashes.

## Test Data

Use HTML metacharacters, Prometheus label quotes/backslashes/newlines, Unicode, empty optional container names, 0/1023/1024/maximum integer values, and 256 disk records.

## Steps

<a id="tc-gos-entry-003-step-01"></a>
### Step 1: Record effective inputs and baseline

Copy the exact candidate model source and templates into an isolated temporary probe crate.

**Expected results:**

- The probe uses the candidate `guest-api` types and exact candidate templates without changing the component workspace.

<a id="tc-gos-entry-003-step-02"></a>
### Step 2: Exercise behavior and boundaries

Render dashboard and metrics with the deterministic hostile strings, boundary counters, optional names, and high-cardinality disk list.

**Expected results:**

- HTML text and attribute contexts are escaped, Prometheus label quotes/backslashes/newlines are escaped, hex and optional names render correctly, numeric metrics remain exact, human-readable sizes cross 1024 correctly, and every bounded synthetic disk record renders.

<a id="tc-gos-entry-003-step-03"></a>
### Step 3: Inject failure and concurrency

Render the immutable presentation model concurrently and compare successful completion and stable output characteristics, then remove the temporary probe.

**Expected results:**

- Concurrent renders complete without panic or shared-state corruption, and the temporary probe is removed automatically.

<a id="tc-gos-entry-003-step-04"></a>
## Postconditions

The temporary probe is removed and the report retains no raw hostile rendered page or credential material.
