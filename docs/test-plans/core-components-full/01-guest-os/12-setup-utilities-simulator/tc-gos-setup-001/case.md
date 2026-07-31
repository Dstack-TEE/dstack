<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-001"></a>
# TC-GOS-SETUP-001: Environment JSON allowlist parsing

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-gos-setup-001](../../../feature-audit.md#req-gos-setup-001)
- Risks: [risk-gos-setup-001](../../../feature-audit.md#risk-gos-setup-001)
- Source: `dstack/dstack-util/src/parse_env_file.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- `parse_env` and `convert_env_to_str` are pure, in-process functions. They
  have no dependency, commit boundary, persistent resource, service restart,
  or adjacent identity. Use the plan-owned acceptance harness, which includes
  the exact candidate `parse_env_file.rs` in an isolated temporary crate. It covers allowlist
  filtering, duplicate-key behavior, deterministic ordering, shell escaping,
  malformed JSON/key input, item/value/total bounds, and a valid retry after
  errors. Parallel test execution is the concurrency boundary; Step 3 verifies
  that no case-owned file/process/listener was created and scans output for
  unauthorized values or credentials. The checked-in unit-test count is not a
  product result and must not be used as a substitute for exercising behavior.

## Objective

Verify environment json allowlist parsing for documented success, boundary, failure, concurrency, and recovery behavior.

## Preconditions

1. Prepare isolated run-scoped inputs and capture effective configuration, service state, files, mounts, processes, network endpoints, and public status.
2. Use sentinel credentials only; evidence records hashes/presence and never the secret value.

## Test Data

Include valid values, empty/minimum/maximum values, malformed input, duplicate invocation, a dependency outage, and an adjacent app or node identity.

## Steps

<a id="tc-gos-setup-001-step-01"></a>
### Step 1: Exercise the complete behavior matrix

Parse string/number/bool/null/nested/duplicate/Unicode/oversized environment JSON with empty, partial and full allowlists; convert accepted values to the Docker env file.

**Expected results:**

- Only allowed scalar keys appear once with exact documented conversion and escaping; disallowed/nested/ambiguous values are rejected and no injection creates another variable.

<a id="tc-gos-setup-001-step-02"></a>
### Step 2: Verify failure atomicity and recovery

Issue malformed and over-limit inputs, repeat valid and invalid calls concurrently, and retry a valid call after every error class.

**Expected results:**

- Uncertain input fails closed, no partial trusted output is consumed, resources are released, retry converges once, and diagnostics identify the exact phase without secrets.

<a id="tc-gos-setup-001-step-03"></a>
### Step 3: Verify persistence, isolation, and cleanup

Repeat the pure conversion, verify deterministic ordering and output isolation, and remove the temporary harness.

**Expected results:**

- Persistent/transient state follows policy, the adjacent identity is unchanged, no credential is exposed, and files, mounts, devices, processes, listeners, and counters return to baseline.

## Postconditions

Remove run-scoped inputs and faults; preserve redacted native outputs and required attachments.
