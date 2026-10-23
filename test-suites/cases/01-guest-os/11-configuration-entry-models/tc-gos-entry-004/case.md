<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-entry-004"></a>
# TC-GOS-ENTRY-004: Guest-agent library initialization reuse

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-gos-entry-004](../../../../catalog/feature-audit.md#req-gos-entry-004)
- Risks: [risk-gos-entry-004](../../../../catalog/feature-audit.md#risk-gos-entry-004)
- Source: `dstack/guest-agent/src/lib.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify guest-agent library initialization reuse exactly matches the source-defined behavior across normal, boundary, concurrent, failure, and restart paths.

## Preconditions

1. Use an isolated deployment with the relevant effective configuration and a clean run-scoped baseline.
2. Enable redacted process, file, RPC, and lifecycle evidence collection.

## Test Data

Include minimum, maximum, duplicate, missing, malformed, and cross-instance values appropriate to the behavior.

## Steps

<a id="tc-gos-entry-004-step-01"></a>
### Step 1: Record effective inputs and baseline

Capture effective configuration, input files/requests, existing processes/resources, and public status before the operation.

**Expected results:**

- Inputs resolve unambiguously to the intended test identity and no run-scoped output or resource exists.

<a id="tc-gos-entry-004-step-02"></a>
### Step 2: Exercise behavior and boundaries

Construct service state repeatedly for tests, socket activation and full daemon paths with missing and complete dependencies.

**Expected results:**

- Initialization produces identical security configuration across entry points, owns each resource once, and teardown leaves no background task.

<a id="tc-gos-entry-004-step-03"></a>
### Step 3: Inject failure and concurrency

Interrupt the primary dependency at its commit boundary, issue a conflicting concurrent operation, restore it, and retry once.

**Expected results:**

- At most one operation commits, failure cleanup releases all temporary resources, diagnostics identify the failed phase, and retry converges without duplicate state.

<a id="tc-gos-entry-004-step-04"></a>
### Step 4: Verify restart, isolation, and redaction

Restart the owning service where permitted and inspect state for this and an adjacent identity plus all collected output.

**Expected results:**

- Persisted and transient state follow policy, adjacent identities are unchanged, and no private material or credential appears in output.

## Postconditions

Remove run-scoped state and verify processes, files, devices, listeners, and allocations match baseline.
