<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-entry-002"></a>
# TC-GOS-ENTRY-002: Guest-agent startup modes and partial listener failure

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-entry-002](../../../feature-audit.md#req-gos-entry-002)
- Risks: [risk-gos-entry-002](../../../feature-audit.md#risk-gos-entry-002)
- Source: `dstack/guest-agent/src/main.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The fixture must provide `values.guest_agent_startup_peer` for the adjacent
  identity check. Use the separate lease-owned peer only for isolation
  observations; all listener mutations remain bounded to case-owned processes.
- A malformed proof command is test infrastructure, not a product failure;
  retry it and grade only the corrected listener/startup observation.

## Objective

Verify guest-agent startup modes and partial listener failure exactly matches the source-defined behavior across normal, boundary, concurrent, failure, and restart paths.

## Preconditions

1. Use an isolated deployment with the relevant effective configuration and a clean run-scoped baseline.
2. Enable redacted process, file, RPC, and lifecycle evidence collection.

## Test Data

Include minimum, maximum, duplicate, missing, malformed, and cross-instance values appropriate to the behavior.

## Steps

<a id="tc-gos-entry-002-step-01"></a>
### Step 1: Record effective inputs and baseline

Capture effective configuration, input files/requests, existing processes/resources, and public status before the operation.

**Expected results:**

- Inputs resolve unambiguously to the intended test identity and no run-scoped output or resource exists.

<a id="tc-gos-entry-002-step-02"></a>
### Step 2: Exercise behavior and boundaries

Start the source-defined combined internal-v0, internal-current, external, and GuestApi listener set; exercise the two supported socket-activated internal listeners and watchdog; occupy the external bind and fail trusted-state initialization.

**Expected results:**

- All four configured listeners start with their correct services, the two internal listeners consume activated descriptors, watchdog observes the external service, partial startup cannot expose an unintended surface, and shutdown drops/joins the complete listener set.

<a id="tc-gos-entry-002-step-03"></a>
### Step 3: Inject failure and concurrency

Interrupt the primary dependency at its commit boundary, issue a conflicting concurrent operation, restore it, and retry once.

**Expected results:**

- At most one operation commits, failure cleanup releases all temporary resources, diagnostics identify the failed phase, and retry converges without duplicate state.

<a id="tc-gos-entry-002-step-04"></a>
### Step 4: Verify restart, isolation, and redaction

Restart the owning service where permitted and inspect state for this and an adjacent identity plus all collected output.

**Expected results:**

- Persisted and transient state follow policy, adjacent identities are unchanged, and no private material or credential appears in output.

## Postconditions

Remove run-scoped state and verify processes, files, devices, listeners, and allocations match baseline.
