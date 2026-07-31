<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-boot-and-i-005"></a>
# TC-GOS-BOOT-AND-I-005: Host notification boot and shutdown events

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-boot-and-i-005](../../../feature-audit.md#req-gos-boot-and-i-005)
- Risks: [risk-gos-boot-and-i-005](../../../feature-audit.md#risk-gos-boot-and-i-005)
- Sources: `dstack/dstack-util/src/system_setup.rs:2370-2783`,
  `dstack/guest-agent/src/guest_api_service.rs:52-58`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- This is a guest-lifecycle integration case, not a user-space GuestApi RPC
  simulator case. It requires a case-scoped guest, a case-scoped HostApi Notify
  recorder, and `destructive_actions_allowed: true` for that guest. The recorder
  must expose its initially empty event stream and preserve ordered timestamped
  payloads through terminal shutdown. If any item is absent from the runtime
  manifest, report BLOCKED directly; never shut down a shared guest.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify host notification boot and shutdown events across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The runtime manifest records a dedicated disposable guest and HostApi Notify
   recorder for this case, with lifecycle actions explicitly allowed.
2. The recorder is reachable and has no event bearing the run-scoped ID before
   boot. A shared guest or the user-space guest-agent simulator is insufficient.
3. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gos-boot-and-i-005-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for host notification boot and shutdown events.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gos-boot-and-i-005-step-02"></a>
### Step 2: Exercise the behavior

Complete boot and graceful shutdown while recording HostApi.Notify.

**Expected results:**

- Ordered progress events contain valid timestamps and payloads and terminal shutdown is reported once.

<a id="tc-gos-boot-and-i-005-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
