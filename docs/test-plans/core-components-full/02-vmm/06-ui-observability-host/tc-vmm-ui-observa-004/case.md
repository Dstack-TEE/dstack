<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-ui-observa-004"></a>
# TC-VMM-UI-OBSERVA-004: Supervisor passthrough operations

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-ui-observa-004](../../../feature-audit.md#req-vmm-ui-observa-004)
- Risks: [risk-vmm-ui-observa-004](../../../feature-audit.md#risk-vmm-ui-observa-004)
- Source: `dstack/vmm/src/main_service.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- A VM created with the stopped flag is persisted by VMM but has no supervisor process. Create and register the VM with `values.vmm.test_input.create_stopped_helper_argv`, call `StartVm`, and poll `SvList` until that exact VM ID appears before grading `SvStop` or `SvRemove`.
- `vmm-create-stopped.py` prints `{"id":"<uuid>"}`. Parse that UUID and pass it to `StartVm`, `StopVm`, and `RemoveVm`; do not use the VM name for lifecycle RPCs or CLI commands. Poll status by matching the UUID.
- The fixture disables VMM auto-restart for this case. After `SvStop`, require the process entry to remain with stopped state; then call `SvRemove` and require the entry to disappear. Use public `RemoveVm` afterward to clean up the persisted VMM definition.

## Objective

Verify supervisor passthrough operations across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-ui-observa-004-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for supervisor passthrough operations.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-ui-observa-004-step-02"></a>
### Step 2: Exercise the behavior

List, stop, and remove supervisor workloads through VMM.

**Expected results:**

- Operations target the requested workload, reflect terminal state, and reject unknown IDs without affecting CVMs.

<a id="tc-vmm-ui-observa-004-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
