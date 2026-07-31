<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-vm-lifecyc-006"></a>
# TC-VMM-VM-LIFECYC-006: Auto-restart policy and backoff

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-vm-lifecyc-006](../../../feature-audit.md#req-vmm-vm-lifecyc-006)
- Risks: [risk-vmm-vm-lifecyc-006](../../../feature-audit.md#risk-vmm-vm-lifecyc-006)
- Source: `dstack/vmm/src/app.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Use `values.vmm.test_input.create_stopped_helper_argv` for the first valid creation and register its returned JSON `id` in `values.vmm.test_input.created_vms_registry` before any follow-on action. Use the exact `values.vmm.json_prpc_routes` and `values.vmm.commands.list_vms`; do not inspect the helper, VMM config, CLI help, or implementation source to rediscover these prepared interfaces. Poll public status for state transitions and asynchronous removal, and use bounded force-stop/remove cleanup unless graceful shutdown is the behavior under test.

## Objective

Verify auto-restart policy and backoff across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.
3. Fault injection targets only the QEMU child of a case-owned VM launcher; killing the launcher itself is not equivalent because it bypasses the launcher's child-reaping path.

## Policy semantics

- `interval` is the supervisor sampling period and must be greater than zero while automatic restart is enabled.
- `max_retries` bounds consecutive automatic restart attempts.
- `initial_backoff` delays the first retry; later retries double up to `max_backoff`.
- `reset_window` is the continuous healthy runtime required to restore the retry budget.
- A manual start or stop resets the automatic retry state, removal makes a VM ineligible, and a never-started VM is never eligible.
- After retry exhaustion, the public VM status remains `exited`; the policy must not rewrite a natural process exit as an operator-requested `stopped` state.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-vm-lifecyc-006-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for auto-restart policy and backoff.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-vm-lifecyc-006-step-02"></a>
### Step 2: Exercise the behavior

Crash eligible and ineligible VMs repeatedly around configured thresholds.

**Expected results:**

- Only eligible VMs restart; retry limits/backoff/reset windows and events match config without a hot loop.

<a id="tc-vmm-vm-lifecyc-006-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
