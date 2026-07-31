<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-ui-observa-005"></a>
# TC-VMM-UI-OBSERVA-005: Web UI deployment workflows

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-ui-observa-005](../../../feature-audit.md#req-vmm-ui-observa-005)
- Risks: [risk-vmm-ui-observa-005](../../../feature-audit.md#risk-vmm-ui-observa-005)
- Source: `dstack/vmm/ui/src`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- `vmm-create-stopped.py` prints `{"id":"<uuid>"}`. Parse that UUID and pass it to `StartVm`, `StopVm`, and `RemoveVm`; do not use the VM name for lifecycle RPCs or CLI commands. Poll status by matching the UUID.
- Browser form updates can re-render controls and invalidate element references. Prefer semantic label/role locators, or take a fresh interactive snapshot after each update that changes the form before using another reference. Do not replace an incomplete UI submission with direct RPC calls and call the UI path successful.
- Use a unique case-scoped browser session name for every browser command and close only that session after capture. Never reuse the default or another case session; stale Chromium state can crash the page before product interaction.
- Step 1 health probes are `Version`, `Status`, `ListImages`, `ListGpus`, and the VM list. Do not call `GetInfo` without a real VM UUID: an empty/unknown ID is expected to return an error and is not a prerequisite failure. In Step 2, a browser-visible form alone is insufficient; at least one deployment must be submitted through the UI and observed by UUID before lifecycle checks. Do not substitute helper/direct RPC creation for the UI submission.
- Drive the form with stable semantic locators (`agent-browser find label <label> fill|select ...` and `find role button click --name ...`) rather than a chain of `@eN` references. Element references are snapshot-scoped and become stale after Vue updates. Use JavaScript evaluation with native `input`/`change` events only for unlabeled controls, then re-query state before submitting.
- Never run `get text body` on the self-contained VMM page because it includes the entire bundled application source and can add hundreds of kilobytes to the Agent session. Use scoped snapshots, `get value`, targeted element text, URL, screenshots, and public status instead.

## Objective

Verify web ui deployment workflows across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials. The browser must run in a fresh case-scoped context and submit a unique VM name through the rendered form.

## Browser evidence requirements

- A successful UI row requires observing the created VM by its server-returned UUID in the public VM list; direct RPC creation is not equivalent.
- Record the exact initial form values before editing so omitted values and explicit defaults remain distinguishable.
- Exercise one controlled server rejection and verify the dialog remains usable for a subsequent successful submission.
- Lifecycle, update/resize, and log actions must be initiated from UI controls; direct RPC calls are reserved for bounded final cleanup.
- A second fresh browser context must not inherit the first context's dialog or form state.

## Steps

<a id="tc-vmm-ui-observa-005-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for web ui deployment workflows.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-ui-observa-005-step-02"></a>
### Step 2: Exercise the behavior

Use UI to create, inspect, update, start/stop, resize, view logs, select simulated platform, networking, GPU, and images.

**Expected results:**

- UI payloads match RPC schema, display server errors/status accurately, preserve unset-vs-default fields, and remain keyboard usable.

<a id="tc-vmm-ui-observa-005-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
