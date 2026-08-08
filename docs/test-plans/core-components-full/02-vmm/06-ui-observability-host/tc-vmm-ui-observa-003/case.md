<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-ui-observa-003"></a>
# TC-VMM-UI-OBSERVA-003: Host sealing-key provider integration

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-vmm-ui-observa-003](../../../feature-audit.md#req-vmm-ui-observa-003)
- Risks: [risk-vmm-ui-observa-003](../../../feature-audit.md#risk-vmm-ui-observa-003)
- Source: `dstack/vmm/src/host_api_service.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The case fixture enables the VMM key-provider client and prepares a real-TDX `key_provider=local` guest. Use `values.vmm.test_input.create_stopped_helper_argv`, start that registered VM, and wait up to 120 seconds for `boot_progress=done`; successful guest boot without a sealing/provider error is the valid-quote integration path because the guest obtains its own hardware quote. A host-originated synthetic quote is not positive evidence.
- `vmm-create-stopped.py` prints `{"id":"<uuid>"}`. Parse that UUID and pass it to `StartVm`, `StopVm`, and `RemoveVm`; do not use the VM name for lifecycle RPCs or CLI commands. Poll status by matching the UUID.
- Exercise malformed/empty direct `HostApi.GetSealingKey` requests only as negative rows through `values.host_api.probe_argv`. Preserve error structure and hashes only; never retain the quote, encrypted key, provider response, or other sealing material.

## Objective

Verify host sealing-key provider integration across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-ui-observa-003-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for host sealing-key provider integration.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-ui-observa-003-step-02"></a>
### Step 2: Exercise the behavior

Request sealing keys with valid/invalid quotes and provider failure.

**Expected results:**

- Encrypted key binds to verified evidence, provider quote is returned, and failures never return plaintext or stale keys.

<a id="tc-vmm-ui-observa-003-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
