<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-manifest-001"></a>
# TC-VMM-MANIFEST-001: Proxied GuestApi transport and VM targeting

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-manifest-001](../../../../catalog/feature-audit.md#req-vmm-manifest-001)
- Risks: [risk-vmm-manifest-001](../../../../catalog/feature-audit.md#risk-vmm-manifest-001)
- Source: `dstack/vmm/src/guest_api_service.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Create and register targets with `values.vmm.test_input.create_stopped_helper_argv`; invoke it directly or use only its validated compatibility options. Do not reconstruct a helper command from the underlying VMM CLI.
- Use `values.vmm.json_prpc_routes.RemoveVm` with `{"id":"<registered-id>"}` for the concurrent-removal row and poll public Status until absence. The CLI has no generic `remove <id>` form suitable for this race. Start the proxy request and RemoveVm concurrently against that same registered ID, then require a bounded response or closed error without fallback to any other VM.
- For dependency interruption, stop only the registered target VM through `StopVm` with `{"id":"<registered-id>","force":true}`, observe that its proxied GuestApi request fails closed, restart it with `StartVm`, and repeat the same proxied request. Never signal, stop, restart, or kill the fixture VMM process itself; its PID is diagnostic metadata, not a fault-injection handle.

## Objective

Verify proxied guestapi transport and vm targeting with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence. Native GuestInfo certificates, TCB bodies, device identifiers, container records, and system/network responses must remain in memory; persist only status, timing, JSON field names, response hashes, and hashes of the projected app/instance/version identity.

A concurrent proxy/remove result may be either the selected guest's completed response or a bounded closed error. A successful response must match the disappearing target's previously observed projected identity and must never match or fall back to an adjacent VM.

## Steps

<a id="tc-vmm-manifest-001-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-vmm-manifest-001-step-02"></a>
### Step 2: Exercise supported and boundary paths

Call Info/SysInfo/NetworkInfo/ListContainers/Shutdown for running, stopped, unknown, and concurrently removed VM IDs through VMM.

**Expected results:**

- Every request reaches only the selected guest, preserves response/error semantics and deadlines, and a disappearing VM cannot redirect the request to another socket.

<a id="tc-vmm-manifest-001-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-vmm-manifest-001-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
