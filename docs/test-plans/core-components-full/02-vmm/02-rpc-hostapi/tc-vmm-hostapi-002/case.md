<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-hostapi-002"></a>
# TC-VMM-HOSTAPI-002: HostApi.Notify

## Metadata

- Priority: P1
- Type: Functional, API, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-hostapi-002](../../../feature-audit.md#req-vmm-hostapi-002)
- Risks: [risk-vmm-hostapi-002](../../../feature-audit.md#risk-vmm-hostapi-002)
- Source: `dstack/host-api/proto/host_api.proto:32`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- After `RemoveVm` succeeds, poll `values.vmm.commands.list_vms` for up to 30 seconds until the created VM ID is absent. A transient `removing` state is expected and must not fail cleanup.
- Prepared RPC contract: `HostApi.Notify` takes `Notification` (`event: string`, `payload: string`) and returns `google.protobuf.Empty` (no fields). The authoritative field matrix is the matching entry in [`api-inventory.json`](../../../api-inventory.json); do not reconstruct it from implementation source.
- For the candidate guest-agent target, use `automation/start-simulator.sh` and the recorded service socket/route, then `automation/stop-simulator.sh`. Do not compile or design another simulator launcher.
- Exercise the case-prescribed absent/default/valid/boundary-invalid/unknown-field and JSON/protobuf representations with a checked-in helper when available. Keep secret response material in memory and record only structural checks, public material, and hashes.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Host API is a vsock-only service and is not mounted on the VMM control-plane HTTP listener. Build calls from `values.host_api.probe_argv` and `values.host_api.json_prpc_routes.Notify`; do not substitute `values.vmm.rpc_url` or a VMM RPC route. A valid `Notify` additionally requires a request whose remote vsock CID belongs to a lease-owned VM, as provided by the action-specific fixture.
- The host process cannot bind an arbitrary guest CID, so a host-originated
  `probe_argv` call is not a valid positive `Notify` row. Create and start the
  fixture's simulated no-TEE guest, register its VM ID, wait for
  `boot_progress == "done"`, and require the VM's public `events` list to
  contain the guest-originated `boot.progress` notifications. Those events
  exercise `HostApi.Notify` over the VM's assigned vsock CID. Use the direct
  helper only for malformed framing and invalid-route negatives, then perform
  bounded force-stop/remove cleanup.
- Invoke `values.vmm.test_input.create_stopped_helper_argv` directly. Do not append the underlying Python executable, VMM CLI path, deploy subcommand, or full prepared command after `--`; the helper reads that command from the case manifest and returns the registered JSON VM ID.
- Direct negative Host API probes add `--body <json>` or `--body-file` to `values.host_api.probe_argv`. The helper has no `--data` option; a CLI argument error is test infrastructure and does not prove rejection.

## Objective

Verify the complete request, response, authorization, state transition, and error contract of `HostApi.Notify`.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

The `HostApi.Notify` entry in [`api-inventory.json`](../../../api-inventory.json) is mandatory test data. Exercise every request field and every recursively referenced message field as absent/default, valid, boundary-invalid and combined with an unknown field; validate every response field, nested message field, and presence bit.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-hostapi-002-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for hostapi.notify.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-hostapi-002-step-02"></a>
### Step 2: Exercise the behavior

Invoke `HostApi.Notify` with a valid `Notification` request using valid service-specific authentication and attestation context; capture the binary and JSON pRPC representations. Then send a schema-invalid request and, where protected, omit the credential.

**Expected results:**

- The valid call returns `google.protobuf.Empty` with every documented field and exhibits the documented `Notify` state and side effects; invalid framing or fields return a structured error, and protected calls reject missing credentials.

<a id="tc-vmm-hostapi-002-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
