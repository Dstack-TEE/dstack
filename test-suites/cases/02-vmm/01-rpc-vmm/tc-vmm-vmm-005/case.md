<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-vmm-005"></a>
# TC-VMM-VMM-005: Vmm.UpgradeApp

## Metadata

- Priority: P1
- Type: Functional, API, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-vmm-005](../../../../catalog/feature-audit.md#req-vmm-vmm-005)
- Risks: [risk-vmm-vmm-005](../../../../catalog/feature-audit.md#risk-vmm-vmm-005)
- Source: `dstack/vmm/rpc/proto/vmm_rpc.proto:347`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Prepared RPC contract: `Vmm.UpgradeApp` takes `UpdateVmRequest` (`id: string`, `compose_file: string`, `encrypted_env: bytes`, `user_config: string`, `update_ports: bool`, `ports: PortMapping`, `update_kms_urls: bool`, `kms_urls: string`, `update_gateway_urls: bool`, `gateway_urls: string`, `gpus: GpuConfig`, `vcpu: uint32`, `memory: uint32`, `disk_size: uint32`, `image: string`, `no_tee: bool`, `update_networking: bool`, `networks: NetworkingConfig`) and returns `Id` (`id: string`). The authoritative field matrix is the matching entry in [`api-inventory.json`](../../../../catalog/api-inventory.json); do not reconstruct it from implementation source.
- For the candidate guest-agent target, use `shared/automation/start-simulator.sh` and the recorded service socket/route, then `shared/automation/stop-simulator.sh`. Do not compile or design another simulator launcher.
- Exercise the case-prescribed absent/default/valid/boundary-invalid/unknown-field and JSON/protobuf representations with a checked-in helper when available. Keep secret response material in memory and record only structural checks, public material, and hashes.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- JSON pRPC follows protobuf forward-compatibility semantics: an unknown field is ignored and is not a malformed request. Use a wrong field type, truncated JSON, a missing behavior-required field, or an unknown object ID for negative rows.
- In this pRPC JSON binding, a successful `google.protobuf.Empty` response is encoded as the JSON literal `null`; HTTP 200 with body `null` is the expected success representation, not a schema failure.
- VM removal is asynchronous. After a successful RemoveVm/`remove` call, poll the exact `values.vmm.commands.list_vms` command for up to 30 seconds and treat cleanup as complete only when the VM ID is absent; an immediate post-response listing may still contain the removing VM.
- Use `values.vmm.cli_argv`, `values.vmm.json_prpc_route_template`, and the exact `values.vmm.test_input.create_stopped_argv` command from the case manifest. Do not invent CLI subcommands or service-qualified pRPC routes.
- Before the positive upgrade, create the lease-owned VM with `values.vmm.test_input.create_stopped_helper_argv`, register its ID, start it once so its writable disk is materialized, then force-stop it and poll until stopped. `UpgradeApp` uses `UpdateVmRequest`: it has no `app_id` request field, returns the first 40 SHA-256 hex characters of the exact updated compose bytes in `Id.id`, and preserves the VM's deployed app identity. Unknown JSON fields are forward-compatible; use malformed compose JSON or a missing VM ID for negative rows.
- Force-stop with the exact `values.vmm.json_prpc_routes.StopVm` endpoint and `{"id":"<registered-id>","force":true}`; do not use the CLI's default graceful shutdown path. Poll `values.vmm.commands.list_vms` until the public status is `stopped` before UpgradeApp.
- In the `UpdateVmRequest` JSON body, `ports`, `kmsUrls`, `gatewayUrls`, and `networks` are arrays. Empty updates are `[]`, never `""`, `{}`, or `{tcp:[],udp:[]}`. `gpus` is the only object-shaped collection field. Check service availability with the Status JSON route, not a nonexistent `vmm-cli status` command.
- The nested `gpus` object uses `{"attach_mode":"listed","gpus":[]}` with the snake_case `attach_mode` key. `attachMode` is ignored by this JSON binding and becomes an empty mode, causing `Invalid GPU attach mode` before UpgradeApp reaches compose validation.
- This JSON pRPC binding uses protobuf snake_case field names for `UpdateVmRequest`: `compose_file`, `encrypted_env`, `user_config`, `update_ports`, `update_kms_urls`, `kms_urls`, `update_gateway_urls`, `gateway_urls`, `disk_size`, `no_tee`, `update_networking`, and `networks`. Camel-case forms such as `composeFile` are ignored as unknown fields and can produce a false HTTP 200 with an empty `Id.id`. Use snake_case for every request field, including malformed-compose negative rows.

## Objective

Verify the complete request, response, authorization, state transition, and error contract of `Vmm.UpgradeApp`.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

The `Vmm.UpgradeApp` entry in [`api-inventory.json`](../../../../catalog/api-inventory.json) is mandatory test data. Exercise every request field and every recursively referenced message field as absent/default, valid, boundary-invalid and combined with an unknown field; validate every response field, nested message field, and presence bit.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-vmm-005-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for vmm.upgradeapp.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-vmm-005-step-02"></a>
### Step 2: Exercise the behavior

Invoke `Vmm.UpgradeApp` with a valid `UpdateVmRequest` request using valid service-specific authentication and attestation context; capture the binary and JSON pRPC representations. Then send a schema-invalid request and, where protected, omit the credential.

**Expected results:**

- The valid call returns `Id` with every documented field and exhibits the documented `UpgradeApp` state and side effects; invalid framing or fields return a structured error, and protected calls reject missing credentials.

<a id="tc-vmm-vmm-005-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
