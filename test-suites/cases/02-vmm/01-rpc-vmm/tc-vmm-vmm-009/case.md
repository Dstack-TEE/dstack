<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-vmm-009"></a>
# TC-VMM-VMM-009: Vmm.GetComposeHash

## Metadata

- Priority: P1
- Type: Functional, API, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-vmm-009](../../../../catalog/feature-audit.md#req-vmm-vmm-009)
- Risks: [risk-vmm-vmm-009](../../../../catalog/feature-audit.md#risk-vmm-vmm-009)
- Source: `dstack/vmm/rpc/proto/vmm_rpc.proto:355`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Prepared RPC contract: `Vmm.GetComposeHash` takes `VmConfiguration` (`name: string`, `image: string`, `compose_file: string`, `vcpu: uint32`, `memory: uint32`, `disk_size: uint32`, `ports: PortMapping`, `encrypted_env: bytes`, `app_id: string`, `user_config: string`, `hugepages: bool`, `pin_numa: bool`, `gpus: GpuConfig`, `kms_urls: string`, `gateway_urls: string`, `stopped: bool`, `no_tee: bool`, `networking: NetworkingConfig`, `networks: NetworkingConfig`, `simulated_tee: string`) and returns `ComposeHash` (`hash: string`). The authoritative field matrix is the matching entry in [`api-inventory.json`](../../../../catalog/api-inventory.json); do not reconstruct it from implementation source.
- For the candidate guest-agent target, use `shared/automation/start-simulator.sh` and the recorded service socket/route, then `shared/automation/stop-simulator.sh`. Do not compile or design another simulator launcher.
- Exercise the case-prescribed absent/default/valid/boundary-invalid/unknown-field and JSON/protobuf representations with a checked-in helper when available. Keep secret response material in memory and record only structural checks, public material, and hashes.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- JSON pRPC follows protobuf forward-compatibility semantics: an unknown field is ignored and is not a malformed request. Use a wrong field type, truncated JSON, a missing behavior-required field, or an unknown object ID for negative rows.
- In this pRPC JSON binding, a successful `google.protobuf.Empty` response is encoded as the JSON literal `null`; HTTP 200 with body `null` is the expected success representation, not a schema failure.
- VM removal is asynchronous. After a successful RemoveVm/`remove` call, poll the exact `values.vmm.commands.list_vms` command for up to 30 seconds and treat cleanup as complete only when the VM ID is absent; an immediate post-response listing may still contain the removing VM.
- Use `values.vmm.cli_argv`, `values.vmm.json_prpc_route_template`, and the exact `values.vmm.test_input.create_stopped_argv` command from the case manifest. Do not invent CLI subcommands or service-qualified pRPC routes.
- `GetComposeHash` accepts a complete `VmConfiguration`, not an `Id`. Use
  `values.vmm.test_input.vm_configuration` unchanged for the positive row and
  compare the returned hash with SHA-256 of its exact `compose_file` bytes.

## Objective

Verify the complete request, response, authorization, state transition, and error contract of `Vmm.GetComposeHash`.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

The `Vmm.GetComposeHash` entry in [`api-inventory.json`](../../../../catalog/api-inventory.json) is mandatory test data. Exercise every request field and every recursively referenced message field as absent/default, valid, boundary-invalid and combined with an unknown field; validate every response field, nested message field, and presence bit.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-vmm-009-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for vmm.getcomposehash.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-vmm-009-step-02"></a>
### Step 2: Exercise the behavior

Invoke `Vmm.GetComposeHash` with a valid `VmConfiguration` request using valid service-specific authentication and attestation context; capture the binary and JSON pRPC representations. Then send a schema-invalid request and, where protected, omit the credential.

**Expected results:**

- The valid call returns `ComposeHash` with every documented field and exhibits the documented `GetComposeHash` state and side effects; invalid framing or fields return a structured error, and protected calls reject missing credentials.

<a id="tc-vmm-vmm-009-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
