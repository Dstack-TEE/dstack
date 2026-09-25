<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-compute-ne-002"></a>
# TC-VMM-COMPUTE-NE-002: Port mapping protocols and conflicts

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-compute-ne-002](../../../../catalog/feature-audit.md#req-vmm-compute-ne-002)
- Risks: [risk-vmm-compute-ne-002](../../../../catalog/feature-audit.md#risk-vmm-compute-ne-002)
- Source: `dstack/vmm/src/config.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Use `values.vmm.json_prpc_routes.Status` with a JSON `StatusRequest` for every health/availability check and `values.vmm.commands.list_vms` for listing. `vmm-cli.py` has no `status` subcommand; a CLI argument error is a probe defect and must not gate Step 2.
- Use only free host ports in the inclusive range declared by `values.vmm.test_input.port_mapping` for every positive mapping row. Ports outside that range are intentionally rejected and cannot establish the positive baseline.
- `CreateVm` takes `VmConfiguration` directly. Start from a copy of `values.vmm.test_input.vm_configuration`, change its `name` and `ports`, and POST that object itself; never wrap it in `{"config":...}`. Parse the returned `Id.id` UUID. `UpdateVm` takes a direct snake_case `UpdateVmRequest` with that UUID in `id`, `update_ports=true`, and the replacement `ports` array; it does not accept `name` or a nested `config`. Use returned UUIDs for cleanup.

## Objective

Verify port mapping protocols and conflicts across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-compute-ne-002-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for port mapping protocols and conflicts.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-compute-ne-002-step-02"></a>
### Step 2: Exercise the behavior

Map TCP/UDP, wildcard/specific host addresses, duplicate ports, disabled mapping, and update/reset.

**Expected results:**

- Valid forwarding reaches the correct VM; conflicts are rejected before launch and stale rules disappear after update/removal.

<a id="tc-vmm-compute-ne-002-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PR #1213)

The fixture node uses the default user-mode networking, so every stopped VM below has user-mode NICs only.

- `PortMapping.nic_index` names the NIC a mapping's traffic enters through. A TCP mapping with `nic_index=0` on the node-default single NIC is accepted and `Status` returns it with `nic_index=0`; on a VM deployed with two user-mode NICs a mapping with `nic_index=1` is accepted and persisted as `1`.
- `CreateVm` with a mapping pinned to `nic_index=1` on a single-NIC VM fails with an error naming `names NIC 1, but this VM has 1` and creates no VM.
- `UpdateVm` with `update_ports=true` and a mapping pinned to a NIC the VM does not have is rejected and leaves the persisted port list unchanged.
- Mappings without `nic_index` keep landing on the first user-mode NIC, so every pre-existing row of this case is unchanged. Pins to bridge, macvtap, or custom NICs are rejected with `cannot publish a host port`; that path needs a bridge-capable node and is covered by the `validate_port_mapping_nics` and `ingress_nic` unit tests (`a_pin_is_checked_against_the_backend_and_not_only_the_count`, `a_pin_to_a_backend_with_no_ingress_resolves_to_nothing`).
- `vmm-cli.py` accepts a trailing `@<nic>` on `--port` and sends it as `nic_index`.

## Post-baseline regression coverage (PR #1286, PR #1351)

The fixture policy allows TCP and UDP host ports `20000..=65535` on `127.0.0.1`. After the Step 2 port reset, the primary VM holds no mapping:

- PR #1286: `UpdateVm` with `update_ports=true`, a new compose file, and a TCP mapping from host port `min - 1` is rejected with `Port mapping is not allowed for tcp:<min - 1>`. Before the fix an update skipped the node policy that `CreateVm` enforced.
- PR #1351: after that rejection `Status` still reports no ports and the original `compose_file`; the rejected update wrote nothing.
- PR #1286: `UpdateVm` with a mapping whose `host_address` is empty is accepted and persists the policy address `127.0.0.1`, as `CreateVm` does. The ports are then reset to empty again.
- A mapping the VM already holds stays accepted after the node narrows its policy; that needs a policy change on a running VMM and is covered by the `port_map_enforces_node_policy_on_new_mappings_only` and `a_rejected_update_writes_nothing` unit tests in `tc-vmm-compute-ne-007`.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
