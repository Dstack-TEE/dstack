<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-compute-ne-003"></a>
# TC-VMM-COMPUTE-NE-003: NUMA pinning hugepages and resource isolation

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-vmm-compute-ne-003](../../../../catalog/feature-audit.md#req-vmm-compute-ne-003)
- Risks: [risk-vmm-compute-ne-003](../../../../catalog/feature-audit.md#risk-vmm-compute-ne-003)
- Source: `dstack/vmm/src/app/qemu.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Create each matrix row with `values.vmm.test_input.create_stopped_helper_argv` and pass the required `--name`, `--vcpu`, `--memory`, `--hugepages`, and `--pin-numa` overrides explicitly. The helper applies these options to the prepared command and registers the returned VM ID; do not infer that extra arguments are ignored.
- A stopped definition does not allocate CPU, memory, or hugepages. After confirming that the requested flags persisted in public VM configuration, call `StartVm` and grade resource placement or exhaustion from the launch result, QEMU command line, and public state. Acceptance by `CreateVm` alone is not evidence that an overcommitted row succeeded.
- Read `values.host_capabilities` before creating a VM. If `hugepages_2m_total` is zero or no NUMA node is available, preserve that manifest observation and finalize the hardware-placement rows as BLOCKED; do not treat the expected absence of a QEMU process as a product FAIL or scan unrelated host VMs.
- The physical TDX host run must first execute `shared/automation/prepare-vmm-hugepages.sh`, which idempotently verifies hugetlbfs and provisions the bounded 2 MiB hugepage pool before fixture inventory.

## Objective

Verify numa pinning hugepages and resource isolation across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy, at least 512 free 2 MiB hugepages and one NUMA node were recorded by the prepared fixture, and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-compute-ne-003-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for numa pinning hugepages and resource isolation.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-compute-ne-003-step-02"></a>
### Step 2: Exercise the behavior

Launch VMs with pin_numa/hugepages across valid and insufficient host resources.

**Expected results:**

- QEMU CPU/memory placement matches policy; exhaustion fails cleanly and other VMs retain resources.

<a id="tc-vmm-compute-ne-003-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
