<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-configurat-003"></a>
# TC-VMM-CONFIGURAT-003: Per-instance simulated TEE selection

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-vmm-configurat-003](../../../../catalog/feature-audit.md#req-vmm-configurat-003)
- Risks: [risk-vmm-configurat-003](../../../../catalog/feature-audit.md#risk-vmm-configurat-003)
- Source: `dstack/vmm/src/app.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The fixture starts a case-owned VMM. Clone `values.vmm.test_input.vm_configuration` in memory, give every variant a unique name, set its `simulated_tee` field, and submit it through `values.vmm.json_prpc_routes.CreateVm`. Register every returned VM ID in `values.vmm.test_input.created_vms_registry` before further actions. Use only the candidate `dstack-dev-0.6.0` image for simulated/no-TEE instances, and use force-stop/remove with bounded polling for cleanup.
- Valid simulated values are exactly `dstack-tdx`, `dstack-gcp-tdx`,
  `dstack-nitro-enclave`, `dstack-amd-sev-snp`, and
  `dstack-aws-nitro-tpm`. For the ordinary no-TEE and real-TEE control rows,
  remove the optional `simulated_tee` key from the JSON request entirely;
  never encode absence as the empty string and never invent values such as
  `cvm`. Empty string and unknown strings are negative rows that must be
  rejected without affecting successfully created instances.

## Objective

Verify per-instance simulated tee selection across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-configurat-003-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for per-instance simulated tee selection.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-configurat-003-step-02"></a>
### Step 2: Exercise the behavior

Deploy simulated and real-TEE instances concurrently with different simulated_tee values.

**Expected results:**

- Only selected instances receive simulator config/no-TEE QEMU mode; production schema and other instances remain unaffected.

<a id="tc-vmm-configurat-003-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
