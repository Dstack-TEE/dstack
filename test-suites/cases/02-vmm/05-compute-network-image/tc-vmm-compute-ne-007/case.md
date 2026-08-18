<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-compute-ne-007"></a>
# TC-VMM-COMPUTE-NE-007: QEMU command and platform matrix

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-vmm-compute-ne-007](../../../../catalog/feature-audit.md#req-vmm-compute-ne-007)
- Risks: [risk-vmm-compute-ne-007](../../../../catalog/feature-audit.md#risk-vmm-compute-ne-007)
- Source: `dstack/vmm/src/app/qemu.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify qemu command and platform matrix across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-compute-ne-007-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for qemu command and platform matrix.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-compute-ne-007-step-02"></a>
### Step 2: Exercise the behavior

Generate launches for TDX full/lite, SNP, GCP TDX, Nitro TPM, no-TEE, swtpm, GPU, and networking combinations.

**Expected results:**

- Machine type, firmware, devices, confidential-guest objects, shares, and vm_config measurements agree for every supported matrix row.

<a id="tc-vmm-compute-ne-007-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression matrix

Generate ACPI for every supported QEMU profile and version clamp, compare seeded randomized tables against the reference implementation, cover AMD PCI-hole and high-memory relocation, and require deterministic DSDT/SRAT/MCFG output for identical VM shape.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
