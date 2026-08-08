<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-platform-010"></a>
# TC-GOS-PLATFORM-010: Guest configuration backward and forward compatibility

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-platform-010](../../../feature-audit.md#req-gos-platform-010)
- Risks: [risk-gos-platform-010](../../../feature-audit.md#risk-gos-platform-010)
- Source: `dstack/dstack-types/src`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Use one case-owned seed-matched TDX simulator and collateral service for all
  four rows. This exercises each official guest's attestation/configuration
  integration through the production verifier path without claiming physical
  TDX origin; select it explicitly with `--simulated-tee dstack-tdx` for each
  deployment. Physical attestation is covered by the hardware cases.
- The compatibility rows intentionally exercise the current VMM, KMS, and
  gateway with official guest images `dstack-dev-0.5.4`, `dstack-0.5.8`,
  `dstack-0.5.11`, and `dstack-0.6.0`. Generate one current-schema compose with
  `vmm-cli.py compose --kms --gateway --key-provider kms --public-logs
  --public-sysinfo --event-log-version 2`; do not disable KMS/gateway or select
  `key_provider=none`, because that removes the dependencies this compatibility
  case is required to test and leaves identity-bearing guests in a prepare
  restart loop. Allocate 2 vCPU, 4096 MiB, and 20 GiB per row. A row that exits
  before `boot_progress=done` is an immediate diagnostic condition; capture its
  bounded serial/VMM log instead of waiting out the entire readiness timeout.
- Deploy the four rows concurrently when capacity is available, register every
  returned VM ID immediately, and poll them together. Use a 10-minute shared
  deadline, not a separate deadline per row. Perform graceful stop only after
  the guest reports `boot_progress=done`; a guest-agent connection error while
  the guest is still booting is not evidence about graceful-stop compatibility.

## Objective

Verify guest configuration backward and forward compatibility with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-gos-platform-010-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-gos-platform-010-step-02"></a>
### Step 2: Exercise supported and boundary paths

Boot previous/current agents with previous/current sys-config, vm_config, compose, user config, and unknown optional fields.

**Expected results:**

- Supported older fields preserve semantics, unknown optional fields do not crash, missing required fields fail clearly, and development simulator fields never enter production SysConfig.

<a id="tc-gos-platform-010-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-gos-platform-010-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
