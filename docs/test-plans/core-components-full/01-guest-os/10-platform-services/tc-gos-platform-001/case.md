<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-platform-001"></a>
# TC-GOS-PLATFORM-001: Local key provider PCCS selection and collateral lifecycle

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-platform-001](../../../feature-audit.md#req-gos-platform-001)
- Risks: [risk-gos-platform-001](../../../feature-audit.md#risk-gos-platform-001)
- Source: `dstack/local-key-provider/src`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify the SGX local key provider uses its configured PCCS for TDX quote collateral, handles cached and refreshed collateral correctly, and fails closed across dependency interruption and restart.

## Preconditions

1. A lease-owned SGX local-key-provider instance is configured through a lease-owned PCCS proxy or an isolated PCCS cache seeded for the hardware under test.
2. The fixture exposes controls for PCCS availability, cache freshness/expiry, provider restart, and redacted evidence capture without mutating shared host services.
3. TPM guest key provisioning is outside this case: `key_provider=tpm` is an independent Guest/VMM path and is not a mode of local-key-provider.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-gos-platform-001-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-gos-platform-001-step-02"></a>
### Step 2: Exercise supported and boundary paths

Submit a valid physical-TDX quote to the lease-owned SGX local-key-provider through a fresh local PCCS cache, repeat with the PCCS dependency unavailable while cached collateral remains valid, then force collateral refresh. Separately configure a public PCCS endpoint and record whether the platform registration policy permits it.

**Expected results:**

- The valid request succeeds through the configured local PCCS; valid cached collateral supports the documented offline interval; stale or expired collateral requires refresh; and the provider never silently falls back to an unconfigured public service. A public PCCS rejection caused by missing platform registration is reported as an expected deployment prerequisite rather than as TPM behavior.

<a id="tc-gos-platform-001-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-gos-platform-001-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
