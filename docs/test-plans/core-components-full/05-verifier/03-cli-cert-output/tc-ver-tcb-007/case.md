<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-tcb-007"></a>
# TC-VER-TCB-007: Canonical TCB status advisory and auth-policy projection

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: TEE_SIMULATOR
- Automation: Yes
- Requirements: [req-ver-tcb-007](../../../feature-audit.md#req-ver-tcb-007)
- Risks: [risk-ver-tcb-007](../../../feature-audit.md#risk-ver-tcb-007)
- Source: `dstack/verifier/src/verification.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify canonical tcb status advisory and auth-policy projection against each source-defined branch and trust assertion.

## Preconditions

1. Use the prepared Cargo target, mock-TDX collateral generator, checked-in hardware-captured SEV-SNP and Nitro Enclave evidence, and source-defined GCP TDX and NitroTPM functional fixtures.
2. Label every row as hardware-captured or simulation; do not claim physical origin for simulator rows. No private key or unredacted evidence is written to case artifacts.

## Test Data

Use seven canonical TCB decision rows plus exact signed-evidence, collateral mutation/outage, conflicting-input, event-replay, and BootInfo serialization tests.

## Steps

<a id="tc-ver-tcb-007-step-01"></a>
### Step 1: Execute the decision table

Execute the exhaustive TDX/GCP TDX/SNP/NitroTPM/Nitro Enclave policy table, including UpToDate, OutOfDate, Revoked, advisory, normalized NitroTPM, and no-TCB rows; then run the conflicting top-level input and BootInfo projection tests.

**Expected results:**

- Canonical platform report is the sole source, TDX/SNP status/advisories propagate identically to auth, Nitro TPM uses defined UpToDate, no-TCB platforms remain empty/fail-closed, and conflicting unauthenticated fields are ignored/rejected.

<a id="tc-ver-tcb-007-step-02"></a>
### Step 2: Verify independent trust bindings and side effects

Independently verify the hardware-captured SNP and Nitro Enclave evidence and the mock-TDX collateral matrix; exercise GCP TDX and Nitro image/PCR bindings with source-defined simulation fixtures.

**Expected results:**

- Every accepted row satisfies all named bindings, rejected rows create no trusted cache/key/cert/route state, and output identifies the exact failed assertion.

<a id="tc-ver-tcb-007-step-03"></a>
### Step 3: Verify outage, restart, and cross-identity isolation

Exercise unavailable TDX collateral followed by recovery, invalid collateral signatures and expiry, quote tampering, conflicting unauthenticated inputs, and RTMR3 event identity mutation followed by recovery.

**Expected results:**

- Uncertainty fails closed, recovery does not reuse stale decisions, accepted state survives only as documented, and cross-identity replay or substitution fails.

## Postconditions

Remove run-scoped evidence/state and restore trust, cache, routing and dependency baselines.
