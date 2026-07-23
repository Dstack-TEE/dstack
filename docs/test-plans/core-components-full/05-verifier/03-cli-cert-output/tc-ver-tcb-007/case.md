<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-tcb-007"></a>
# TC-VER-TCB-007: Canonical TCB status advisory and auth-policy projection

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-ver-tcb-007](../../../feature-audit.md#req-ver-tcb-007)
- Risks: [risk-ver-tcb-007](../../../feature-audit.md#risk-ver-tcb-007)
- Source: `dstack/verifier/src/verification.rs`

## Objective

Verify canonical tcb status advisory and auth-policy projection against each source-defined branch and trust assertion.

## Preconditions

1. Prepare isolated valid evidence and one-field mutations for each named platform/version/state.
2. Record trust roots, image/config/app identifiers, policy and dependency baseline without private material.

## Test Data

Use a decision table containing every condition in Step 1, relevant conflicting combinations, boundary lengths and a pinned historical-format row.

## Steps

<a id="tc-ver-tcb-007-step-01"></a>
### Step 1: Execute the decision table

Feed TDX/SNP/Nitro-TPM/Nitro-Enclave/GCP evidence with UpToDate, out-of-date, revoked, advisory lists, empty/no-TCB and conflicting top-level values; compare VerificationDetails and BootInfo.

**Expected results:**

- Canonical platform report is the sole source, TDX/SNP status/advisories propagate identically to auth, Nitro TPM uses defined UpToDate, no-TCB platforms remain empty/fail-closed, and conflicting unauthenticated fields are ignored/rejected.

<a id="tc-ver-tcb-007-step-02"></a>
### Step 2: Verify independent trust bindings and side effects

Independently decode/verify evidence and compare policy inputs, cache/state mutation, returned public material and persisted artifacts for each row.

**Expected results:**

- Every accepted row satisfies all named bindings, rejected rows create no trusted cache/key/cert/route state, and output identifies the exact failed assertion.

<a id="tc-ver-tcb-007-step-03"></a>
### Step 3: Verify outage, restart, and cross-identity isolation

Interrupt the external verifier/auth/image/network dependency, restart after accepted/rejected rows, and replay evidence under another app/node identity.

**Expected results:**

- Uncertainty fails closed, recovery does not reuse stale decisions, accepted state survives only as documented, and cross-identity replay or substitution fails.

## Postconditions

Remove run-scoped evidence/state and restore trust, cache, routing and dependency baselines.
