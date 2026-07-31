<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-strategy-006"></a>
# TC-VER-STRATEGY-006: Platform-specific OS image verification and download strategy

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: TEE simulator and signed fixtures for functional coverage; matching hardware for physical-origin claims
- Automation: Yes
- Requirements: [req-ver-strategy-006](../../../feature-audit.md#req-ver-strategy-006)
- Risks: [risk-ver-strategy-006](../../../feature-audit.md#risk-ver-strategy-006)
- Source: `dstack/verifier/src/verification.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify platform-specific os image verification and download strategy against each source-defined branch and trust assertion.

## Coverage boundary

The matrix uses cryptographically valid simulator evidence and committed signed platform fixtures to exercise the production strategy selector and each platform-specific image binding. It verifies fail-closed dispatch, measurement/PCR/CBOR binding, download isolation, outage and recovery behavior; it does not claim that simulated rows originated from physical TDX, SEV-SNP, GCP, or Nitro hardware.

## Preconditions

1. Prepare isolated valid evidence and one-field mutations for each named platform/version/state.
2. Record trust roots, image/config/app identifiers, policy and dependency baseline without private material.

## Test Data

Use a decision table containing every condition in Step 1, relevant conflicting combinations, boundary lengths and a pinned historical-format row.

## Steps

<a id="tc-ver-strategy-006-step-01"></a>
### Step 1: Execute the decision table

Verify TDX full, TDX-lite, SEV-SNP, GCP TDX, Nitro Enclave and Nitro TPM with image server online/offline and altered platform-specific signed measurement/PCR/CBOR inputs.

**Expected results:**

- Full TDX downloads and replays measured image; lite and SNP use authenticated measurement material without download; GCP validates signed CBOR/image relation; Nitro variants validate required PCR mapping; no platform silently uses another strategy.

<a id="tc-ver-strategy-006-step-02"></a>
### Step 2: Verify independent trust bindings and side effects

Independently decode/verify evidence and compare policy inputs, cache/state mutation, returned public material and persisted artifacts for each row.

**Expected results:**

- Every accepted row satisfies all named bindings, rejected rows create no trusted cache/key/cert/route state, and output identifies the exact failed assertion.

<a id="tc-ver-strategy-006-step-03"></a>
### Step 3: Verify outage, restart, and cross-identity isolation

Interrupt the external verifier/auth/image/network dependency, restart after accepted/rejected rows, and replay evidence under another app/node identity.

**Expected results:**

- Uncertainty fails closed, recovery does not reuse stale decisions, accepted state survives only as documented, and cross-identity replay or substitution fails.

## Postconditions

Remove run-scoped evidence/state and restore trust, cache, routing and dependency baselines.
