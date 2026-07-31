<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-apiver-011"></a>
# TC-KMS-APIVER-011: GetAppKey and SignCert API-version compatibility

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-kms-apiver-011](../../../feature-audit.md#req-kms-apiver-011)
- Risks: [risk-kms-apiver-011](../../../feature-audit.md#risk-kms-apiver-011)
- Source: `dstack/kms/src/main_service.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

- Positive protected-RPC rows require a client certificate carrying a cryptographically verifiable attestation bound to that certificate key. A simulator certificate with only the app-info extension is not an authenticated positive path, and rewriting a captured quote report-data field invalidates its signature. If the declared fixture exposes neither a hardware-attested client nor a mock-attestation client plus its matching explicitly enabled test trust anchors and collateral, record the positive rows as capability `BLOCKED` with the verifier error; do not grade that missing capability as product `FAIL`.

## Objective

Verify getappkey and signcert api-version compatibility against each source-defined branch and trust assertion.

## Preconditions

1. Prepare isolated valid evidence and one-field mutations for each named platform/version/state.
2. Record trust roots, image/config/app identifiers, policy and dependency baseline without private material.

## Test Data

Use a decision table containing every condition in Step 1, relevant conflicting combinations, boundary lengths and a pinned historical-format row.

## Steps

<a id="tc-kms-apiver-011-step-01"></a>
### Step 1: Execute the decision table

Call GetAppKey api_version 0/1/2/maximum and SignCert v1/v2/unknown using valid and cross-version encoded CSR/signatures; compare v1→v2 conversion, chain and legacy gateway fields.

**Expected results:**

- GetAppKey accepts only documented versions, SignCert v1/v2 yield equivalent authorized certificate semantics, unknown/cross-encoded versions fail, and legacy/current gateway fields remain consistent.

<a id="tc-kms-apiver-011-step-02"></a>
### Step 2: Verify independent trust bindings and side effects

Independently decode/verify evidence and compare policy inputs, cache/state mutation, returned public material and persisted artifacts for each row.

**Expected results:**

- Every accepted row satisfies all named bindings, rejected rows create no trusted cache/key/cert/route state, and output identifies the exact failed assertion.

<a id="tc-kms-apiver-011-step-03"></a>
### Step 3: Verify outage, restart, and cross-identity isolation

Interrupt the external verifier/auth/image/network dependency, restart after accepted/rejected rows, and replay evidence under another app/node identity.

**Expected results:**

- Uncertainty fails closed, recovery does not reuse stale decisions, accepted state survives only as documented, and cross-identity replay or substitution fails.

## Postconditions

Remove run-scoped evidence/state and restore trust, cache, routing and dependency baselines.
