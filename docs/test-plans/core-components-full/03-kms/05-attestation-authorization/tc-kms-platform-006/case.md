<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-platform-006"></a>
# TC-KMS-PLATFORM-006: Nitro Enclave app and KMS authorization

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-kms-platform-006](../../../feature-audit.md#req-kms-platform-006)
- Risks: [risk-kms-platform-006](../../../feature-audit.md#risk-kms-platform-006)
- Source: `dstack/kms/src/main_service/amd_attest.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify nitro enclave app and kms authorization against each source-defined branch and trust assertion.

## Preconditions

1. Prepare isolated valid evidence and one-field mutations for each named platform/version/state.
2. Record trust roots, image/config/app identifiers, policy and dependency baseline without private material.

## Test Data

Use a decision table containing every condition in Step 1, relevant conflicting combinations, boundary lengths and a pinned historical-format row.

## Steps

<a id="tc-kms-platform-006-step-01"></a>
### Step 1: Execute the decision table

Exercise production and debug Nitro Enclave documents with valid/altered AWS chain, module ID, timestamp, nonce/user/public-key data, PCR0/1/2/4, vm_config image/app/config binding and authorization allow/deny.

**Expected results:**

- Only a non-debug fresh document with trusted AWS chain, expected PCR/image/config/app bindings and positive policy is authorized; debug zero-PCR or any mutation receives no app/KMS key.

<a id="tc-kms-platform-006-step-02"></a>
### Step 2: Verify independent trust bindings and side effects

Independently decode/verify evidence and compare policy inputs, cache/state mutation, returned public material and persisted artifacts for each row.

**Expected results:**

- Every accepted row satisfies all named bindings, rejected rows create no trusted cache/key/cert/route state, and output identifies the exact failed assertion.

<a id="tc-kms-platform-006-step-03"></a>
### Step 3: Verify outage, restart, and cross-identity isolation

Interrupt the external verifier/auth/image/network dependency, restart after accepted/rejected rows, and replay evidence under another app/node identity.

**Expected results:**

- Uncertainty fails closed, recovery does not reuse stale decisions, accepted state survives only as documented, and cross-identity replay or substitution fails.

## Postconditions

Remove run-scoped evidence/state and restore trust, cache, routing and dependency baselines.
