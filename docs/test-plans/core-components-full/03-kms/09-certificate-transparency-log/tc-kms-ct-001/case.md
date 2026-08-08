<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-ct-001"></a>
# TC-KMS-CT-001: Removed certificate-log surface regression

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-ct-001](../../../feature-audit.md#req-kms-ct-001)
- Risks: [risk-kms-ct-001](../../../feature-audit.md#risk-kms-ct-001)
- Source: `dstack/kms/src/main.rs`, `dstack/kms/Cargo.toml`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify the removed, unused certificate-log implementation and configuration surface do not silently return to KMS.

## Preconditions

1. Use the exact candidate repository and prepared Cargo target.
2. Preserve bounded source-inventory and test output evidence.

## Test Data

Use the candidate KMS module graph, dependency manifest, configuration fields, and library test suite.

## Steps

<a id="tc-kms-ct-001-step-01"></a>
### Step 1: Record effective inputs and baseline

Confirm the runtime manifest commit matches the candidate repository HEAD.

**Expected results:**

- The candidate identity is exact and no service or mutable runtime state is required.

<a id="tc-kms-ct-001-step-02"></a>
### Step 2: Exercise behavior and boundaries

Inspect the KMS module graph, source inventory, configuration fields, and dependency manifest, then run the current KMS library tests.

**Expected results:**

- `ct_log.rs`, its module declaration, `cert_log_dir`, and its sole `chrono` dependency remain absent, while the current KMS library suite passes.

<a id="tc-kms-ct-001-step-03"></a>
### Step 3: Inject failure and concurrency

Search all candidate KMS Rust sources for the removed configuration and module surface.

**Expected results:**

- No hidden call site or configuration hook can reactivate the deleted non-atomic file writer.

<a id="tc-kms-ct-001-step-04"></a>
## Postconditions

No service, file, listener, credential, or run-scoped product state was created.
