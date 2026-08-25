<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-build-001"></a>
# TC-KMS-BUILD-001: KMS Build, Image, Auth, Contract, and Existing Regression Suite

## Metadata

- Priority: P0
- Type: Build, Regression, Supply Chain, Security
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-kms-build-001](../../../../catalog/feature-audit.md#req-kms-build-001)
- Risks: [risk-kms-build-001](../../../../catalog/feature-audit.md#risk-kms-build-001)
- Source: `dstack/kms`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify the complete component build, generated-interface, packaging, existing-test, and supply-chain baseline before product-level cases rely on the candidate.

## Preconditions

1. Run Cargo commands from the candidate repository’s `dstack/` Rust workspace, using a clean component build cache, pinned toolchains, and recorded dependency mirrors.
2. Snapshot the bounded pre-existing working-tree status before testing. Do not update locks or generated files during the test, and require no new or changed status entries relative to that baseline; unrelated pre-existing changes do not fail this case.

## Test Data

Use the candidate commit, committed fixtures, lock files, image recipes, generated protobuf/OpenAPI sources, and all component-native test configurations.

## Steps

<a id="tc-kms-build-001-step-01"></a>
### Step 1: Build from clean state

Build the Rust KMS package with `cargo build --locked -p dstack-kms` and test it with `cargo test --locked -p dstack-kms`; build RPC/container plus mock/simple/Node/Bun authorization and Solidity contracts, then run Vitest/Jest, Foundry, storage-layout, and static-security suites.

**Expected results:**

- All artifacts build reproducibly with pinned dependencies, generated schemas match, every test/security gate passes, and container entrypoint starts the selected implementation without embedded secrets.

<a id="tc-kms-build-001-step-02"></a>
### Step 2: Verify generated and packaged artifacts

Regenerate interfaces into a temporary tree, compare with committed output, inspect licenses/SBOM/locks and container/image contents, and repeat the build with network disabled after dependency fetch. The `dstack-kms` binary is not a crates.io package; do not use `cargo package` as a packaging gate.

**Expected results:**

- Generated output has no unexplained diff, offline rebuild succeeds from pins, required licenses are present, and packages contain only declared runtime/test content.

<a id="tc-kms-build-001-step-03"></a>
### Step 3: Verify failure detection

Introduce one temporary source/test-fixture/schema/config mismatch outside the committed tree and confirm the relevant build/test/generation gate fails, then restore and rerun.

**Expected results:**

- The gate detects the controlled regression with a specific error and returns to a clean passing result after restoration.

## Post-baseline regression coverage (PR #1128)

- Inspect the built KMS application image and verify the pinned runtime package set installs CA certificates.
- From the running image, establish TLS to a public-test CA chain and reject an untrusted chain; do not inject host CA files into the container.

## Postconditions

Remove temporary build/output trees and verify the candidate checkout remains clean.
