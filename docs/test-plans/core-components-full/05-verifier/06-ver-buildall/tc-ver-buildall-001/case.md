<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-buildall-001"></a>
# TC-VER-BUILDALL-001: Verifier and Measurement Tool Existing Regression Suite

## Metadata

- Priority: P0
- Type: Build, Regression, Supply Chain, Security
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-ver-buildall-001](../../../feature-audit.md#req-ver-buildall-001)
- Risks: [risk-ver-buildall-001](../../../feature-audit.md#risk-ver-buildall-001)
- Source: `dstack/verifier/test.sh`

## Objective

Verify the complete component build, generated-interface, packaging, existing-test, and supply-chain baseline before product-level cases rely on the candidate.

## Preconditions

1. Use a clean checkout, empty component build caches, pinned toolchains, and recorded dependency mirrors.
2. Do not update locks or generated files during the test; capture any dirty working-tree diff.

## Test Data

Use the candidate commit, committed fixtures, lock files, image recipes, generated protobuf/OpenAPI sources, and all component-native test configurations.

## Steps

<a id="tc-ver-buildall-001-step-01"></a>
### Step 1: Build from clean state

Build verifier, dstack-mr and dstack-attest from clean state; run unit tests, committed fixture script, mutation tests and candidate container smoke test.

**Expected results:**

- All existing known-good fixtures verify, known-bad/mutated fixtures fail at expected stages, generated outputs are stable, and build pins/trust artifacts match the recorded candidate.

<a id="tc-ver-buildall-001-step-02"></a>
### Step 2: Verify generated and packaged artifacts

Regenerate interfaces into a temporary tree, compare with committed output, inspect licenses/SBOM/locks/image contents and repeat the build with network disabled after dependency fetch.

**Expected results:**

- Generated output has no unexplained diff, offline rebuild succeeds from pins, required licenses are present, and packages contain only declared runtime/test content.

<a id="tc-ver-buildall-001-step-03"></a>
### Step 3: Verify failure detection

Introduce one temporary source/test-fixture/schema/config mismatch outside the committed tree and confirm the relevant build/test/generation gate fails, then restore and rerun.

**Expected results:**

- The gate detects the controlled regression with a specific error and returns to a clean passing result after restoration.

## Postconditions

Remove temporary build/output trees and verify the candidate checkout remains clean.
