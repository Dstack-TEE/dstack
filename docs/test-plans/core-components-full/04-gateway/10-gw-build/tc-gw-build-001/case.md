<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-build-001"></a>
# TC-GW-BUILD-001: Gateway, Certbot, Cluster Harness, and Existing Regression Suite

## Metadata

- Priority: P0
- Type: Build, Regression, Supply Chain, Security
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-gw-build-001](../../../feature-audit.md#req-gw-build-001)
- Risks: [risk-gw-build-001](../../../feature-audit.md#risk-gw-build-001)
- Source: `dstack/gateway`

## Objective

Verify the complete component build, generated-interface, packaging, existing-test, and supply-chain baseline before product-level cases rely on the candidate.

## Preconditions

1. Use a clean checkout, empty component build caches, pinned toolchains, and recorded dependency mirrors.
2. Do not update locks or generated files during the test; capture any dirty working-tree diff.

## Test Data

Use the candidate commit, committed fixtures, lock files, image recipes, generated protobuf/OpenAPI sources, and all component-native test configurations.

## Steps

<a id="tc-gw-build-001-step-01"></a>
### Step 1: Build from clean state

Build gateway/RPC/certbot/container artifacts, run Rust tests and the isolated Pebble/Cloudflare/three-node cluster suites, and validate generated templates/configs.

**Expected results:**

- All tests pass from clean state, cluster harness proves sync/cert/proxy basics, templates render valid restricted configs, and production image contains no test key or debug bypass.

<a id="tc-gw-build-001-step-02"></a>
### Step 2: Verify generated and packaged artifacts

Regenerate interfaces into a temporary tree, compare with committed output, inspect licenses/SBOM/locks/image contents and repeat the build with network disabled after dependency fetch.

**Expected results:**

- Generated output has no unexplained diff, offline rebuild succeeds from pins, required licenses are present, and packages contain only declared runtime/test content.

<a id="tc-gw-build-001-step-03"></a>
### Step 3: Verify failure detection

Introduce one temporary source/test-fixture/schema/config mismatch outside the committed tree and confirm the relevant build/test/generation gate fails, then restore and rerun.

**Expected results:**

- The gate detects the controlled regression with a specific error and returns to a clean passing result after restoration.

## Postconditions

Remove temporary build/output trees and verify the candidate checkout remains clean.
