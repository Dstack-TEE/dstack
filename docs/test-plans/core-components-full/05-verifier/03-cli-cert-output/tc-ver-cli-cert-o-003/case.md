<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-cli-cert-o-003"></a>
# TC-INT-CLI-CERT-O-003: OS image hash verification modes

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-ver-cli-cert-o-003](../../../feature-audit.md#req-ver-cli-cert-o-003)
- Risks: [risk-ver-cli-cert-o-003](../../../feature-audit.md#risk-ver-cli-cert-o-003)
- Source: `dstack/verifier/src/verification.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- Exercise the prepared candidate binary directly. Do not probe raw-substrate service ports or block because they are not listening; this section tests offline CLI/certificate behavior.

## Objective

Verify os image hash verification modes across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The prepared candidate verifier binary, checked-in full-TDX quote report, and manifest-declared extracted image fixture are available.
2. `DSTACK_TEST_VERIFIER_FULL_TDX_IMAGE_DIR` names the extracted image whose `sha256(sha256sum.txt)` is `14ad42d0270b444eaeb53918a5a94d9b17eec7a817cd336173b17c5327541c67`.
3. Commands use case-scoped caches and a loopback download server; this case consumes prepared artifacts and does not test image construction.

## Test Data

Use the checked-in `dstack/verifier/fixtures/quote-report.json`, the manifest-declared image directory, isolated caches, an ephemeral loopback HTTP server, and allow/deny sets containing only public image hashes.

## Steps

<a id="tc-ver-cli-cert-o-003-step-01"></a>
### Step 1: Inspect the effective prerequisite

Validate the prepared verifier path, quote fixture, image manifest identity, and isolated cache baseline.

**Expected results:**

- The quote and image share the expected hash identity, required image files exist, and no case-owned cache entry exists before its row starts.

<a id="tc-ver-cli-cert-o-003-step-02"></a>
### Step 2: Exercise the behavior

Run the real full-TDX quote against a pre-cached image with an unreachable download URL, apply relying-party allow and deny sets to the verified hash, fail with an empty offline cache, recover through a controlled image server, and mutate a measured boot artifact.

**Expected results:**

- Full-TDX quote, OS image, event log, and ACPI verification all pass for the valid image; the matching allowlist accepts and the nonmatching allowlist rejects; pre-cached offline verification performs no download; a missing offline image and a measured-artifact mutation fail closed; the same cache recovers through the controlled server.

<a id="tc-ver-cli-cert-o-003-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Confirm successful download promotion, bounded diagnostics for both expected rejections, recovery in the cache that previously failed, and absence of partial destination state.

**Expected results:**

- The controlled download is atomically promoted only after manifest validation, negative rows expose no secrets, and the verifier remains usable after the failed offline attempt.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
