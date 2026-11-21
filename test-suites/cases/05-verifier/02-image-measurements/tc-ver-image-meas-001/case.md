<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-image-meas-001"></a>
# TC-INT-IMAGE-MEAS-001: Image download digest and extraction security

## Metadata

- Priority: P1
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-ver-image-meas-001](../../../../catalog/feature-audit.md#req-ver-image-meas-001)
- Risks: [risk-ver-image-meas-001](../../../../catalog/feature-audit.md#risk-ver-image-meas-001)
- Source: `dstack/verifier/src/verification.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify image download digest and extraction security across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-ver-image-meas-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for image download digest and extraction security.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-ver-image-meas-001-step-02"></a>
### Step 2: Exercise the behavior

Download known image, wrong digest, truncated/multilayer/malicious archive, redirect, timeout, and retry.

**Expected results:**

- Content hash is verified before use, extraction cannot traverse roots, failures leave no trusted cache entry, and retry is bounded.

<a id="tc-ver-image-meas-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PRs #1251, #1337, and #1388)

- #1251: `sha256sum.txt` is parsed with one strict grammar (`<lowercase sha256>  <flat file name>\n` per line, no duplicates, no self entry), and every listed file is hashed in-process before the image is accepted, replacing `sha256sum -c`. `verification::tests::every_manifest_entry_is_checked_before_the_image_is_accepted` replaces `image_paths_must_be_confined_and_manifest_paths_must_be_flat`; `verification::tests::image_archive_paths_must_be_confined` and `dstack-types` `sha256sum::tests::accepts_sha256sum_output` / `sha256sum::tests::rejects_anything_else` pass by exact name.
- #1337: `sha256(sha256sum.txt)` is compared with `os_image_hash` before anything else in the archive is parsed, the firmware, kernel and initrd named by `metadata.json` must be manifest entries, the archive and its extracted size are capped at 100 MiB, and concurrent requests download an image once (`extracted_image_binds_the_files_metadata_measures`, `concurrent_requests_download_an_image_once`).
- #1388: a download truncated before `Content-Length` is retried (`truncated_image_download_is_retried`). The end-to-end retry and tampered-archive rows are in TC-VER-CLI-CERT-O-003.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
