<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-build-001"></a>
# TC-GOS-BUILD-001: Guest image builder provenance

## Metadata

- Priority: P0
- Type: Functional, Regression, Supply Chain
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gos-build-001](../../../../catalog/feature-audit.md#req-gos-build-001)
- Risks: [risk-gos-build-001](../../../../catalog/feature-audit.md#risk-gos-build-001)
- Source: `os/image/assemble.sh`, `os/mkosi/tests/check-output.sh`

## Objective

Verify that an assembled candidate guest image records the selected builder and
that the mkosi output contract rejects metadata that does not identify mkosi.

## Preconditions

1. Provide a protected candidate image store through the `image-assembly` fixture.
2. Record the expected builder in `DSTACK_TEST_GUEST_IMAGE_BUILDER`.

<a id="tc-gos-build-001-step-01"></a>
### Step 1: Validate the assembly and output-check scripts

Run bounded shell syntax validation on the candidate assembly script and mkosi
output checker.

**Expected results:** Both candidate scripts parse successfully.

<a id="tc-gos-build-001-step-02"></a>
### Step 2: Inspect candidate artifact provenance

Read the fixture-selected candidate image's `metadata.json` and compare its
`builder` field with the expected image builder.

**Expected results:** `builder` is present, non-empty, and equals the selected
backend; a legacy-only `backend` field is not accepted as provenance.

<a id="tc-gos-build-001-step-03"></a>
### Step 3: Verify the mkosi contract

Confirm the candidate mkosi output checker requires `builder` and compares it
with `mkosi` before accepting an artifact.

**Expected results:** The checked-in contract cannot accept output metadata that
omits or misidentifies the builder.

## Postconditions

Release the fixture without modifying the protected image store. Retain only
the builder name, candidate revision, boolean checks, and hashes.
