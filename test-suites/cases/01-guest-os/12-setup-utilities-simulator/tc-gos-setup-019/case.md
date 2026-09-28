<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-019"></a>
# TC-GOS-SETUP-019: Quote and quote-report CLI bindings

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-setup-019](../../../../catalog/feature-audit.md#req-gos-setup-019)
- Risks: [risk-gos-setup-019](../../../../catalog/feature-audit.md#risk-gos-setup-019)
- Source: `dstack/dstack-util/src/main.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify quote and quote-report cli bindings including exact cryptographic binding, CLI encoding, file safety, negative inputs, and dependency recovery.

## Preconditions

1. Run on isolated hardware and simulator environments as applicable; simulator results do not confirm hardware assertions.
2. Capture command argv, exit status, redacted stdout/stderr, output hashes/permissions, and independently decoded cryptographic evidence.

## Test Data

Use run-scoped non-secret inputs plus separately generated valid and one-field-mutated evidence fixtures.

## Steps

<a id="tc-gos-setup-019-step-01"></a>
### Step 1: Exercise all CLI modes and boundaries

Run `quote` and `quote-report` with empty/boundary/64-byte/oversized report data, sys-config variants, debug/output modes and unavailable TEE device.

**Expected results:**

- Quote report data and packaged report bind exact requested/config inputs, output encoding is valid, oversize is rejected and debug cannot weaken verification or leak secrets.

<a id="tc-gos-setup-019-step-02"></a>
### Step 2: Verify independent decoding and failure atomicity

Decode or verify output with an independent library/tool, inject device/network/filesystem failure before output commit, restore it, and retry.

**Expected results:**

- Independent results match, invalid/failing operations return nonzero with actionable redacted error, no partial trusted output remains, and retry succeeds exactly once.

<a id="tc-gos-setup-019-step-03"></a>
### Step 3: Verify isolation permissions and repeatability

Repeat under another app/device identity and after restart; inspect outputs, logs and temporary files.

**Expected results:**

- Deterministic values are stable only within documented identity scope, random values do not repeat, cross-identity evidence/keys fail, permissions are restrictive, and no private material is logged.

## Postconditions

Securely remove generated private material and restore device, mount, network and filesystem state.
