<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-020"></a>
# TC-GOS-SETUP-020: RA CA and app key generation CLI

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-setup-020](../../../feature-audit.md#req-gos-setup-020)
- Risks: [risk-gos-setup-020](../../../feature-audit.md#risk-gos-setup-020)
- Source: `dstack/dstack-util/src/main.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify ra ca and app key generation cli including exact cryptographic binding, CLI encoding, file safety, negative inputs, and dependency recovery.

## Preconditions

1. Run on isolated hardware and simulator environments as applicable; simulator results do not confirm hardware assertions.
2. Capture command argv, exit status, redacted stdout/stderr, output hashes/permissions, and independently decoded cryptographic evidence.

## Test Data

Use run-scoped non-secret inputs plus separately generated valid and one-field-mutated evidence fixtures.

Use the candidate CLI argument contract exactly:

- `gen-ca-cert --cert <certificate-path> --key <key-path> --ca-level <level>`
- `gen-ra-cert --ca-cert <ca-certificate-path> --ca-key <ca-key-path> --cert-path <certificate-path> --key-path <key-path>`
- `gen-app-keys --ca-level <level> --output <output-path>`

## Steps

<a id="tc-gos-setup-020-step-01"></a>
### Step 1: Exercise all CLI modes and boundaries

Run `gen-ra-cert`, `gen-ca-cert`, and `gen-app-keys` across CA levels, SAN/usage inputs, existing outputs, unsafe paths/permissions, and a mismatched CA key.

**Expected results:**

- Generated keys match certificates/chains and intended CA constraints, private files are restrictive, and mismatch fails without overwriting existing trusted output.

<a id="tc-gos-setup-020-step-02"></a>
### Step 2: Verify independent decoding and error recovery

Decode or verify output with an independent library/tool, exercise an invalid output path, restore it, and retry.

**Expected results:**

- Independent results match, invalid/failing operations return nonzero with actionable redacted error, and retry succeeds.

<a id="tc-gos-setup-020-step-03"></a>
### Step 3: Verify isolation permissions and repeatability

Repeat under another app/device identity and after restart; inspect outputs, logs and temporary files.

**Expected results:**

- Deterministic values are stable only within documented identity scope, random values do not repeat, cross-identity evidence/keys fail, permissions are restrictive, and no private material is logged.

## Postconditions

Securely remove generated private material and restore device, mount, network and filesystem state.
