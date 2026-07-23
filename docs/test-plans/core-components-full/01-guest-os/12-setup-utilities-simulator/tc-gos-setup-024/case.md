<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-024"></a>
# TC-GOS-SETUP-024: KMS GetKeys CLI transport and output safety

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-setup-024](../../../feature-audit.md#req-gos-setup-024)
- Risks: [risk-gos-setup-024](../../../feature-audit.md#risk-gos-setup-024)
- Source: `dstack/dstack-util/src/main.rs`

## Objective

Verify kms getkeys cli transport and output safety including exact cryptographic binding, CLI encoding, file safety, negative inputs, and dependency recovery.

## Preconditions

1. Run on isolated hardware and simulator environments as applicable; simulator results do not confirm hardware assertions.
2. Capture command argv, exit status, redacted stdout/stderr, output hashes/permissions, and independently decoded cryptographic evidence.

## Test Data

Use run-scoped non-secret inputs plus separately generated valid and one-field-mutated evidence fixtures.

## Steps

<a id="tc-gos-setup-024-step-01"></a>
### Step 1: Exercise all CLI modes and boundaries

Run `get-keys` against valid/multiple/timeout/wrong-cert/deny KMS URLs with valid/altered vm_config and output paths, then repeat/restart.

**Expected results:**

- Only attestation-authorized response is accepted, failover preserves one key identity, output is atomic/restrictive and no key material appears on stdout/logs unless explicitly documented.

<a id="tc-gos-setup-024-step-02"></a>
### Step 2: Verify independent decoding and failure atomicity

Decode or verify output with an independent library/tool, inject device/network/filesystem failure before output commit, restore it, and retry.

**Expected results:**

- Independent results match, invalid/failing operations return nonzero with actionable redacted error, no partial trusted output remains, and retry succeeds exactly once.

<a id="tc-gos-setup-024-step-03"></a>
### Step 3: Verify isolation permissions and repeatability

Repeat under another app/device identity and after restart; inspect outputs, logs and temporary files.

**Expected results:**

- Deterministic values are stable only within documented identity scope, random values do not repeat, cross-identity evidence/keys fail, permissions are restrictive, and no private material is logged.

## Postconditions

Securely remove generated private material and restore device, mount, network and filesystem state.
