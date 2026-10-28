<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-setup-025"></a>
# TC-GOS-SETUP-025: Streaming environment encryption and decryption

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-gos-setup-025](../../../../catalog/feature-audit.md#req-gos-setup-025)
- Risks: [risk-gos-setup-025](../../../../catalog/feature-audit.md#risk-gos-setup-025)
- Source: `dstack/dstack-util/src/crypto.rs`, `dstack/dstack-util/src/main.rs`

## Objective

Verify the versioned chunked environment-encryption format, legacy decryption
fallback, authenticated framing, and trusted KMS signer enforcement.

<a id="tc-gos-setup-025-step-01"></a>
### Step 1: Verify streaming round trips

Exercise empty, single-frame, and multi-frame plaintext with different chunk
boundaries.

**Expected results:** Encryption and decryption preserve bytes exactly and use
bounded independently authenticated frames.

<a id="tc-gos-setup-025-step-02"></a>
### Step 2: Reject malformed streams

Mutate authentication tags, truncate and reorder frames, change lengths and
flags, and append trailing data.

**Expected results:** Every malformed stream fails closed; callers are told to
discard partial output.

<a id="tc-gos-setup-025-step-03"></a>
### Step 3: Verify compatibility and signer binding

Auto-detect stream ciphertext, fall back to the legacy format, and validate the
timestamped environment public-key signature against the configured KMS key.

**Expected results:** Legacy input remains readable; an untrusted, expired, or
wrong-app signer cannot authorize encryption.

## Postconditions

Retain test names and status only; do not retain plaintext, keys, or ciphertext.
