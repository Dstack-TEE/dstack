<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-keyhier-001"></a>
# TC-KMS-KEYHIER-001: Derived key determinism across a KMS restart

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-keyhier-001](../../../../catalog/feature-audit.md#req-kms-keyhier-001)
- Risks: [risk-kms-keyhier-001](../../../../catalog/feature-audit.md#risk-kms-keyhier-001)
- Source: `dstack/kms/src/main_service.rs:356` (`get_app_key`), `dstack/kms/src/crypto.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- The lease owns its KMS process, its certificate directory and its guest
  simulator. This case stops that process and starts a replacement from the
  same recorded configuration and the prepared `dstack-kms` binary in
  `DSTACK_TEST_RUNTIME_MANIFEST`. It must never be pointed at a shared KMS.
- The derived secrets are compared in memory. Only their SHA-256 digests, the
  public keys computed from them and the issued signature are written to the
  artifacts.
- The harness self-tests its cryptographic primitives against the golden
  vectors in `dstack/kms/src/crypto.rs` and RFC 7748 before it asserts anything
  about the live service, and fails the case if a vector does not match.

## Objective

Verify that one attested identity receives byte-identical `disk_crypt_key`,
`env_crypt_key`, `k256_key` and `k256_signature` from a KMS before and after
that KMS is restarted.

This is the property every other guarantee in the product rests on: an
application that cannot re-derive its own disk key after the KMS restarts
cannot decrypt its own disk. The existing restart cases in this chapter compare
`GetMeta` — the public CA and the root k256 public key — and stop there. A KMS
whose root material survives a restart but whose *derivation* of that material
drifts would pass every one of them.

## Preconditions

1. The shared plan prerequisites are healthy and the lease-owned KMS answers
   `KMS.GetMeta`.
2. The fixture declares an attested client identity (`kms_attested_client`)
   and authorises lease-scoped destructive actions
   (`component_substrate.destructive_actions_allowed`).
3. The runtime manifest names a prepared `dstack-kms` binary.

## Test Data

The fixture's own attested client certificate and `vm_config`, and the KMS
configuration file the lease recorded. No test data is invented: the point of
the case is that the *same* inputs produce the same outputs across a process
lifetime boundary.

## Steps

<a id="tc-kms-keyhier-001-step-01"></a>
### Step 1: Self-test the primitives and the listener

Check the harness's Keccak-256, secp256k1 recovery and X25519 implementations
against their golden vectors, then read `KMS.GetMeta`.

**Expected results:**

- Every golden vector matches, and `GetMeta` returns a 33-byte compressed
  root k256 public key and a CA certificate.

<a id="tc-kms-keyhier-001-step-02"></a>
### Step 2: Take the baseline

Call `KMS.GetAppKey` with the attested client identity and retain the derived
material in memory.

**Expected results:**

- The response carries every documented field, and the artifacts record only
  hashes of the secrets plus the public keys derived from them.

<a id="tc-kms-keyhier-001-step-03"></a>
### Step 3: Replace the KMS and re-derive

Stop the recorded KMS process, start a replacement reading the same
configuration, wait for its listener, and repeat the call.

**Expected results:**

- The replacement runs under a different PID, so the restart demonstrably
  happened.
- `disk_crypt_key`, `env_crypt_key`, `k256_key` and `k256_signature` are
  byte-identical to the baseline.
- `ca_cert` is unchanged, and `GetMeta`'s `ca_cert` and `k256_pubkey` are
  unchanged.

## Postconditions

The case leaves the lease-owned KMS stopped, exactly as
[tc-kms-keys-certs-009](../../06-keys-certs-operations/tc-kms-keys-certs-009/case.md#tc-kms-keys-certs-009)
does: the replacement process is not recorded in the lease journal, so leaving
it running would leak a process and hold the lease's port after teardown. The
certificate directory is not modified.

What this case does **not** establish:

- It does not prove determinism across a *reprovisioned* KMS. The replacement
  reads the same `cert_dir`, which is the intended production behaviour; a KMS
  that lost its root material is the subject of the onboarding and backup
  cases, not this one.
- It does not prove determinism across versions. That belongs to the upgrade
  and onboarding compatibility section.
- The attested client is the fixture's seed-matched simulated TDX identity, so
  the case asserts key-hierarchy behaviour for a verified identity and makes no
  physical-origin trust claim.
