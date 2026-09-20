<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-keyhier-003"></a>
# TC-KMS-KEYHIER-003: Issued k256 signature chain recovery

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-keyhier-003](../../../../catalog/feature-audit.md#req-kms-keyhier-003)
- Risks: [risk-kms-keyhier-003](../../../../catalog/feature-audit.md#risk-kms-keyhier-003)
- Source: `dstack/kms/src/crypto.rs` (`derive_k256_key`, `sign_message`), `dstack/ra-tls/src/api_v1.rs:158` (`sign_recoverable_keccak256`)

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- The documented preimage is
  `keccak256("dstack-kms-issued" || ":" || app_id || pubkey)` where `pubkey`
  is the 33-byte compressed SEC1 encoding `VerifyingKey::to_sec1_bytes`
  produces. The envelope is 65 bytes: low-S `r`, `s`, then
  `recovery_id.to_byte()`, which is 0..3 and not the 27-based Ethereum form.
- The `app_id` is read from the lease's guest simulator over
  `DstackGuest.Info`, because `AppKeyResponse` does not echo it.
- `crypto.rs` pins these bytes with golden vectors, and the harness checks
  itself against those same vectors before it looks at the live service. What
  the golden vectors cannot do is close the loop through the RPC: they never
  ask whether the key a running KMS *issues* chains to the key it *publishes*.

## Objective

Verify that the `k256_signature` in a live `AppKeyResponse` recovers to the
root k256 public key the same KMS returns from `KMS.GetMeta`, over the
documented preimage, and that no mutation of that chain still recovers.

A signature chain nobody verifies end to end is a signature chain that can
break silently: a KMS that signs with the wrong key, over the wrong preimage,
or with the uncompressed public-key encoding would still return a
well-formed 65-byte value, and every existing case would still pass.

## Preconditions

1. The shared plan prerequisites are healthy and the lease-owned KMS answers
   `KMS.GetMeta` with a compressed root k256 public key.
2. The fixture declares an attested client identity and a guest simulator
   exposing `DstackGuest.Info`.

## Test Data

The live response itself, plus six deliberately wrong claims derived from it:
a flipped bit in `r`, a flipped bit in `s`, a flipped recovery id, the
all-zero `app_id`, the uncompressed SEC1 encoding of the same public key, and
the environment-key domain prefix in place of the issued-key one.

## Steps

<a id="tc-kms-keyhier-003-step-01"></a>
### Step 1: Self-test the primitives and the listener

Check the harness's Keccak-256, secp256k1 recovery and X25519 implementations
against the golden vectors in `crypto.rs` and RFC 7748, then read
`KMS.GetMeta`.

**Expected results:**

- Every golden vector matches, including the row proving the issued preimage
  carries the compressed public key and not the uncompressed one.
- `GetMeta.k256_pubkey` is a 33-byte compressed SEC1 point.

<a id="tc-kms-keyhier-003-step-02"></a>
### Step 2: Close the chain

Call `KMS.GetAppKey`, compute the public key of the returned `k256_key`,
build the documented preimage, and recover the signer from `k256_signature`.

**Expected results:**

- The recovered public key equals `GetMeta.k256_pubkey` exactly.

<a id="tc-kms-keyhier-003-step-03"></a>
### Step 3: Break the chain, and cross-check the representation

Recover the signer from each of the six wrong claims, then repeat the call over
the protobuf representation.

**Expected results:**

- None of the six recovers to the root public key. A wrong domain prefix, a
  wrong `app_id` and a wrong public-key encoding are each sufficient to break
  it, which is what makes the claim unambiguous.
- The protobuf response carries byte-identical `disk_crypt_key`,
  `env_crypt_key`, `k256_key`, `k256_signature` and `os_image_hash` to the
  hex-encoded JSON response, so the two representations agree about key
  material.

## Postconditions

No state is created. The artifacts retain the derived public key, the
signature, the preimage digest and the root public key — all public — plus
SHA-256 digests of the secrets.

What this case does **not** establish:

- It does not prove the derived private key was produced by the documented
  HKDF. It proves the public key of whatever private key was issued is the one
  the root key vouched for. A KMS that derived the key differently but signed
  the result honestly would still pass; that derivation is pinned by the golden
  vector in `crypto.rs`, not by an RPC.
- It does not prove the root k256 key is held inside a TEE. `GetMeta` is an
  unauthenticated read; the attestation boundary is covered by the attestation
  and authorization section.
