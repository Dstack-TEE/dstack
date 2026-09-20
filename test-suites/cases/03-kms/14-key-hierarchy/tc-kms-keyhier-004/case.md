<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-keyhier-004"></a>
# TC-KMS-KEYHIER-004: Environment public key signature_v1 freshness

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-keyhier-004](../../../../catalog/feature-audit.md#req-kms-keyhier-004)
- Risks: [risk-kms-keyhier-004](../../../../catalog/feature-audit.md#risk-kms-keyhier-004)
- Source: `dstack/kms/rpc/proto/kms_rpc.proto:20` (`PublicKeyResponse`), `dstack/kms/src/crypto.rs` (`sign_message_with_timestamp`)

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- The proto documents two preimages for one published key:
  `keccak256(prefix || ":" || app_id || public_key)` for the legacy
  `signature`, and
  `keccak256(prefix || ":" || app_id || be64(timestamp) || public_key)` for
  `signature_v1`. The prefix is `dstack-env-encrypt-pubkey`.
- The response is not deterministic across seconds: `timestamp` and
  `signature_v1` change while `public_key` and the legacy `signature` do not.
  [`PROGRAMMATIC-EXECUTION.md`](../../../../PROGRAMMATIC-EXECUTION.md) records
  that a harness which assumes otherwise passes alone and fails under a
  parallel sweep. This case asserts the split explicitly rather than assuming
  either half.
- The method needs no client identity, so the whole contract is reachable from
  the public surface.

## Objective

Verify that `signature_v1` actually binds the domain, the application ID, the
timestamp and the published key, that the timestamp advances between calls, and
that the legacy `signature` still validates.

`signature_v1` exists for exactly one reason: a relying party that pins an
environment encryption key must be able to tell a fresh answer from a replayed
one. Nothing verified it. A KMS that returned a constant timestamp, or signed
without the timestamp, or reused one call's signature for the next, advertises
replay resistance it does not have and no case would notice.

## Preconditions

1. The shared plan prerequisites are healthy and the lease-owned KMS answers
   `KMS.GetMeta` with a compressed root k256 public key.
2. The lease's guest simulator exposes `DstackGuest.Info`, so the case can use
   the attested identity's real `app_id`.

## Test Data

Two `KMS.GetAppEnvEncryptPubKey` responses for the attested identity's own
`app_id`, taken at least one second apart, plus four wrong claims built from
the first one: the timestamp shifted by one second, the all-zero `app_id`, the
issued-key domain prefix, and the untimestamped preimage.

## Steps

<a id="tc-kms-keyhier-004-step-01"></a>
### Step 1: Self-test the primitives and the listener

Check the harness's primitives against the golden vectors, including the four
timestamped envelopes and their shifted-timestamp negatives, then read
`KMS.GetMeta`.

**Expected results:**

- Every golden vector matches, and every shifted-timestamp negative fails to
  recover, so the harness's notion of freshness is anchored before it is used.

<a id="tc-kms-keyhier-004-step-02"></a>
### Step 2: Verify both signatures over one response

Call `KMS.GetAppEnvEncryptPubKey` and recover the signer from both signatures.

**Expected results:**

- The reported `timestamp` is within two minutes of the case's wall clock.
- `signature_v1` recovers to `GetMeta.k256_pubkey` over the timestamped
  preimage.
- The legacy `signature` recovers to the same key over the untimestamped
  preimage, so backward compatibility is intact.
- None of the four wrong claims recovers to it: shifting the timestamp by one
  second, substituting the application ID, substituting the domain prefix, or
  dropping the timestamp each break the signature.

<a id="tc-kms-keyhier-004-step-03"></a>
### Step 3: Show the timestamp advances and the chain follows it

Call the method again after the clock crosses a second, then once more over the
protobuf representation.

**Expected results:**

- The second `timestamp` is strictly greater than the first.
- `public_key` and the legacy `signature` are byte-identical across the two
  calls — the published key did not move, only the freshness proof did.
- The second `signature_v1` differs from the first, verifies under the second
  timestamp, and does **not** verify under the first. A signature captured at
  one second cannot be replayed as the answer for another.
- The protobuf representation publishes the same `public_key` and carries a
  `signature_v1` that recovers under its own reported timestamp.

## Postconditions

No state is created. The artifacts retain public keys, signatures and
timestamps only.

What this case does **not** establish:

- It does not prove a relying party enforces freshness. It proves the KMS emits
  a signature that makes enforcement possible; whether a given SDK checks the
  timestamp window is an SDK case.
- It does not prove the KMS clock is trustworthy. `timestamp` comes from
  `SystemTime::now()` on the KMS host, and the case only requires it to be near
  the case's own clock and to advance.
- It says nothing about the freshness of `KMS.GetAppKey`, which carries no
  timestamp by design.
