<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-keyhier-002"></a>
# TC-KMS-KEYHIER-002: Application-scoped environment key separation

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-kms-keyhier-002](../../../../catalog/feature-audit.md#req-kms-keyhier-002)
- Risks: [risk-kms-keyhier-002](../../../../catalog/feature-audit.md#risk-kms-keyhier-002)
- Source: `dstack/kms/src/main_service.rs:408` (`get_app_env_encrypt_pub_key`), `dstack/kms/src/main_service.rs:379` (the three `derive_dh_secret` contexts)

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- `KMS.GetAppEnvEncryptPubKey` takes an arbitrary `app_id` and needs no client
  identity, so the app-scoped half of the hierarchy can be driven without
  minting a second attested identity.
- The attested identity's own `app_id` is read from the lease's guest
  simulator over `DstackGuest.Info`. `AppKeyResponse` deliberately does not
  echo the identity it derived from, so the preimage has to come from the same
  place the KMS read it.
- The environment secret in `AppKeyResponse.env_crypt_key` is an X25519 static
  secret; its public key is computed with RFC 7748 clamping, which is what
  `x25519_dalek::PublicKey::from(&StaticSecret)` does.

## Objective

Verify that environment encryption keys are scoped to `app_id`: the same
application ID always receives the same public key, every distinct application
ID receives a different one, and the secret handed to an attested identity is
the one published for that identity's own `app_id`.

`derive_dh_secret(root, [app_id, "env-encrypt-key"])` is the whole isolation
boundary between two applications' secret environments. Nothing in this chapter
asked a running KMS whether two application IDs actually get different keys.

## Preconditions

1. The shared plan prerequisites are healthy and the lease-owned KMS answers
   `KMS.GetMeta`.
2. The fixture declares an attested client identity and a guest simulator
   exposing `DstackGuest.Info`.

## Test Data

Nine 20-byte application IDs that cannot collide with a deployed one: the
constant patterns `00`, `01`, `02`, `7f` and `ff` repeated twenty times, and
the first twenty bytes of `sha256("dstack-test-keyhier-app-<n>")` for `n` in
1..4. Plus the attested identity's own `app_id`, read from the simulator, and
two deliberately malformed IDs of 19 and 21 bytes.

## Steps

<a id="tc-kms-keyhier-002-step-01"></a>
### Step 1: Self-test the primitives and the listener

Check the harness's Keccak-256, secp256k1 recovery and X25519 implementations
against their golden vectors, then read `KMS.GetMeta`.

**Expected results:**

- Every golden vector matches and the KMS answers with its public identity.

<a id="tc-kms-keyhier-002-step-02"></a>
### Step 2: Drive the separation table

Call `KMS.GetAppEnvEncryptPubKey` twice for each of the nine application IDs.

**Expected results:**

- Each application ID receives the same 32-byte public key both times.
- No public key is the all-zero point.
- All 36 pairs of distinct application IDs have distinct public keys.

<a id="tc-kms-keyhier-002-step-03"></a>
### Step 3: Bind the attested identity to its own namespace

Read the attested identity's `app_id` from the simulator, call
`KMS.GetAppKey`, and compare the public key of the returned `env_crypt_key`
with the key published for that `app_id`.

**Expected results:**

- The X25519 public key of the issued environment secret equals the public key
  `GetAppEnvEncryptPubKey` publishes for the same `app_id`, so the secret the
  attested identity holds is the one the public RPC advertises for it.
- A foreign `app_id` publishes a different key.
- `disk_crypt_key`, `env_crypt_key` and `k256_key` are three different values,
  so the three derivation contexts are actually separated.
- A 19-byte and a 21-byte `app_id` are both rejected with a client error, which
  is `ensure_app_id_len`.

## Postconditions

No state is created; every call is a read. The per-application-ID table is
retained in the artifacts as public key material only.

**The separation matrix, and what is missing from it.** The documented
hierarchy is asymmetric: the disk key is derived over `app_id || instance_id`,
while the environment and k256 keys are derived over `app_id` alone. Proving
the asymmetry needs two attested identities that differ in exactly one of those
two fields.

| Row | Covered here |
|---|---|
| Same `app_id`, environment key repeats | Yes |
| Different `app_id`, environment key differs (36 pairs) | Yes |
| Issued `env_crypt_key` belongs to the caller's own `app_id` | Yes |
| Three derivation contexts differ within one identity | Yes |
| `app_id` length is enforced | Yes |
| Different `app_id` ⇒ different `disk_crypt_key` | **No** |
| Different `instance_id`, same `app_id` ⇒ different `disk_crypt_key` | **No** |
| Different `instance_id`, same `app_id` ⇒ *same* `env_crypt_key` and `k256_key` | **No** |
| Different `app_id` ⇒ different `k256_key` | **No** |

The four uncovered rows all need a second attested identity, and the fixture
cannot mint one. `generate_simulator_client_identity` in
[`shared/fixtures/providers/isolated-component.py`](../../../../shared/fixtures/providers/isolated-component.py)
varies only the certificate subject, SANs and key usage; `app_id` and
`instance_id` are not configuration at all. They are event-log payloads inside
the captured attestation `sdk/simulator/attestation.bin`, not fields of
`appkeys.json` or `app-compose.json`, and `dstack/dstack-attest/src/attestation.rs`
requires the runtime event log to replay to the quoted RTMR3. So a second
identity means a second attestation fixture with an edited event log, a
recomputed RTMR3 and a quote re-signed under the lease's mock attestation seed.
That is provider work, and a case must not fabricate it.

What the fixture would need: a second seed-matched simulated guest, started
from a second attestation fixture whose `app-id` and `instance-id` events
differ, issuing from the same client CA and the same mock attestation seed, and
exported as a second attested client identity in the lease values. With that
one addition, the four missing rows become four assertions in this harness.

Finally, the attested client is a simulated TDX identity: the case asserts
key-hierarchy behaviour for a verified identity and makes no physical-origin
trust claim.
