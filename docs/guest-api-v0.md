# dstack Guest Agent API v0 (frozen)

This is the normative specification of the unversioned guest agent API, the
surface dstack 0.6.0 froze at exactly what v0.5.11 served. It defines the URL
scheme, the key derivation function, the signature chain encoding, and the
per-algorithm signing modes, so that a client written against this surface has a
written contract rather than an implementation to read.

Read it as the contract. The proto file
(`dstack/guest-agent/rpc/proto/agent_rpc.proto`) describes the message shapes;
this document pins the bytes. Where an implementation and this document disagree,
one of them is a bug.

**New code should target v1.** [`docs/guest-api-v1.md`](./guest-api-v1.md) is the
current API and the one under active development. This document exists because
the frozen surface is permanently closed and every 0.5.x client deployed today
speaks it, not because it is where new work belongs.

## Scope and status

The surface is closed. It gains no methods, no fields, no renumbering, and no
semantic changes to what is already there. It exists so a v0.5.x client keeps
working against a 0.6 agent unchanged. Every new capability goes to
`dstack.guest.v1`.

Three services are frozen: `DstackGuest` and `Worker` (both in the
`dstack_guest` proto package) and `Tappd`, which predates the scheme.

The freeze is mechanical, not a convention. `the_frozen_services_match_their_pinned_shape`
in `dstack/guest-agent/rpc/tests/frozen_surface.rs` hashes each frozen service's
descriptor against a pinned SHA-256. The descriptor covers the method list and
the full field list of every message reachable from it, `reserved` ranges
included.
Any addition changes the digest and fails the test, including a wire-compatible
one. That is deliberate: "frozen except for additions" is how three
never-released methods accumulated on this surface between v0.5.11 and 0.6.0.
`the_frozen_services_expose_the_v0_5_11_methods` in the same file spells the
method lists out so a failure is readable.

The descriptor digest pins the shape, not the behaviour. Behaviour is held by
the agent's own tests: `get_key_pins_the_frozen_chain_link` in
`dstack/guest-agent/src/rpc_service.rs` pins a chain link byte for byte, and
`the_internal_v0_mount_is_an_alias_for_the_unversioned_path`,
`the_external_v0_mount_is_an_alias_for_the_unversioned_path` and
`each_internal_mount_serves_only_its_own_surface` in
`dstack/guest-agent/src/server.rs` exercise the real mount table rather than a
restatement of it.

Two behaviour changes in 0.6.0 are sanctioned and do not alter the wire shape:
`GetQuote` fails on a platform without Intel TDX instead of returning an empty
quote, and `GetTlsKey` rejects a `not_before` that is not earlier than
`not_after`. A third method, `EmitEvent`, always fails. Each is described in
[The remaining methods](#the-remaining-methods).

## Transport and mounts

| Listener | Service | Mount | Example path |
|---|---|---|---|
| Internal socket | `DstackGuest` | `/v0` | `/v0/GetKey` |
| Internal socket | `DstackGuest` | `/` | `/GetKey` |
| External | `Worker` | `/prpc/v0` | `/prpc/v0/Info` |
| External | `Worker` | `/prpc` | `/prpc/Worker.Info` |
| Tappd socket | `Tappd` | `/prpc/` | `/prpc/Tappd.Info` |

The unversioned mounts are aliases, kept so a pre-0.6 client keeps working
unchanged. They are additional mounts of the *same* handler, not a parallel
implementation, so they cannot drift from the versioned path. New code that must
stay on this surface should say `/v0` and `/prpc/v0` explicitly.

Both `Worker` mounts strip a `Worker.` service-name prefix from the method
segment, so `/prpc/Worker.Info` and `/prpc/Info` both reach `Info`. `Tappd`
strips `Tappd.` the same way. The internal `DstackGuest` mounts do not strip
anything: the method segment is the bare method name.

The internal socket is `/var/run/dstack.sock`, reachable only by the application
itself, and it is the only place key material is served. The external listener is
reachable by anyone who can route to the CVM, and `Worker` never returns key
material. `Tappd` has its own socket, `/var/run/tappd.sock`.

Version selection is by URL path and nothing else. There is no header
negotiation and no default-version redirect.

Both listeners run the same prpc transport. A `POST` carrying
`Content-Type: application/json` takes a JSON body and returns JSON; any other
content type takes a protobuf-encoded request message and returns a
protobuf-encoded response. A `GET` takes its fields as query parameters and
returns JSON.

In the JSON encoding, a proto `bytes` field is a lowercase hex string. On input
an optional `0x` prefix is accepted and stripped. This applies to every `bytes`
field on this surface, including `GetKeyResponse.key`, each element of a
`signature_chain`, `SignRequest.data`, and `report_data`.

### Status codes

These are transport-level and identical on both surfaces.

| Status | Body | Meaning |
|---|---|---|
| 200 | the response message | Success |
| 404 | the server's own 404 page | No such mount: this agent has no surface at that path |
| 404 | `{"error": "Service not found: <Method>"}` | The surface is mounted; it has no such method |
| 400 | `{"error": "<message>"}` | The method ran and failed |
| 413 | `{"error": "<message>"}` | The request body exceeded the configured limit |
| other | `{"error": "<message>"}` | A handler chose the status; the message says why |

A handler failure is a 400 with the error text in the body. In the protobuf
encoding the same error arrives as a `ProtoError` message rather than JSON.

## GetKey

`GetKey` derives an application key from the application root key and returns it
with a two-link signature chain proving where it came from. It is the reason this
document exists: it is the one method on this surface whose output other parties
depend on, and until now its bytes lived only in the implementation.

`GetKeyArgs` has three fields.

| Field | Type | Reaches the KDF |
|---|---|---|
| `path` | string | **yes**, verbatim |
| `purpose` | string | no |
| `algorithm` | string | no |

Only `path` reaches the KDF. `purpose` is echoed into the chain claim of link 0
and has no other effect: two calls differing only in `purpose` return the same
32 bytes in `key` and differ only in `signature_chain[0]`. `algorithm` selects
how those 32 bytes are *interpreted* and how the public key is encoded; it does
not domain-separate the derivation.

Derivation is flat. `path` is an opaque byte string used as HKDF `info` and
nothing more. `a/b` is not a child of `a`, no key derived here derives another,
and there is no BIP-32-style hierarchy. The empty string is a valid `path`.

### The KDF

```text
salt = "RATLS"                          (5 bytes, ASCII: 52 41 54 4c 53)
IKM  = app root secp256k1 private key   (32 bytes, `k256_key` from .appkeys.json)
info = path                             (the caller's bytes, verbatim)
L    = 32

key = HKDF-SHA256(salt, IKM, info, L)   (RFC 5869: extract, then expand)
```

`ra_tls::kdf::derive_key` is the implementation. It takes `context_data` as a
slice of byte slices and hands that slice straight to ring's HKDF `expand`, which
concatenates the parts to form `info`. `GetKey` passes exactly one part,
`request.path.as_bytes()`, so `info` is the raw `path` bytes with no separator,
no tag, and no length prefix.

The salt is the constant `LEGACY_SALT` in `dstack/ra-tls/src/kdf.rs`. It is the
five ASCII bytes `RATLS`. It is baked into every key deployed before the
versioned API and must never change.

### Algorithm selection

`normalize_algorithm` maps the caller's string to a canonical name: `k256`
becomes `secp256k1`, and every other value passes through unchanged. `GetKey`
then matches on the result.

| `algorithm` sent | Behaviour |
|---|---|
| `secp256k1` | secp256k1 |
| `k256` | alias; identical to `secp256k1`, same key bytes |
| `""` (empty or field absent) | secp256k1, the default |
| `ed25519` | ed25519 |
| `secp256k1_prehashed` | **error.** Prehashing is a signing mode, not a key type; `Sign` accepts it, `GetKey` does not |
| anything else | error, `Unsupported algorithm` |

An unrecognised value is an error rather than a silent fallback to the default.
Only the literal empty string defaults.

### Output encoding

`key` is the 32 derived bytes, raw. It is not a PEM, not a DER, and not
algorithm-tagged; the caller knows which algorithm it asked for. In the JSON
encoding it is a 64-character hex string.

- **secp256k1**: the 32 bytes are the big-endian private scalar. If it is zero or
  at least the group order the call fails with `Failed to parse k256 key`. The
  public key is the SEC1 **compressed** point, 33 bytes, `0x02`/`0x03` prefix.
- **ed25519**: the 32 bytes are the RFC 8032 seed, from which the key expands as
  usual. The public key is the RFC 8032 raw public key, 32 bytes.

`GetKeyResponse` has no `public_key` field. A caller derives the public key from
`key` itself, and a verifier of the chain must reproduce the same encoding, as
described below. (v1 added `public_key` to the response for exactly this reason.)

### One secret, two curves

The derivation ignores `algorithm`, so `GetKey(path, *, "secp256k1")` and
`GetKey(path, *, "ed25519")` return **the same 32 bytes**. One secret is served
in two representations: a secp256k1 scalar and an ed25519 seed.

This is a property callers must account for, not a bug in an individual call.
Anyone who can reach the socket can request either interpretation, so the two
keys are not independent: compromise of one is compromise of both, and a
protocol that assumes a per-curve key does not get one here. Where independent
keys across algorithms are required, encode the algorithm into `path`: for
example `backup-signing/secp256k1` and `backup-signing/ed25519`.

This is one of the things v1 changed: the v1 KDF binds the canonical algorithm
name and a version tag into `info` under its own salt, so the two curves never
share a secret. See
[Key derivation](./guest-api-v1.md#key-derivation) and
[Migration from the unversioned API](./guest-api-v1.md#migration-from-the-unversioned-api).

### The signature chain

`GetKeyResponse.signature_chain` has exactly two elements.

```text
[0]  app root key  signs  the v0 key claim (specified here)
[1]  KMS root key  signs  the app root public key
```

Both are 65 bytes in the same envelope:

```text
link = r || s || v          (65 bytes)
```

`r` and `s` are 32-byte big-endian integers, low-S normalised, and `v` is the
one-byte recovery id in `0..=3`. The recovery byte lets a relying party recover
the signing public key from the link alone. `ra_tls::api_v1::sign_recoverable_keccak256`
produces both links; only the preimage differs.

**Link 0, the key claim.**

```text
claim  = purpose || ":" || lowercase_hex(public_key)
digest = keccak256(claim)
link0  = r || s || v
```

`purpose` is the caller's string verbatim. `public_key` is the derived public key
in the encoding from [Output encoding](#output-encoding), SEC1 compressed for
secp256k1 and RFC 8032 raw for ed25519. It is hex-encoded in lowercase and
appended as **text**, not as raw bytes. The claim is a UTF-8 byte string, since
`purpose` is a proto3 `string`, and the digest is keccak256 over those bytes.

The claim is a `:`-joined string over a caller-chosen `purpose`, which means an
application can steer much of what its own app root key signs. That is inside the
application's own trust domain, because the caller already holds the derived
key, but it is why v1's claim is length-prefixed instead, and why a v0 claim can
never be mistaken for a v1 one. See
[Why this cannot be forged through v0](./guest-api-v1.md#why-this-cannot-be-forged-through-v0).

**Link 1, the KMS attestation.** Produced by the KMS, outside the agent, and
passed through byte-for-byte from `k256_signature` in `.appkeys.json`. It is the
same bytes v1 serves in its own `signature_chain[1]`.

```text
message = "dstack-kms-issued" || ":" || app_id || sec1_compressed(app_root_pubkey)
digest  = keccak256(message)
link1   = r || s || v
```

`app_id` is the raw app id bytes and the app root public key is SEC1 compressed,
33 bytes. `sign_message` in `dstack/kms/src/crypto.rs` builds the preimage as
`[prefix, b":", appid, message].concat()`. Note there is no separator between
`app_id` and the public key.

### Verifying a chain

A relying party holds `key` (or the public key derived from it), a
`signature_chain`, the `(path, purpose, algorithm)` the key was requested under,
and the `app_id`.

1. **Anchor.** Obtain the KMS root public key from a source you trust
   independently of the agent being checked: the `DstackKms` contract's
   `kmsInfo().k256Pubkey`, or a value pinned out of band. This step carries the
   security of everything below it. An attacker who can answer your query for the
   anchor can also mint a self-consistent chain, so reading the anchor from the
   KMS you are checking proves nothing.

2. **Rebuild the claim.** Encode the public key as
   [Output encoding](#output-encoding) specifies, hex-encode it in lowercase, and
   compute `digest0 = keccak256(purpose || ":" || hex)`.

3. **Recover the app root key.** Split `signature_chain[0]` into `r`, `s`, `v`
   and recover the secp256k1 public key from `(digest0, r, s, v)`. Reject a
   non-canonical high-S `s`. Call the result `app_root_pubkey`, SEC1 compressed.

4. **Rebuild the KMS message.** Compute
   `digest1 = keccak256("dstack-kms-issued" || ":" || app_id || app_root_pubkey)`.

5. **Check link 1.** Verify `signature_chain[1]` over `digest1` against the anchor
   from step 1, either by recovering and comparing to the anchor or by verifying
   `(r, s)` against it directly. Reject high-S here too.

6. **Bind the application.** Confirm the `app_id` you used in step 4 is the
   application you meant to talk to. The chain proves that the KMS issued this app
   root key to *some* application; only this step ties it to yours.

Step 2 is where a v0 verifier can go wrong in a way a v1 verifier cannot: the
claim is built from a `purpose` the verifier must already know out of band, and
from a hex string whose case and public-key encoding must match exactly. A
verifier that guesses `purpose`, uppercases the hex, or uses the uncompressed
SEC1 point computes a different digest and recovers a different, meaningless
public key in step 3, which then simply fails at step 5.

### Test vector

`get_key_pins_the_frozen_chain_link` in `dstack/guest-agent/src/rpc_service.rs`
pins link 0. With the fixture app root key `DUMMY_K256_KEY` from that test
module,

```text
app root key = 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
path         = "test"
purpose      = "signing"
algorithm    = "secp256k1"
```

`signature_chain[0]` is

```text
c8a3dcf06c4e95bd78a5d7a1c8fcff171fc5848cfae804c6fc11bda4dc5d4062
379995390843827444992c4c0e4bac70f0f878e01b9fc8b98cd7126fe5a3876b
01
```

ECDSA here is deterministic (RFC 6979), so this vector pins the whole encoding
including the recovery byte. It is the only committed vector for this surface;
the values above are asserted on every test run.

## Sign

`Sign` signs a caller-supplied payload with a key the agent derives itself. The
key is not chosen by the caller: `Sign` calls `GetKey` internally with
`path = "vms"` and `purpose = "signing"`, always, and only `algorithm` varies.
That is the same key `Worker.GetAttestationForAppKey` attests.

`SignRequest.algorithm` goes through `normalize_algorithm` first, so `k256` is
accepted as an alias for `secp256k1` here too. Unlike `GetKey`, `Sign` has **no
default**: an empty `algorithm` derives a key and then fails with
`Unsupported algorithm`, because the empty string matches no signing mode.

### Modes

| `algorithm` | Key derived as | Bytes signed | Hash | Signature |
|---|---|---|---|---|
| `secp256k1` | secp256k1 at `vms`/`signing` | `data`, raw | SHA-256, by the agent | 64 bytes, `r \|\| s` |
| `k256` | alias for the row above | — | — | — |
| `secp256k1_prehashed` | secp256k1 at `vms`/`signing` | `data`, used **as the digest** | none | 64 bytes, `r \|\| s` |
| `ed25519` | ed25519 at `vms`/`signing` | `data`, raw | RFC 8032 (SHA-512, internal) | 64 bytes, `R \|\| S` |
| anything else | — | — | — | error, `Unsupported algorithm` |

`r` and `s` are 32-byte big-endian integers and `s` is low-S normalised. Note the
shape: a payload signature is **64 bytes and carries no recovery byte**, unlike
the 65-byte chain links. It is the fixed-width form, not DER.

`public_key` is the SEC1 compressed point (33 bytes) for both secp256k1 modes and
the RFC 8032 raw public key (32 bytes) for ed25519.

The prehashed mode derives its key under the base name `secp256k1`, because
prehashing is a signing mode and not a key type. `secp256k1` and
`secp256k1_prehashed` therefore use the **same key** and produce the **same**
`public_key` and the same `signature_chain[1]` and `[2]`.

Because `GetKey`'s derivation ignores the algorithm, the ed25519 and secp256k1
modes also share one 32-byte secret, the one derived at `path = "vms"`. See
[One secret, two curves](#one-secret-two-curves).

**`secp256k1_prehashed` puts the hash on the caller.** `data` must be exactly 32
bytes; any other length fails with a message naming the length received. The
agent signs those 32 bytes directly as the digest and does not hash them again.
Consequences the caller owns:

- Choose the hash function, and make sure the verifier uses the same one. The
  agent records nothing about it, and neither does the signature.
- Domain-separate the payload before hashing. The agent will sign any 32 bytes,
  including 32 bytes that are a digest of something else entirely, so a caller
  that reuses one signing key across message types must build that distinction
  into the preimage.
- The non-prehashed `secp256k1` mode hashes with SHA-256 inside the agent, so the
  two modes produce different signatures over the same `data`, and a signature
  from one does not verify under the other's rules.

### The signature chain

`SignResponse.signature_chain` has exactly three elements. The proto comment on
the field describes it accurately.

```text
[0]  the payload signature      (64 bytes; the same bytes as `signature`)
[1]  app root key  signs  "signing:" || hex(public_key)     (65 bytes)
[2]  KMS root key  signs  the app root public key           (65 bytes)
```

Elements `[1]` and `[2]` are exactly `GetKey`'s `signature_chain[0]` and `[1]`
for a call with `path = "vms"`, `purpose = "signing"` and the mode's base
algorithm. Verify them by the steps in
[Verifying a chain](#verifying-a-chain), with `purpose = "signing"`.

Element `[0]` duplicates the top-level `signature` field; it is there so that one
array carries the whole path from the payload to the KMS root. It is a different
shape from the other two: 64 bytes, no recovery byte, and verified against
`public_key` under the mode's own rules rather than recovered.

## Verify

`Verify` checks one signature against one public key. It is legacy: verification
needs no key material and no attestation, and the agent's answer arrives over the
socket unattested, so a relying party gains nothing over verifying locally. It is
retained because it is part of this frozen surface and the SDKs' v0 clients still
expose it. v1 has no counterpart.

`algorithm` goes through `normalize_algorithm`, so the accepted values are
`ed25519`, `secp256k1`, `k256` (alias), and `secp256k1_prehashed`. An empty or
unrecognised value is an error, not `valid: false`.

| `algorithm` | `public_key` | `data` |
|---|---|---|
| `ed25519` | RFC 8032 raw, 32 bytes | the message; hashed per RFC 8032 |
| `secp256k1` / `k256` | SEC1, compressed (33) or uncompressed (65) | the message; hashed with SHA-256 |
| `secp256k1_prehashed` | SEC1, compressed or uncompressed | the digest, used as-is |

`signature` is the 64-byte `r || s` (or `R || S`) fixed-width form. DER is not
accepted.

A malformed input is an error, not a verdict: a `public_key` that is not a valid
point, or a `signature` that is not 64 bytes or whose `r` or `s` is zero or at
least the group order, fails the call with HTTP 400. `valid: false` means the
inputs parsed and the signature did not check out.

**A non-canonical high-S secp256k1 signature does not verify.** It parses,
because `r` and `s` are in range, and is then rejected by k256's verification,
so the call answers `valid: false` rather than failing. The effect is that a
malleated copy of a valid signature is not accepted here, which matters because
callers may be treating this answer as a uniqueness check. Verify the same way
if you replace this call with a local check.

`secp256k1_prehashed` is more permissive here than in `Sign`, which is an
asymmetry worth knowing about. `Sign` requires `data` to be exactly 32 bytes.
`Verify` accepts any length from 16 bytes up: a shorter `data` is zero-padded on
the left to 32 and a longer one is truncated to its leftmost 32 bytes, both
silently. Pass exactly the 32-byte digest and the two agree.

A relying party that wants more than a single-signature check wants the chain
verification in [Verifying a chain](#verifying-a-chain), which this method does
not do: `Verify` never looks at a `signature_chain` and never touches a trust
anchor.

## The remaining methods

### GetTlsKey

Issues a certificate and returns it with the key that backs it. The name is
misleading and v1 renamed it `IssueCert`: the operation is certificate issuance,
and the key is a by-product.

**The key is freshly generated on every call, not derived.** No request field
feeds it, and two identical requests return two unrelated keys. It is a P-256
key built from 32 bytes of `ring::rand::SystemRandom` output, returned as a
PKCS#8 PEM string in `key`. `GetKey` is the method that returns a stable,
re-derivable key.

The agent builds a `CertSigningRequestV2` over the public key, signs the CSR with
the generated key, and relays it. With a KMS key provider the CSR goes to the KMS
`SignCert` RPC; without one it is signed by the local CA the app booted with. The
returned `certificate_chain` is whatever the signer produced.

`usage_ra_tls` requests the RA-TLS quote extension, and `with_app_info` the app
info extension. `subject`, `alt_names`, `usage_server_auth` and
`usage_client_auth` map onto the certificate directly.

`not_before` and `not_after` are seconds since the UNIX epoch and are optional
independently. When **both** are set, `not_before` must be strictly earlier than
`not_after`; otherwise the call fails. Setting only one is not validated here.
That check is one of 0.6.0's two sanctioned behaviour changes on this surface: a
0.5.x client that sent an inverted pair got a certificate; it now gets an error.

### GetQuote

Returns a raw Intel TDX quote over caller-supplied report data, with the event
log, the padded report data and the VM config.

`report_data` is up to 64 bytes and is zero-padded on the right to 64. More than
64 bytes is an error, never a truncation. `GetQuoteResponse.report_data` is the
padded 64 bytes as the platform saw them.

**As of 0.6.0 this method is Intel TDX only.** It used to answer on every
platform, returning an empty `quote`; a platform without a TDX quote now gets an
error naming `Attest` as the replacement. This is a behaviour change on a frozen
surface, and it is deliberate: an empty quote is not evidence, and a client that
treated it as one was already broken. See the 0.6.0 CHANGELOG entry beginning
"guest-agent: `GetQuote` is restricted to Intel TDX".

On GCP Confidential VMs the gate passes, because there is a TDX quote, but the
answer carries the TDX half only. `GetQuoteResponse` has no field for the vTPM
quote GCP's own verification also binds, so a relying party there wants
`Attest`.

`event_log` is a JSON array of TDX event log entries. V2 runtime events include
the hex-encoded preimage of their digest; a verifier should check that
`sha384(hex_decode(preimage))` equals the digest.

### Attest

Returns a `VersionedAttestation` over caller-supplied report data, as opaque
bytes in `attestation`. Report data padding is the same as `GetQuote`'s: up to 64
bytes, zero-padded on the right, longer is an error.

Unlike `GetQuote` it answers on every supported platform, and the attestation it
returns already carries the TDX quote and event log where those exist. The wire
format and how to extract a quote from it are specified in
[Extracting a quote from an attestation](./guest-api-v1.md#extracting-a-quote-from-an-attestation);
the format is shared between the two surfaces.

`AttestResponse` on this surface carries `attestation` and nothing else. Field 2
is `reserved`: it briefly carried `boottime_gpu_evidence` on an unreleased build.
Boot-time GPU evidence is a v1 feature, and a request sending
`include_boottime_gpu_evidence` here is ignored rather than honoured.

### EmitEvent

**Always fails, as of 0.6.0.** It answers HTTP 400 with

```text
EmitEvent was removed in dstack 0.6.0; runtime RTMR3 events are system-owned and cannot be extended by apps
```

Runtime RTMR3 events became system-owned, so an application can no longer extend
the measurement chain. Applications bind their data through `report_data`
instead.

The method was kept rather than deleted so that a pre-0.6 client gets a
self-explanatory error. Deleting it would answer HTTP 404
`Service not found: EmitEvent`, which says nothing about why the events stopped
being recorded. The explanatory failure is the entire reason the method still
exists; `EmitEventArgs` is kept for the same reason, so an old client's request
still decodes and reaches the handler.

### Info

Returns application identity and configuration. It is not attestation: the
response arrives over a socket with no quote behind it, and nothing in it is
evidence. A relying party confirms these values against an attestation.

`app_id`, `instance_id`, `device_id`, `mr_aggregated`, `os_image_hash` and
`compose_hash` are raw bytes (hex strings in JSON). `app_name`,
`key_provider_info` and `vm_config` are strings. `cloud_vendor` and
`cloud_product` are the DMI `sys_vendor` and `product_name` values, empty when
unreadable.

`tcb_info` is a pretty-printed JSON string, not a message. It carries `mrtd` and
`rtmr0` through `rtmr3`, the full `event_log`, the verbatim `app_compose`
document, and hex copies of `mr_aggregated`, `os_image_hash`, `compose_hash` and
`device_id` that also appear as top-level fields. `compose_hash` is `sha256` over
the exact `app_compose` bytes, so do not parse and re-serialize before hashing.

`app_cert` is a demo certificate the agent mints for a dashboard. It proves
nothing, it is requested lazily in the background, and it is an empty string
until that request completes. v1 dropped it.

**What `public_tcbinfo` hides.** The gating applies only on the external
listener, and only when the app-compose does not set `public_tcbinfo`. In that
case `tcb_info` and `vm_config` come back as **empty strings**; every other
field, `key_provider_info` included, is served as normal. The internal
`DstackGuest.Info` applies no gating at all: the caller there is the application
itself, which cannot need protecting from its own configuration.

Note that this is not what v1's `Worker.Info` does; v1 also blanks
`key_provider_info`. The difference is intentional and the frozen behaviour is
unchanged. See
[public_tcbinfo on the external surface](./guest-api-v1.md#public_tcbinfo-on-the-external-surface).

### Version

Returns the agent's `version` (its Cargo package version) and `rev` (the git
revision it was built from). It takes no arguments and touches nothing, which
makes it the cheapest liveness probe on either listener.

### Worker.GetAttestationForAppKey

On the external listener. Derives the application key for `algorithm`, builds
report data committing to its public key, and returns a `GetQuoteResponse` over
it. The caller cannot build that report data itself, because it does not know the
public key until the agent derives it. That is why attesting an app key needs
its own method rather than the caller-supplied `report_data` that `GetQuote` and
`Attest` take.

The key is `GetKey(path = "vms", purpose = "signing", algorithm)`, the same key
`Sign` uses. `algorithm` goes through `normalize_algorithm`, and
`secp256k1_prehashed` derives under `secp256k1` exactly as it does in `Sign`. An
empty or unrecognised `algorithm` is an error.

The report data is a DIP-1 tagged ASCII string, zero-padded on the right to 64
bytes:

```text
report_data = prefix || base64url_nopad(public_key)   then right-padded with 0x00 to 64
```

| `algorithm` | `prefix` | `public_key` | Total length |
|---|---|---|---|
| `secp256k1`, `k256`, `secp256k1_prehashed` | `dip1::secp256k1c-pk:` (20 bytes) | SEC1 compressed, 33 bytes | 20 + 44 = 64, no padding |
| `ed25519` | `dip1::ed25519-pk:` (17 bytes) | RFC 8032 raw, 32 bytes | 17 + 43 = 60, padded with 4 zero bytes |

The base64 alphabet is URL-safe and unpadded. The construction fails rather than
truncating if it would exceed 64 bytes, so a commitment can never silently become
a valid-looking commitment to a different key. Note that the secp256k1 form fills
the field exactly: there is no trailing NUL to parse against, so a reader should
stop at 64 bytes or at the first NUL, whichever comes first.

The `c` in `secp256k1c` records that the point is compressed. A verifier that
re-derives the commitment from an uncompressed point gets a different string.

`app_key_report_data_matches_its_vectors` in
`dstack/guest-agent/src/rpc_service.rs` pins both forms against the fixture app
root key from [Test vector](#test-vector):

```text
ed25519    "dip1::ed25519-pk:5Pbre1Amf1hrp2V2bbfKlIfxpQb2pJAmrgmhxgVoG9s\0\0\0\0"
secp256k1  "dip1::secp256k1c-pk:A6t_JdVkVdMAocH3f1f20WGT6JzdntxcXimUtEax8zc9"
```

`app_key_report_data_accepts_secp256k1_prehashed` asserts that
`secp256k1_prehashed` produces the second one unchanged.

Because it returns a `GetQuoteResponse`, this method answers on Intel TDX and
fails everywhere else, exactly as `GetQuote` does.

v1 ships no counterpart, on purpose: no v1 `GetKey(domain, algorithm)` can return
the key this attests, so a v1 method would hand back an attestation of a public
key whose private half the caller could not obtain. A v1 application attests its
own key instead. See
[There is no v1 AttestAppKey](./guest-api-v1.md#there-is-no-v1-attestappkey).

## Tappd

`Tappd` predates v0 and is deprecated. It is served on its own socket
(`/var/run/tappd.sock`) at `/prpc/`, with the `Tappd.` service-name prefix
stripped, and it is frozen by the same descriptor digest. New code should not
call it; the notes below exist so a reader of an old client can tell what it did.

Every method maps onto a `DstackGuest` one, except where noted.

| Method | Relationship to `DstackGuest` |
|---|---|
| `DeriveK256Key` | `GetKey`, verbatim. Same arguments, same bytes, fields renamed to `k256_key` and `k256_signature_chain` |
| `Info` | `Info`, with internal semantics: no `public_tcbinfo` gating |
| `Version` | `Version` |
| `TdxQuote` | `GetQuote`, but it hashes the report data first (see below) |
| `RawQuote` | `TdxQuote` with `hash_algorithm = "raw"`; requires exactly 64 bytes and does not pad |
| `DeriveKey` | *No `DstackGuest` equivalent.* See below |

`TdxQuote` builds report data as `hash(prefix || content)` rather than taking it
raw. The default `hash_algorithm` is `sha512` and the default `prefix` is
`app-data:`; the digest is left-aligned in the 64 bytes and the rest is zero.
`hash_algorithm = "raw"` passes `report_data` through unchanged and then requires
it to be exactly 64 bytes.

`DeriveKey` is the one method with no counterpart: it derives a **P-256** key
pair at `path` and issues a certificate for it. Unlike `GetTlsKey`, whose key is
random, this key is derived from the app root key through the same
HKDF-SHA256/`RATLS` construction, so it is stable across calls, unless
`random_seed` is set, which replaces the app root key with 32 fresh random bytes
and makes the result unreproducible. It always requests `ext_app_info = false`
and takes no validity window.

## Migration to v1

[`docs/guest-api-v1.md`](./guest-api-v1.md) is the current API. Its
[Field mapping](./guest-api-v1.md#field-mapping) table lists every v0 method and
field against its v1 counterpart, and
[Migration from the unversioned API](./guest-api-v1.md#migration-from-the-unversioned-api)
covers what changes for an application that moves.

The one thing to read before doing anything else: **v1 derives different key
material.** Deriving under the same name on `/v1` returns different bytes than
`/v0` does, by design and with no compatibility mode. An application holding
assets or identity under a v0 key must migrate them deliberately rather than
switching URLs.

Nothing forces a migration. This surface stays available and closed, and a
v0.5.x client keeps working against a 0.6 agent unchanged.

## Related documents

- [dstack Guest Agent API v1](./guest-api-v1.md), the current API and the
  normative spec for `dstack.guest.v1`
- [Attestation on Intel TDX](./attestation-tdx.md)
- [App Compose format](./normalized-app-compose.md), for the document behind
  `compose_hash` and `AppInfo.tcb_info`'s `app_compose`
- [On-chain governance](./onchain-governance.md), for the `DstackKms` contract
  that publishes the KMS root public key used as the chain's trust anchor
- [`sdk/curl/api.md`](../sdk/curl/api.md), a curl-oriented tour of both surfaces
