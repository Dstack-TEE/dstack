# dstack Guest Agent API v1

This is the normative specification of `dstack.guest.v1`, the versioned guest
agent API introduced in dstack 0.6.0. It defines the URL scheme, the key
derivation function, the signature chain encoding, and the steps a relying party
follows to verify what the agent produces.

Read it as the contract. The proto file
(`dstack/guest-agent/rpc/proto/agent_rpc_v1.proto`) describes the message shapes;
this document pins the bytes. Where an implementation and this document disagree,
one of them is a bug.

## What v1 is for

v1 exists because the unversioned surface cannot be fixed without breaking the
v0.5.x clients that depend on it. That surface is closed at exactly the v0.5.11
shape. v1 is where the corrections live.

The guest agent is not a general-purpose crypto service. It holds two things no
caller can obtain elsewhere: the application root key, and the platform's ability
to attest. v1 serves those two things and nothing else.

That is the organising principle behind the method set. `Sign` and `Verify` are
absent because they are pure computation over material the caller already has.
Any process that can reach this socket can ask `GetKey` for the private key
itself, so a server-side `Sign` grants no capability, adds an IPC round trip, and
adds an entry point to audit. Verification does not even need a key.

Four things changed for the operations that remain.

**Keys are domain-separated.** v0 derived a key from a path alone and handed the
same 32 bytes to both secp256k1 and ed25519. v1 binds the algorithm and a
versioned context tag into the derivation, so the two curves never share a secret
and a v1 key is never a v0 key.

**A key is named by one field.** v0 had `path` and `purpose`, of which only `path`
reached the KDF while `purpose` was echoed into the chain claim. v1 merges them
into `domain`, and both `domain` and `algorithm` affect the derived key.

**The chain claim is unambiguous.** v0's claim is a `:`-joined string over a
caller-chosen `purpose`, which lets an application steer what the app root key
signs. v1's claim is length-prefixed and binds raw public key bytes.

**Names say what things are.** `GetTlsKey` became `IssueCert`, because the
operation is certificate issuance. `Info` no longer nests documents inside a JSON
blob called `tcb_info`.

## Transport and versioning

Every surface the agent serves is now a closed v0 fossil plus a v1. The
unversioned surfaces are exactly v0.5.11 and never change again; new capability
arrives only in `dstack.guest.v1`.

The scheme is uniform: `v0` names the frozen v0.5.11 surface, `v1` the current
one, on both listeners.

| Listener | Version | Service | Mount | Example path |
|---|---|---|---|---|
| Internal socket | v1 | `DstackGuestV1` | `/v1` | `/v1/GetKey` |
| Internal socket | v0 | `DstackGuest`, frozen | `/v0` | `/v0/GetKey` |
| Internal socket | v0 alias | `DstackGuest`, frozen | `/` | `/GetKey` |
| External | v1 | `WorkerV1` | `/prpc/v1` | `/prpc/v1/Health` |
| External | v0 | `Worker`, frozen | `/prpc/v0` | `/prpc/v0/Info` |
| External | v0 alias | `Worker`, frozen | `/prpc` | `/prpc/Worker.Info` |

The unversioned paths are compatibility aliases, kept so a pre-0.6 client keeps
working unchanged. They are additional mounts of the *same* handler, not a
parallel implementation, so they cannot drift from `/v0`. New code should say
which version it means.

`Tappd` is unchanged and outside this scheme: it predates v0 and stays on its own
socket at `/prpc/`.

The internal socket is `/var/run/dstack.sock`, reachable only by the application
itself. The external listener is reachable by anyone who can route to the CVM.
That difference is the whole reason there are two services rather than one
mounted twice: `DstackGuestV1` hands out key material, and `WorkerV1` never does.

Version selection is by URL path and nothing else. There is no header
negotiation, no `Accept-Version`, and no default-version redirect, so a request
URL is the complete record of which contract the caller asked for. An agent that
predates v1 has no `/v1` mount at all, so it answers `/v1/...` with a plain
HTTP 404 -- see [Detecting an agent without v1](#detecting-an-agent-without-v1).

Both surfaces run over the same prpc transport. A `POST` carrying
`Content-Type: application/json` takes a JSON body and returns JSON; any other
content type takes a protobuf-encoded request message and returns a
protobuf-encoded response. A `GET` takes its fields as query parameters and
returns JSON.

### Status codes

| Status | Body | Meaning |
|---|---|---|
| 200 | the response message | Success |
| 404 | the server's own 404 page | No such mount: this agent has no surface at that path |
| 404 | `{"error": "Service not found: <Method>"}` | The surface is mounted; it has no such method |
| 400 | `{"error": "<message>"}` | The method ran and failed |
| other | `{"error": "<message>"}` | A handler chose the status; the message says why |

A handler failure is a 400 with the error text in the body. v1 does not default,
coerce, or truncate a malformed request into a well-formed one.

### Detecting an agent without v1

Both "this agent is too old for v1" and "v1 exists but has no such method"
answer 404, so the status alone does not separate them. The body does.

- 404 whose body is **not** JSON carrying `Service not found` -- there is no
  surface mounted at that path. The agent predates v1.
- 404 whose body **is** `{"error": "Service not found: <Method>"}` -- v1 is
  mounted and does not have that method.

`/v1/Version` is the cheapest probe: it takes no arguments and touches nothing.

## The internal surface

`DstackGuestV1` has six methods.

| Method | Purpose |
|---|---|
| `IssueCert` | Issue a certificate, with a freshly generated key |
| `GetKey` | Derive an application key and return it with its signature chain |
| `Attest` | Produce a versioned attestation over caller-supplied report data |
| `AttestGpu` | Collect GPU evidence now, against a caller-chosen nonce |
| `Info` | Return application identity and configuration |
| `Version` | Return the agent version |

Five v0 methods are deliberately absent.

`Sign` and `Verify` are absent for the reason above: neither needs the TEE.
Applications sign locally with a standard crypto library, using the key `GetKey`
returns, and verify locally following this document. A v0 client may keep calling
the unversioned `Verify` for single-signature checks; the v0 `Sign` RPC's
per-algorithm signing modes are documented on that surface, not here.

`GetQuote` is absent because `Attest` subsumes it. `GetQuote` answers on Intel TDX
and nowhere else, and the `VersionedAttestation` that `Attest` returns already
carries the TDX quote and the event log. See
[Extracting a quote from an attestation](#extracting-a-quote-from-an-attestation).

`GpuInfo` is absent from v1, and has also been removed from the unversioned
surface. It never appeared in a release, and
`Attest` with `include_boottime_gpu_evidence` returns the same bytes.

`EmitEvent` is absent because runtime RTMR3 events became system-owned in 0.6.0.
An application binds its data through `report_data` instead.

### Naming conventions

Every request message is `<Method>Request` and every response is
`<Method>Response`, including for methods that take no arguments. An empty message
can gain a field later; `google.protobuf.Empty` cannot.

A field's encoding lives in its doc comment, not in its name. Fields carrying JSON
documents say so and name who owns the schema.

## Certificate issuance

`IssueCert` is certificate issuance. The agent generates a key, builds a CSR,
signs the CSR with that key, and relays it to the KMS `SignCert` RPC, or to the
local CA when the application runs without a KMS. It returns the chain the signer
produced.

v0 called this `GetTlsKey`, which named the by-product rather than the request.
The private key is incidental: it is freshly generated on every call, no request
field feeds it, and two identical requests produce two unrelated keys. `GetKey` is
the method that derives a stable, attestable key.

`not_before` must be earlier than `not_after` when both are set; otherwise the
call fails.

This first cut serves only the integrated one-step mode, where the agent holds the
key. A mode that signs a caller-supplied CSR or public key, so the private key
never leaves the caller, is a plausible extension. It would arrive as added fields
or a sibling method, never as a change to what these fields mean.

## Key derivation

### Inputs

A v1 application key is named by exactly two values.

`domain` is a caller-chosen domain-separation string. It is not a DNS name; the
certificate fields on `IssueCertRequest` are the ones that take those. It may be
any byte string a proto3 `string` can carry, including one containing `:`, `/`, or
NUL.

`algorithm` is `secp256k1` or `ed25519`. There is no default and no alias. An
empty string is an error, and so is any other value, including `k256` and
`secp256k1_prehashed`.

Derivation is **flat**. Two domains yield unrelated keys. `a/b` is an opaque
string that happens to contain a slash, not a child of `a`, and no key derived
here can be used to derive another. There is no BIP-32-style hierarchy. The old
`path` name invited that reading, which is part of why it is gone.

### Length-prefixed encoding

Every construction below builds its input from length-prefixed fields. Write
`LP(x)` for:

```text
LP(x) = uint32_be(len(x)) || x
```

`len(x)` is the byte length, encoded big-endian in exactly four bytes. Encoding
fails if a field is longer than 2^32 - 1 bytes.

The prefix is what makes the encoding injective. A domain is arbitrary
caller-chosen bytes, so any delimiter it could also contain would let two
different `(domain, algorithm)` pairs encode to one byte string and share a key.
Joining with `:` or `/` is not sufficient here and is not what v1 does.

### The KDF

```text
salt = "dstack-guest-v1"                (15 bytes, ASCII; v0 uses "RATLS")
IKM  = app root secp256k1 private key   (32 bytes, `k256_key` from .appkeys.json)
info = LP("dstack-guest-v1-key") || LP(algorithm) || LP(domain)
L    = 32

key = HKDF-SHA256(salt, IKM, info, L)   (RFC 5869: extract, then expand)
```

`algorithm` is bound as its canonical name, `secp256k1` or `ed25519`, never as the
string the caller sent.

The primitive is unchanged from v0, which also used HKDF-SHA256 over the same
input key material. Two things changed. The `info` now binds the algorithm and a
version tag, where v0 passed the path alone, so the algorithm did not participate
and one 32-byte secret served both curves. And the salt is v1's own.

The salt is what makes v1 a separate derivation tree rather than a
differently-labelled branch of the old one. Under a shared salt the two surfaces
would be separated only by their HKDF `info` -- and the legacy `info` is the
caller's `path` verbatim, so a caller that passed the v1 `info` byte string as a
v0 `path` would reproduce a v1 key exactly. Different salts close that by
construction, whatever either side puts in `info`.

That collision was never a privilege boundary: both derivations serve the same
single-tenant application from the same root key, and that application may call
either surface. It is closed because a KDF whose separation depends on nobody
choosing an awkward input is one refactor away from not separating anything, and
the fix costs nothing on a surface with no deployed keys yet.

The 32 output bytes are used directly:

- **secp256k1**: the big-endian private scalar. If it is zero or at least the
  group order, the call fails. That is a ~2^-128 event for a given domain, and the
  caller can choose another one. Folding the scalar into range would silently land
  two domains on one key.
- **ed25519**: the RFC 8032 seed, from which the key expands as usual.

### Public key encoding

| Algorithm | Encoding | Length |
|---|---|---|
| `secp256k1` | SEC1 compressed point, `0x02`/`0x03` prefix | 33 bytes |
| `ed25519` | RFC 8032 raw public key | 32 bytes |

These are the exact bytes returned in `public_key` and the exact bytes bound into
the chain claim. A relying party never has to re-derive the public key from the
private key to check the chain.

### Test vectors

Generated with an app root key of

```text
1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
```

| domain | algorithm | private key | public key |
|---|---|---|---|
| `""` | secp256k1 | `59f60584ce6fd2a3a31997256db9d77322463fc8a6b1520110401bcb1ee92387` | `0377c7fb050db181d392266a3cee9adb2901c6d665f11bac68be5457f577ba4908` |
| `""` | ed25519 | `b023493030669cf22e9cafa6a464d4cf3ae4edfe5474ec796710f21ea011946d` | `a3dc149fd5b765eab2eb7d3174fa939e39386898f10b15b7b146f6f1358ecf2a` |
| `wallet` | secp256k1 | `2580611f0f936abe59399a8ac4ed9964d0259bd34c88ea012ca42b32acbf9386` | `0369cecd3c8da88730f7d45875824c3e75f63a2d3da4be42f45671954daa2abb28` |
| `wallet` | ed25519 | `d76a703b08ebb074b809b9d6acf3d7c6663131273807717ce9d23bbadc2c644e` | `dade622d0fa1641e79b16e0b04e296be671f85f0aa6387b7d37e9d89f87494f5` |
| `a/b/c` | secp256k1 | `7f0973449298085d2d36a3b4c4d3243c100ba1981ffa885fe9e9dee883e69538` | `02e9b1a61b6d70aa9b241753828c316bf90e33e77b2e113f9ba75a8b6dc3cde5c1` |
| `k\0:ey` | ed25519 | `42da8bf0b479ed125c370e3b91f982735bf08ff592abbd586985affa43ee96a1` | `c833107822b003ff5675b33b90b151d4315c3ab9162b17d876e8dffde41abf9b` |

The last row's domain is the five bytes `6b 00 3a 65 79`. It is there because a
delimiter-joined encoding would mishandle it.

The same vectors are asserted in
`dstack/guest-agent/src/rpc_service_v1/keys.rs`. They describe deployed key
material, so a diff against them is a bug in the derivation, not a stale fixture.

## The signature chain

`GetKey` returns a two-element `signature_chain` alongside the key.

```text
[0]  app root key  signs  the v1 key claim (specified here)
[1]  KMS root key  signs  the app root public key (unchanged from v0)
```

Link 1 is produced by the KMS, outside the agent, and both API surfaces pass the
same bytes through. Only link 0 is new.

### Link 0: the key claim

```text
claim  = LP("dstack-guest-v1-key-claim")
      || LP(algorithm)
      || LP(domain)
      || LP(public_key)

digest = keccak256(claim)
link0  = r || s || v          (65 bytes)
```

`link0` is a recoverable ECDSA secp256k1 signature over `digest` by the app root
key. `r` and `s` are 32-byte big-endian integers, low-S normalised, and `v` is the
one-byte recovery id in `0..=3`. `public_key` is the raw derived public key from
the table above, not a hex string.

A worked claim, for `domain = "wallet"` and `algorithm = "secp256k1"`:

```text
00 00 00 19  "dstack-guest-v1-key-claim"     25 bytes
00 00 00 09  "secp256k1"                      9 bytes
00 00 00 06  "wallet"                         6 bytes
00 00 00 21  03 69 ce cd ... bb 28           33 bytes
```

With the app root key from the test vector table, `link0` is

```text
af26d2f258d34580e7288bd83fc97bddc83769476d77823c4f76a3ad77a75149
1a39ffc4ef3aa66cb0d008b8f6f199e6d57c1da9a92ba4cf10f23bf752b8cad0
00
```

The signature is deterministic (RFC 6979), so this vector pins the whole encoding
including the recovery byte.

#### Why this cannot be forged through v0

v0's claim is `keccak256("{purpose}:{hex(pubkey)}")`, and `purpose` is an
arbitrary caller-supplied string. A malicious application can therefore make the
app root key sign nearly any ASCII byte string that ends in `:` followed by
lowercase hex. If a v1 claim were reachable that way, the v1 chain would be worth
nothing.

It is not reachable, and the reason is structural rather than probabilistic.

Every v0 preimage ends with `:` followed by the hex encoding of a public key, so
its last 64 bytes (ed25519) or 66 bytes (secp256k1) are all lowercase hex
characters. A v1 claim ends with `LP(public_key)`, whose four length bytes are
`00 00 00 21` for secp256k1 and `00 00 00 20` for ed25519, sitting 37 or 36 bytes
from the end. That is inside the region a v0 preimage requires to be hex-only, and
`0x00` is not a hex character. No choice of `purpose` reproduces a v1 claim byte
string, and since the two byte strings can never be equal, matching their keccak
digests would require a preimage attack on keccak256.

The regression test is `a_v0_claim_cannot_be_crafted_into_a_v1_claim` in
`dstack/guest-agent/src/rpc_service_v1/keys.rs`. It builds the strongest available
forgery, a `purpose` set to the v1 claim minus exactly the suffix v0 appends on
its own, then asserts both that the byte strings differ and that the structural
property holds.

The two context tags are also distinct, so a derivation input can never be read as
a claim: `dstack-guest-v1-key` for the KDF, `dstack-guest-v1-key-claim` for the
claim. Because both are length-prefixed, neither encoding is a prefix of the other.

### Link 1: the KMS attestation

Unchanged from v0 and reproduced here so this document is self-contained.

```text
message = "dstack-kms-issued" || ":" || app_id || sec1_compressed(app_root_pubkey)
digest  = keccak256(message)
link1   = r || s || v          (65 bytes)
```

`link1` is a recoverable ECDSA secp256k1 signature over `digest` by the KMS root
key. `app_id` is the raw app id bytes, and the app root public key is SEC1
compressed, 33 bytes.

### Verifying a chain

A relying party holds a `public_key`, a `signature_chain`, the `(domain,
algorithm)` the key was requested under, and the `app_id`. It performs the
following.

1. **Anchor.** Obtain the KMS root public key from a source you trust
   independently of the agent being checked: the `DstackKms` contract's
   `kmsInfo().k256Pubkey`, or a value pinned out of band. This step carries the
   security of everything below it. An attacker who can answer your query for the
   anchor can also mint a self-consistent chain, so reading the anchor from the
   KMS you are checking proves nothing.

2. **Rebuild the claim.** Compute
   `claim = LP("dstack-guest-v1-key-claim") || LP(algorithm) || LP(domain) || LP(public_key)`
   using the canonical algorithm name and the raw public key bytes, then
   `digest0 = keccak256(claim)`.

3. **Recover the app root key.** Split `signature_chain[0]` into `r`, `s`, `v` and
   recover the secp256k1 public key from `(digest0, r, s, v)`. Reject a
   non-canonical high-S `s`. Call the result `app_root_pubkey`, SEC1 compressed.

4. **Rebuild the KMS message.** Compute
   `digest1 = keccak256("dstack-kms-issued" || ":" || app_id || app_root_pubkey)`.

5. **Check link 1.** Verify `signature_chain[1]` over `digest1` against the anchor
   from step 1, either by recovering and comparing to the anchor or by verifying
   `(r, s)` against it directly. Reject high-S here too.

6. **Bind the application.** Confirm the `app_id` you used in step 4 is the
   application you meant to talk to. The chain proves that the KMS issued this app
   root key to *some* application; only this step ties it to yours.

To also check a payload signature an application produced with a key from
`GetKey`, verify that signature against `public_key` under whatever scheme the
application used, then run steps 2 through 6 to establish that `public_key` is what
it claims to be. The two halves are independent: a valid payload signature under an
unverified public key says nothing.

Step 3 recovers the app root key rather than requiring it as an input, which is why
link 0 carries a recovery byte. A verifier that already knows the expected app root
public key may verify `(r, s)` against it directly and compare instead.

## The external surface

`WorkerV1` has three methods, served at `/prpc/v1`.

| Method | Purpose |
|---|---|
| `Info` | Application identity and configuration, subject to `public_tcbinfo` |
| `Version` | The agent version |
| `Health` | Report whether the application is serving |

Nothing here returns key material, and no caller chooses what gets signed or
attested.

### There is no v1 AttestAppKey

The frozen surface has `Worker.GetAttestationForAppKey`, which attests a key the
agent derives from an algorithm name alone. v1 has no counterpart, on purpose.

That method attests the key v0's KDF derives at path `vms` with purpose
`signing`. No v1 `GetKey(domain, algorithm)` call can return that key: the v1
KDF has a different salt, a different `info`, and no `purpose` input at all. A
v1 application calling it would receive an attestation of a public key whose
private half it has no way to obtain, which is worse than having no method --
it looks like it works.

A v1 application attests its own key instead:

1. Derive the key: `GetKey(domain, algorithm)` on the internal socket.
2. Commit to it: build `report_data` over `public_key` yourself. Prefix it so a
   verifier can tell what it is looking at -- see the `dip1::` convention the
   frozen method uses.
3. Attest it: `Attest(report_data)` on the internal socket.
4. Publish it: hand the resulting attestation to relying parties. The
   application serves it; the agent's external listener does not.

This is strictly more capable than the method it replaces. The application picks
which of its keys to attest, and picks the commitment format, instead of being
limited to the single key the agent would derive for it.

Legacy flows keep using `Worker.GetAttestationForAppKey`, unchanged and frozen.
It is Intel TDX only, because it returns a `GetQuoteResponse`.

`Health` is polled by the gateway to decide whether an instance belongs in its
application's load-balancing rotation. It answers from a cache the agent
refreshes on its own timer, so one call costs a lock and a clone however many
gateway nodes are polling. Only instances that opted in via
`RegisterCvmRequest.health_check` are ever polled; see
[Application health checks](./app-health-checks.md).

### public_tcbinfo on the external surface

`WorkerV1.Info` returns the same `InfoResponse` the internal surface returns,
minus what the application asked to keep private. Unless the app-compose sets
`public_tcbinfo`, the three document fields come back as empty strings:

- `app_compose`
- `vm_config`
- `key_provider_info`

Identity and the measurement hashes are always present.

This is close to, but deliberately not the same as, what the frozen
`Worker.Info` does. That one blanks `tcb_info` and `vm_config`, and serves
`key_provider_info` externally in every case. v1 blanks `key_provider_info` too:
it names the component holding the application's keys, and an external caller
has no use for it. The frozen behaviour is unchanged on its own surface, so a
v0.5.x client sees exactly what it always did.

| Field | `Worker.Info` (frozen) | `WorkerV1.Info` |
|---|---|---|
| identity, measurement hashes | always served | always served |
| `tcb_info` / measurement registers | blanked | not in the message at all |
| `vm_config` | blanked | blanked |
| `app_compose` | (nested in `tcb_info`, blanked) | blanked |
| `key_provider_info` | **always served** | **blanked** |

The internal `DstackGuestV1.Info` applies no gating at all. The flag decides what
an outside party may learn, and the caller on the internal socket is the
application itself; an application cannot need protecting from its own
configuration.

## Attestation

`Attest` is v1's only CVM attestation entry point. It takes up to 64 bytes of
`report_data`, zero-padded on the right to 64; more than 64 bytes is an error
rather than a truncation. It returns the versioned dstack attestation format,
which covers every supported platform.

### Extracting a quote from an attestation

`AttestResponse.attestation` is a `VersionedAttestation`. The authoritative
implementation is `dstack/dstack-attest/src/v1.rs`, and `dstack-verifier` is the
reference consumer.

The wire format is sniffed from the first byte. A leading `0x00` marks the legacy
SCALE-encoded V0 form; a MessagePack map prefix marks V1. V1 decodes as a
MessagePack map produced by `rmp_serde::to_vec_named`:

```text
{ "version": u64,
  "platform": { "kind": <tag>, "data": { ... } },
  "stack":    { "kind": <tag>, "data": { ... } } }
```

`platform.kind` is one of `tdx`, `gcp-tdx`, `nitro-enclave`, `aws-nitro-tpm`, or
`sev-snp`. For `tdx` and `gcp-tdx`, `platform.data` carries `quote` (the raw TDX
quote bytes, exactly what the unversioned `GetQuote` returned) and `event_log`.
`gcp-tdx` additionally carries `tpm_quote`, which GCP's own verification binds and
which `GetQuote` had no field for. The other three platforms have no TDX quote,
which is why `GetQuote` could not answer on them at all.

`stack.data.report_data` carries the 64 bytes the caller asked for.

V2 runtime events in the event log always include the hex-encoded preimage of
their digest; a verifier should check that `sha384(hex_decode(preimage))` equals
the digest.

### GPU evidence

`AttestResponse.boottime_gpu_evidence` is populated only when the request sets
`include_boottime_gpu_evidence` and boot-time output exists. It is not bound to
`report_data`: nvattest ran at boot against its own nonce. To bind it, replay the
runtime event log and compare `sha256` of those exact UTF-8 bytes against the
`evidence_sha256` field of the measured `gpu-attestation` event.

That evidence is a historical statement about the boot and does not prove the GPU
is still attached. Sampling the GPU at attestation time would not fix it, because
an NVIDIA report binds the device and a nonce but not the TD the device is
attached to, so a fresh report can be relayed from a genuine remote GPU. Only
TDISP/TEE-IO device binding closes that gap.

`AttestGpu` answers the narrower question of whether the device reachable right
now is a genuine CC-enabled GPU that signs a caller-chosen 32-byte nonce. It
returns vendor-native evidence bundles rather than a local verdict, so a relying
party appraises them with its own verifier.

## Info

`Info` returns identity and configuration. It is not attestation, and nothing it
returns is evidence: the response arrives over a local socket with no quote behind
it.

That is why the measurement registers and the event log are absent. v0's
`AppInfo.tcb_info` carried MRTD, RTMR0-3 and the event log inside a JSON string,
which invited relying parties to read measurements out of an unattested response.
Those values belong to `Attest`, whose attestation carries them quote-backed.

`mr_aggregated`, `os_image_hash` and `compose_hash` remain, deliberately. They
identify *which* application and image this is, which is the question `Info`
answers. They are typed bytes rather than hex strings inside a JSON blob, and each
appears exactly once; v0 returned all three both as top-level fields and again,
hex-encoded, inside `tcb_info`. They are still unattested, and a relying party
still confirms them against an attestation.

`app_cert` is gone. It was a self-issued demo certificate the agent minted for a
dashboard, and it proved nothing.

`app_compose` carries the verbatim deployed document. `compose_hash` is `sha256`
over exactly those bytes, so do not parse and re-serialize before hashing: key
order, whitespace and unknown fields all change the digest, and that digest is
what gets whitelisted on chain.

`DstackGuestV1.Info` on the internal socket applies no hiding: the caller is the
application itself, which cannot need protecting from its own configuration.
`WorkerV1.Info` on the external listener honours `public_tcbinfo`; see
[public_tcbinfo on the external surface](#public_tcbinfo-on-the-external-surface),
which is the authoritative description.

## Errors

| Condition | Behaviour |
|---|---|
| Empty or unrecognised `algorithm` | Error naming the accepted values |
| Derived secp256k1 scalar out of range | Error; the caller picks another domain |
| `report_data` longer than 64 bytes | Error |
| `not_before` not earlier than `not_after` | Error |
| Unknown method on a mounted surface | HTTP 404, `Service not found: <Method>` |
| `/v1/...` on an agent that predates v1 | HTTP 404, no such mount |

Everything above the last two rows is an HTTP 400 with the message in the body.
See [Status codes](#status-codes) for the full mapping. v1 does not default,
coerce, or truncate a malformed request into a well-formed one.

## Migration from the unversioned API

**v1 keys are different keys.** Deriving under the same name on `/v1` that an
application used on `/` returns different key material. This is the point of the
new KDF, not a defect: the v0 derivation ignored the algorithm, so one secret
served two curves. There is no compatibility mode and no flag to get the old bytes
back from `/v1`.

An application holding assets or identity under a v0 key must migrate them
deliberately. Derive the v1 key, move the asset with a transaction signed by the
v0 key, and only then cut over. An application with no persistent state can switch
by pointing at the new URL.

Both unversioned surfaces stay available and closed. A v0.5.x client keeps
working against a 0.6 agent with no changes: `Sign`, `Verify` and `EmitEvent`
remain on the internal one (`EmitEvent` fails with a message naming its removal),
and `GetAttestationForAppKey` remains on the external one. Nothing forces a
migration.

**SDK shape.** The SDKs do not implement v1 yet; that lands in a later release.
This is the contract they will implement, stated here so integrators can plan
against it and so the SDK work has something to be checked against.

They will ship two clients mirroring the two surfaces: a `ClientV0` for the
closed unversioned API, including its `Sign` and `Verify` RPCs, and a `ClientV1`
for this one. They will be transport mirrors, not a compatibility layer, and
neither will translate calls to the other. `ClientV1` will have no `Sign` and no
`Verify`, because v1 has neither; an application signs locally and a relying
party verifies locally, following the rules above.

Until that release, the current SDKs speak the frozen surface only. Against a
0.6 agent they keep working, because that surface is still mounted.

## Field mapping

For readers porting from the unversioned API.

| v0 | v1 | Note |
|---|---|---|
| `GetTlsKey` | `IssueCert` | Renamed; same behaviour |
| `GetKeyArgs.path` + `.purpose` | `GetKeyRequest.domain` | Merged; both KDF inputs now |
| `GetKeyArgs.algorithm` (defaulted) | `GetKeyRequest.algorithm` | Required; no `k256` alias |
| — | `GetKeyResponse.public_key` | Added |
| `GetQuote` | `Attest` | TDX-only channel subsumed |
| `AppInfo.tcb_info` | — | Measurements are typed fields; the rest belongs to `Attest` |
| `AppInfo.app_cert` | — | Dashboard artifact |
| `AppInfo.vm_config` | `InfoResponse.vm_config` | Unchanged content |
| `AppInfo.key_provider_info` | `InfoResponse.key_provider_info` | Unchanged content |
| (nested in `tcb_info`) | `InfoResponse.app_compose` | Promoted to top level |
| `Sign` | — | Removed; sign locally with the key from `GetKey` |
| `Verify` | — | Removed; verify locally per this document |
| `EmitEvent` | — | Removed; RTMR3 is system-owned |
| `Worker.GetAttestationForAppKey` | — | No v1 counterpart; a v1 app attests its own key, see above |
| `Worker.Info` | `WorkerV1.Info` | Also gates `key_provider_info`; see above |

## Related documents

- [Attestation on Intel TDX](./attestation-tdx.md)
- [Application health checks](./app-health-checks.md), for `WorkerV1.Health`
- [App Compose format](./normalized-app-compose.md), for the schema behind
  `InfoResponse.app_compose`
- [On-chain governance](./onchain-governance.md), for the `DstackKms` contract that
  publishes the KMS root public key
