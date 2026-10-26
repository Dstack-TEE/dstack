# dstack SDK for Python

Access TEE features from your Python application running inside dstack. Derive deterministic keys, request attestations, and issue TLS certificates—all backed by hardware security.

## The default client speaks v1

dstack 0.6.0 split the guest agent API into two surfaces on one socket, and the
agent picks between them by URL path alone. This SDK mirrors both, and nothing
more — neither client translates calls to the other.

| Client | Surface | Paths | What it is |
|---|---|---|---|
| `DstackClient` / `AsyncDstackClient` — same classes as `DstackClientV1` / `AsyncDstackClientV1` | `dstack.guest.v1` | `/v1/GetKey` | **The default.** Where every new capability lands |
| `DstackClientV0` / `AsyncDstackClientV0` | the frozen v0.5.11 API | `/GetKey`, equivalently `/v0/GetKey` | Legacy. Frozen: no new method, no new field, ever |

Use the unsuffixed name in new code. The `V1` names are the same classes, spelled
out for code that wants the surface visible at a glance.

> [!WARNING]
> **v1 derives different key material than v0.** `DstackClient.get_key('x', 'secp256k1')`
> and `DstackClientV0.get_key('x')` return different private keys. The v1 KDF binds
> the algorithm and its own context tag alongside the domain, which is the point of
> the new derivation, not a defect: v0 ignored the algorithm, so one secret served
> two curves. There is no compatibility mode and no flag that brings the old bytes
> back. An application that has published or committed to material derived from a v0
> key must migrate deliberately — derive the v1 key, re-establish whatever depends on
> the old one under it, and only then cut over.
>
> Code that used the unsuffixed client for v0 calls fails **loudly** on upgrade
> rather than silently deriving different keys, because the v1 method signatures
> differ and `get_key` requires `algorithm` explicitly. To stay on the frozen
> surface, switch to `DstackClientV0`.

The v1 surface serves only what genuinely needs the TEE, so it has no `sign`, no
`verify`, no `emit_event`, no `get_quote` and no `gpu_info`. See
[`docs/guest-api-v1.md`](../../docs/guest-api-v1.md) for the normative spec, and
[Legacy (v0, frozen)](#legacy-v0-frozen) for the surface those methods live on.

## Installation

```bash
pip install dstack-sdk
```

Blockchain helpers are optional extras, needed only for the v0-era chain
adapters ([Blockchain helpers](#blockchain-helpers)):

| Extra | Pulls in | Use when |
|---|---|---|
| `dstack-sdk[ethereum]` | `eth-account` | You sign Ethereum transactions |
| `dstack-sdk[solana]` | `solders` | You sign Solana transactions |
| `dstack-sdk[all]` | both | You need both |

Aliases `[eth]` and `[sol]` are accepted for convenience.

## Quick Start

```python
from dstack_sdk import DstackClient

client = DstackClient()

key = client.get_key('storage-encryption', 'secp256k1')   # algorithm is required
attestation = client.attest(b'my-app-state')
info = client.info()
```

The client automatically connects to `/var/run/dstack.sock`. For local
development with the simulator:

```python
client = DstackClient('http://localhost:8090')
# or export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
```

Every v1 method requires a 0.6.0+ guest agent: older agents have no `/v1` mount
and answer HTTP 404.

## Client

`DstackClient` speaks `dstack.guest.v1` at `/v1/<Method>`. Six methods, and
deliberately no more — v1 serves only what genuinely needs the TEE. In the
examples below, `client = DstackClient()`.

### `get_key()`

Derives deterministic keys bound to your application's identity (`app_id`). The
same domain always produces the same key for your app, and different apps get
different keys for the same domain.

```python
key = client.get_key('storage-encryption', 'secp256k1')
print(key.key)             # 32 raw bytes
print(key.public_key)      # SEC1 compressed (33 B), or 32 B for ed25519
print(key.signature_chain) # two links: app root, then KMS root
```

Every field the proto declares `bytes` is `bytes` here, hex only on the wire.
`public_key` in particular is what the v1 key claim commits to, and the claim is
built over raw bytes — passing a hex string would build it over 66 ASCII
characters and produce a chain that silently never verifies.

**Parameters:**
- `domain`: Any string. This replaces v0's `path` plus `purpose`; in v0 only `path` reached the KDF and `purpose` was merely echoed into the chain claim. Derivation is flat — two domains give unrelated keys, and `a/b` is not a child of `a`.
- `algorithm`: Exactly `'secp256k1'` or `'ed25519'`. **Required.** There is no default and no `k256` alias, because in v0 a typo silently produced a key of the wrong type under a name the caller thought meant something else. An empty value is rejected client-side.

**Returns:** `GetKeyResponseV1` with `key: bytes`, `public_key: bytes` and
`signature_chain: list[bytes]`.

### `attest()`

The sole CVM attestation entry point in v1. The dstack attestation format
already carries the quote and the event log, so v0's TDX-only `get_quote` has
nothing left to add.

`report_data` is bytes, never `str`. v0 accepted a `str` and UTF-8 encoded it,
so `attest("deadbeef")` committed to the eight ASCII characters rather than the
four bytes they spell, with no error to say so; v1 makes you write
`value.encode()` or `bytes.fromhex(value)` at the call site, where it is visible
which one was meant. `attest_gpu`'s nonce is bytes only for the same reason.

```python
result = client.attest(b'user:alice:nonce123')
print(result.attestation)   # bytes

with_gpu = client.attest(b'user:alice:nonce123', include_boottime_gpu_evidence=True)
for bundle in with_gpu.boottime_gpu_evidence:
    print(bundle.vendor, bundle.format, bundle.evidence)
```

`report_data` is 1–64 bytes and is zero-padded on the right to 64.
`boottime_gpu_evidence` is a list of `GpuEvidenceBundleV1` — the same model
`attest_gpu()` returns, so one bundle parser serves both methods. It is empty
unless the flag was set and the guest has boot-time output; there is no
sentinel. Boot-time bundles carry `format='nvidia-nvattest-boottime-json-v1'`,
against `attest_gpu()`'s `'nvidia-nvattest-collect-evidence-json-v1'`.

Boot-time evidence is *not* bound to `report_data` — nvattest ran at boot
against its own nonce. Bind it by replaying the runtime event log and comparing
sha256 of `bundle.evidence` against `evidence_sha256` in the measured
`gpu-attestation` event. `evidence` is the nvattest output byte for byte; do not
parse and re-serialize before hashing, since key order and whitespace change the
digest.

### `attest_gpu()`

Samples the GPU *now*, against a nonce you choose — which is what
`boottime_gpu_evidence` cannot tell you, since that is a record written at boot.
Use it after anything that may have reinitialised the GPU.

```python
result = client.attest_gpu(os.urandom(32))  # exactly 32 bytes
for bundle in result.bundles:
    print(bundle.vendor, bundle.format, bundle.evidence)
```

Select a verifier using each bundle's `vendor` and `format`, then check the
signature, certificate chain, measurements, and the nonce embedded in the
evidence. `evidence` is opaque vendor-native bytes, hex-encoded on the wire — do
not assume UTF-8 or JSON. It does not by itself bind the GPU to this CVM; only
TDISP/TEE-IO device binding closes that gap.

### `issue_cert()`

v0 called this `get_tls_key()`, which named the by-product rather than the
request. The private key is freshly generated per call and is *not* derived from
the app identity: two calls with the same arguments return two unrelated keys.

```python
cert = client.issue_cert(
    subject='api.example.com',
    alt_names=['localhost'],
    usage_ra_tls=True,       # Embed the attestation in the certificate
    usage_server_auth=True,
    usage_client_auth=False,
    with_app_info=True,
    not_before=1700000000,   # seconds since UNIX epoch
    not_after=1800000000,
)
print(cert.key)                 # PEM private key
print(cert.certificate_chain)   # PEM chain, leaf first
```

**Returns:** `IssueCertResponseV1` with a PEM `key` and a leaf-first
`certificate_chain`.

### `info()`

```python
info = client.info()
print(info.app_id, info.app_name, info.compose_hash)
print(info.instance_id, info.device_id)
print(info.os_image_hash, info.mr_aggregated)
print(info.app_compose, info.vm_config, info.key_provider_info)
print(info.cloud_vendor, info.cloud_product)
```

Identity and configuration — not attestation. Nothing here is evidence: it
arrives over a local socket with no quote behind it. That is why there is no
`tcb_info` and no `app_cert`. The measurement registers and the event log belong
to `attest()`, which returns them quote-backed. `compose_hash`, `os_image_hash`
and `mr_aggregated` are here because they identify *which* application and image
this is, and a relying party still confirms them against an attestation.

`app_compose` is the verbatim deployed document and `compose_hash` is sha256
over exactly those bytes — do not parse and re-serialize before hashing.

`app_id`, `instance_id`, `compose_hash`, `device_id`, `os_image_hash` and
`mr_aggregated` are `bytes`, matching the proto. Call `.hex()` to print one.

### `version()`

```python
client.version()   # VersionResponseV1(version, rev)
```

### Async

`AsyncDstackClient` has the identical surface, with every method a coroutine:

```python
import asyncio
from dstack_sdk import AsyncDstackClient

async def main():
    client = AsyncDstackClient()

    info = await client.info()
    key = await client.get_key('backup-signing', 'ed25519')

    # Run requests concurrently
    keys = await asyncio.gather(
        client.get_key('user/alice', 'secp256k1'),
        client.get_key('user/bob', 'secp256k1'),
    )

asyncio.run(main())
```

`AsyncDstackClient` accepts the same constructor as `DstackClient` plus
`use_sync_http: bool = False` for callers that need to issue sync HTTP from
within an async context. The same holds for the v0 clients.

### Signing and verifying

Neither is a v1 method. Signing happens wherever the key is, and `get_key()`
already hands you the key, so a round trip to the agent adds nothing; verifying
needs no key at all, and an agent's answer arrives over the socket unattested,
so a relying party gains nothing over checking the signature itself with a
standard library.

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

key = client.get_key('signing/messages', 'ed25519')
signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(key.key)
signature = signing_key.sign(b'message to sign')
```

To verify a v1 signature chain, follow
[`docs/guest-api-v1.md`](../../docs/guest-api-v1.md), which is the normative
spec: it gives the claim encoding, the link order, and — the part that actually
establishes anything — the requirement that the KMS root public key come from
somewhere you already trust (the `DstackKms` contract's `kmsInfo().k256Pubkey`,
or a value you pinned), never from the CVM being checked.

---

## Deployment Utilities

These utilities are for deployment scripts, not runtime SDK operations, and are
the same for either client.

### Encrypted Environment Variables

The KMS returns a fresh X25519 public key (with a secp256k1 signature) that you encrypt secrets against before submitting them with your deployment. Always verify the signer before trusting the key:

```python
from dstack_sdk import (
    encrypt_env_vars,
    verify_env_encrypt_public_key,
    EnvVar,
)

# `public_key`, `signature_v1`, `timestamp` come from KMS /GetAppEnvEncryptPubKey.
signer = verify_env_encrypt_public_key(
    public_key=public_key_bytes,
    signature=signature_v1_bytes,
    app_id=app_id_hex,
    timestamp=timestamp,
)
if signer is None:
    raise RuntimeError('invalid KMS env-encrypt public key')

# Always compare the recovered signer against a known-good KMS signer
# address, obtained out-of-band from the DstackKms contract or your
# deployment configuration. Without this check, an attacker could sign
# their own env-encrypt key and the verification above would still pass.
EXPECTED_KMS_SIGNER = '0x...'  # replace with your known KMS signer address
if signer != EXPECTED_KMS_SIGNER:
    raise RuntimeError(
        f'unexpected KMS signer: got {signer}, '
        f'expected {EXPECTED_KMS_SIGNER}'
    )

env_vars = [
    EnvVar(key='DATABASE_URL', value='postgresql://...'),
    EnvVar(key='API_KEY', value='secret'),
]
encrypted = await encrypt_env_vars(env_vars, public_key_hex)
# encrypt_env_vars_sync(...) is also available for non-async callers.
```

`verify_env_encrypt_public_key` returns the recovered compressed secp256k1 signer (`0x`-prefixed hex) on success, or `None` for any failure (bad length, expired/future timestamp, malformed `app_id`, invalid signature). The default `max_age_seconds` is 300; pass a larger value if your deployment workflow legitimately holds the response longer.

`verify_env_encrypt_public_key_legacy` remains available only for deployments that explicitly support older KMS builds without `signature_v1`. It does not provide timestamp replay protection and should not be used for new deployments.

### Calculate Compose Hash

```python
from dstack_sdk import get_compose_hash

hash_value = get_compose_hash(app_compose_dict)
```

---

## Compatibility

| Feature | Required dstack OS |
|---|---|
| Every `DstackClient` (v1) method | 0.6.0+ — older agents have no `/v1` mount and answer HTTP 404 |
| V0 `get_key`, `get_quote`, `get_tls_key` (legacy fields), `info` (legacy fields) | 0.3+ |
| V0 `attest`, `sign`, `verify`, `is_reachable` | 0.5.0+ (`sign` requires a server build with the feature) |
| V0 `version`, `algorithm='ed25519'` on `get_key`, `info.cloud_vendor` / `cloud_product`, `not_before` / `not_after` / `with_app_info` on `get_tls_key` | 0.5.7+ |
| V0 `emit_event` | Removed in 0.6.0: the agent always fails it |
| `verify_env_encrypt_public_key` (signature_v1 with timestamp) | Requires KMS build that emits `signature_v1`; legacy variant remains available |

V0 calls that require 0.5.7-only fields probe the `Version` RPC first and raise a clear `RuntimeError` on older guest agents. The v1 client never probes: it requires a 0.6 agent outright.

## Development

For local development without TDX hardware, use the simulator:

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
```

Then set the endpoint:

```bash
export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
```

Install dev dependencies, then run the tests and the format/lint checks with PDM:

```bash
cd sdk/python
pdm install --dev
pdm run test
pdm run check
```

`make install` / `make test` wrap the same commands and additionally assert that
`DSTACK_SIMULATOR_ENDPOINT` and `TAPPD_SIMULATOR_ENDPOINT` are set.

---

# Legacy (v0, frozen)

Everything below is the frozen v0.5.11 surface. It still works and is still
served, but it gains no method and no field. Reach for it when you must keep the
v0 key derivation, or when you need `sign` / `verify`, which v1 does not serve.

Import it by its explicit name — the unsuffixed `DstackClient` now means v1:

```python
from dstack_sdk import DstackClientV0, AsyncDstackClientV0

v0 = DstackClientV0()
```

## V0 Client

In the examples below, `v0 = DstackClientV0()`.

### Derive Keys

`get_key()` derives deterministic keys bound to your application's identity (`app_id`). The same path always produces the same key for your app, but different apps get different keys even with the same path.

```python
# Derive keys by path
eth_key = v0.get_key('wallet/ethereum')
btc_key = v0.get_key('wallet/bitcoin')

# Use path to separate keys
mainnet_key = v0.get_key('wallet/eth/mainnet')
testnet_key = v0.get_key('wallet/eth/testnet')

# Use a different signature algorithm (requires dstack OS >= 0.5.7)
ed_key = v0.get_key('signing/key', algorithm='ed25519')
```

**Parameters:**
- `path` (optional): Key derivation path. Defaults to `""` (root).
- `purpose` (optional): Included in the signature chain message; does not affect the derived key.
- `algorithm` (optional): `'secp256k1'` (default) or `'ed25519'`. For compatibility, this selects how the same derived 32-byte material is interpreted; it does not domain-separate the derivation. Use algorithm-specific paths when independent keys are required.

**Returns:** `GetKeyResponse`
- `key`: Hex-encoded private key
- `signature_chain`: Signatures proving the key was derived in a genuine TEE
- `decode_key()` / `decode_signature_chain()`: Helpers that return `bytes`

### Generate Attestation Quotes

`get_quote()` creates a TDX quote proving your code runs in a genuine TEE.
It needs Intel TDX: without it the call fails, and on GCP Confidential VMs it
returns the TDX quote alone, leaving out the vTPM quote GCP's verification also
binds. Call `attest()` in both cases.

```python
quote = v0.get_quote(b'user:alice:nonce123')
print(quote.event_log)
```

**Parameters:**
- `report_data`: Up to 64 bytes (`bytes` or `str`). Shorter inputs are padded with zeros; longer inputs should be hashed first (e.g., SHA-256).

**Returns:** `GetQuoteResponse`
- `quote`: Hex-encoded TDX quote
- `event_log`: JSON string of measured events
- `decode_quote()` / `decode_event_log()`: Helpers

### Versioned Attestation

`attest()` returns a versioned attestation payload that newer verifier APIs can dispatch on without sniffing the quote format.

```python
result = v0.attest(b'user:alice:nonce123')
print(result.attestation)        # hex string
print(result.decode_attestation())  # bytes
```

`report_data` is the only argument. GPU evidence — boot-time and on-demand alike —
is a v1 capability; see [`attest()`](#attest) and [`attest_gpu()`](#attest_gpu).

### Get Instance Info

```python
info = v0.info()
print(info.app_id)
print(info.instance_id)
print(info.tcb_info)
print(info.cloud_vendor, info.cloud_product)  # 0.5.7+
```

**Returns:** `InfoResponse`
- `app_id`, `instance_id`, `app_name`, `device_id`
- `tcb_info`: TCB measurements (MRTD, RTMRs, event log, compose hash, ...)
- `compose_hash`: Hash of the app configuration
- `app_cert`: Application certificate (PEM)
- `key_provider_info`: Key management configuration
- `cloud_vendor` / `cloud_product`: Cloud provider strings (empty on older OS)

### Generate TLS Certificates

`get_tls_key()` creates fresh TLS certificates. Unlike `get_key()`, each call generates a new random key.

```python
tls = v0.get_tls_key(
    subject='api.example.com',
    alt_names=['localhost'],
    usage_ra_tls=True,    # Embed attestation in certificate
    # 0.5.7+ options below:
    not_before=1700000000,   # seconds since UNIX epoch
    not_after=1800000000,
    with_app_info=True,
)
print(tls.key)                  # PEM private key
print(tls.certificate_chain)    # Certificate chain
```

**Parameters:**
- `subject` (optional): Certificate Common Name (e.g., domain name)
- `alt_names` (optional): Subject Alternative Names
- `usage_ra_tls` (optional): Embed TDX quote in a certificate extension (default `False`)
- `usage_server_auth` (optional): Enable for server authentication (default `True`)
- `usage_client_auth` (optional): Enable for client authentication (default `False`)
- `not_before` / `not_after` (optional, kw-only): Validity window in seconds since UNIX epoch. Requires dstack OS >= 0.5.7.
- `with_app_info` (optional, kw-only): Embed app identity into the certificate. Requires dstack OS >= 0.5.7.

When any of the 0.5.7-only options is set, the SDK probes `Version` first and raises `RuntimeError` on older guest agents that lack it.

**Returns:** `GetTlsKeyResponse`
- `key`: PEM-encoded private key
- `certificate_chain`: List of PEM certificates
- `as_uint8array(max_length=None)`: Returns the DER-encoded private key bytes (handy when feeding key material into low-level crypto libraries)

### Sign and Verify

Both are frozen v0 RPCs and neither has a v1 counterpart.

```python
result = v0.sign('ed25519', b'message to sign')

verdict = v0.verify(
    'ed25519',
    b'message to sign',
    result.decode_signature(),
    result.decode_public_key(),
)
assert verdict.valid is True
```

**`sign()` Parameters:**
- `algorithm`: `'ed25519'`, `'secp256k1'` (alias `'k256'`), or `'secp256k1_prehashed'`
- `data`: Data to sign (`bytes` or `str`). For `secp256k1_prehashed`, must be a 32-byte digest.

**`sign()` Returns:** `SignResponse`
- `signature`: Hex-encoded signature
- `public_key`: Hex-encoded public key
- `signature_chain`: Three signatures linking the signing key back to the KMS root

**`verify()` Returns:** `VerifyResponse` with a single `valid: bool`. It reports
only whether that one signature matches that one public key — it says nothing
about *whose* key it is, and it does not walk the signature chain.

Earlier drafts of this SDK shipped local `verify_signature` and
`verify_signature_chain` helpers. They are gone; verify locally per
[`docs/guest-api-v1.md`](../../docs/guest-api-v1.md).

### Diagnostics

```python
v0.version()        # VersionResponse(version, rev) — raises on OS < 0.5.7
v0.is_reachable()   # Quick connectivity probe; never raises
```

### Async

`AsyncDstackClientV0` has the identical surface, with every method a coroutine:

```python
import asyncio
from dstack_sdk import AsyncDstackClientV0

async def main():
    v0 = AsyncDstackClientV0()

    info = await v0.info()
    key = await v0.get_key('wallet/eth')

    # Run requests concurrently
    keys = await asyncio.gather(
        v0.get_key('user/alice'),
        v0.get_key('user/bob'),
    )

asyncio.run(main())
```

### Removed in 0.6.0

`emit_event()` is still on the client, but the agent now fails every call:
runtime RTMR3 events are system-owned and an app can no longer extend them. The
method remains so that a caller written against 0.5.x gets the agent's own
explanation rather than a 404. `attest_gpu()` and `gpu_info()` never shipped on
this surface and are not here; they live on the v1 client.

## Blockchain helpers

The chain adapters are v0-era. `dstack_sdk.ethereum` and `dstack_sdk.solana`
take a v0 `GetKeyResponse` or `GetTlsKeyResponse`, and that is the only shape
they take: v1 has no chain-related surface. `get_key()` returns key material,
and what an application builds out of those bytes is its own business.

```python
from dstack_sdk import DstackClientV0
from dstack_sdk.ethereum import to_account_secure
from dstack_sdk.solana import to_keypair_secure

v0 = DstackClientV0()

account = to_account_secure(v0.get_key('wallet/ethereum'))
print(account.address)

keypair = to_keypair_secure(
    v0.get_key('wallet/solana', purpose='mainnet', algorithm='ed25519')
)
print(keypair.pubkey())
```

`to_account_secure` / `to_keypair_secure` hash the full key material with
SHA-256 before deriving. The legacy `to_account()` / `to_keypair()` use raw key
bytes and are kept only for backward compatibility.

## Migration from TappdClient

`TappdClient` only ever spoke v0, so replace it with `DstackClientV0` —
not with the unsuffixed name, which is now v1 and derives different keys:

```python
# Before
from dstack_sdk import TappdClient
client = TappdClient()

# After
from dstack_sdk import DstackClientV0
v0 = DstackClientV0()
```

Method changes:
- `derive_key()` → `get_tls_key()` for TLS certificates
- `tdx_quote()` → `get_quote()` (raw data only, no hash algorithms)
- Socket path: `/var/run/tappd.sock` → `/var/run/dstack.sock`

## Migration from v0 to v1

v1 is a separate surface, not an upgrade path — read the key warning at the top
before switching anything that holds state.

| v0 | v1 | Note |
|---|---|---|
| `get_tls_key()` | `issue_cert()` | Renamed; same behaviour |
| `get_key(path, purpose)` | `get_key(domain, algorithm)` | Merged into one KDF input; `algorithm` is now required |
| `get_quote()` | `attest()` | The TDX-only channel is subsumed |
| `info().tcb_info` | — | Measurements are typed fields; the rest belongs to `attest()` |
| `info().app_cert` | — | A dashboard artifact; it proved nothing |
| `sign()` | — | Sign locally with the key `get_key()` returns |
| `verify()` | — | Verify locally, per `docs/guest-api-v1.md` |
| `emit_event()` | — | RTMR3 is system-owned as of 0.6.0 |
| `gpu_info()` | `attest()` with `include_boottime_gpu_evidence=True` | Same bytes, now on the attestation call, in `attest_gpu()`'s bundle shape |

## License

Apache License 2.0
