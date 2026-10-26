# @phala/dstack-sdk

JavaScript / TypeScript client for the dstack guest agent. Derive deterministic keys, produce TDX attestations, issue TLS certificates, and encrypt environment variables for KMS-managed deployments — all against the guest agent socket inside a confidential VM (CVM).

## Installation

```bash
npm install @phala/dstack-sdk
```

`@noble/hashes` and `@noble/curves` ship as regular dependencies — the core needs them for hashing and for verifying the KMS env-encryption key. Install the matching peer when you import one of the v0-era chain submodules:

| Import path | Extra peer dependency |
| --- | --- |
| `@phala/dstack-sdk/viem` | `viem` |
| `@phala/dstack-sdk/solana` | `@solana/web3.js` |

> **Breaking change in 0.5.8.** Prior releases listed `@solana/web3.js` and `viem` under `optionalDependencies`, so npm installed them automatically. They are now opt-in peers — install them yourself when you use the corresponding submodule.

Node 18+ supported. Tested through Node 24.

## Quick start

```typescript
import { DstackClient } from '@phala/dstack-sdk'

const client = new DstackClient()

const key = await client.getKey('storage-encryption', 'secp256k1')
console.log(Buffer.from(key.key).toString('hex'))

const { attestation } = await client.attest(Buffer.from('app-state-snapshot'))
console.log(attestation)
```

The constructor probes `/var/run/dstack.sock`, then `/run/dstack.sock`, then the `/var/run/dstack/` and `/run/dstack/` variants. Pass an explicit endpoint for HTTP or for a non-default socket:

```typescript
const client = new DstackClient('http://localhost:8090')      // simulator
const client = new DstackClient('/run/dstack/dstack.sock')    // custom path
```

`DSTACK_SIMULATOR_ENDPOINT` overrides the default when set.

An agent that predates v1 has no `/v1` mount at all, so it answers with a plain HTTP 404 page rather than a JSON error. `version()` is the cheapest probe for support.

## Two API surfaces

dstack 0.6.0 splits the guest agent API into two surfaces on the same socket, selected by URL path. This SDK mirrors both.

| Client | Paths | Status |
| --- | --- | --- |
| `DstackClient`, `DstackClientV1` | `/v1/<Method>` | **Current, and the default.** Six methods. Needs guest agent ≥ 0.6.0. |
| `DstackClientV0` | `/<Method>`, and equivalently `/v0/<Method>` | Deprecated. Frozen at the 0.5.11 shape; will not change again. |

The unsuffixed `DstackClient` names v1. `DstackClientV1` is the same class under an explicit name — use whichever reads better; new code should not need `DstackClientV0` at all.

> **v1 keys are not v0 keys.** `getKey` on v1 derives under its own HKDF salt and binds the algorithm and a versioned context tag into the derivation. The same name yields **different key material** on the two surfaces, and under v1 secp256k1 and ed25519 no longer share one 32-byte secret. There is no compatibility mode and no migration path back — an app that has published v0-derived material must keep deriving it with `DstackClientV0`. `docs/guest-api-v1.md` pins the byte-level construction.

Code that used the unsuffixed client for v0 calls fails **loudly** on upgrade rather than silently deriving different keys, because the v1 method signatures differ and `getKey` requires `algorithm` explicitly. To stay on the frozen surface, switch to `DstackClientV0`.

v1 also drops `sign`, `verify`, `getQuote`, `gpuInfo` and `emitEvent`. Those are not oversights: the agent holds two things a caller cannot get elsewhere — the app root key, and the platform's ability to attest — and v1 serves those two things only. Signing and verifying are pure computation over material `getKey` already hands you.

## Client methods

### `issueCert(options?)`

Issue a certificate for this application. The agent generates a key, builds a CSR, signs it, and relays it to the KMS (or to the local CA when the app runs without one).

```typescript
const cert = await client.issueCert({
  subject: 'api.example.com',
  altNames: ['localhost', '127.0.0.1'],
  usageRaTls: true,           // embed the attestation quote in a cert extension
})
cert.key                       // PEM-encoded private key
cert.certificate_chain         // PEM entries, leaf first
```

PEM and nothing else: v0 attached a raw-bytes accessor to this response, but it was there to feed the key into the blockchain adapters, and v1 has no chain-flavored surface. This is TLS material, PEM is what a TLS stack takes, and DER is one standard-library call away if you want it.

Options: `subject`, `altNames`, `usageRaTls`, `usageServerAuth` (default `true`), `usageClientAuth` (default `false`), `withAppInfo`, `notBefore`, `notAfter` (Unix seconds).

The key is freshly generated on every call and is not derived from the app identity — two identical requests return two unrelated keys. v0 called this `getTlsKey`, which named the by-product rather than the request. Use `getKey` for stable, attestable material.

### `getKey(domain, algorithm)`

Derive a deterministic application key.

```typescript
const enc = await client.getKey('storage-encryption', 'secp256k1')
const sig = await client.getKey('backup-signing', 'ed25519')   // unrelated key material

enc.key             // Uint8Array, 32 bytes
enc.public_key      // Uint8Array — SEC1 compressed (33) for secp256k1, raw (32) for ed25519
enc.signature_chain // Uint8Array[], exactly 2 links
```

Both arguments are required. `algorithm` is exactly `'secp256k1'` or `'ed25519'` — there is no default and no `k256` alias, because v0's defaulting meant a typo silently produced a key of the wrong type under a name the caller thought meant something else.

`domain` is an opaque domain-separation string, not a DNS name and not a path. Derivation is **flat**: `'a/b'` is a string that happens to contain a slash, not a child of `'a'`, and no key derived here can derive another. It replaces v0's `path` plus `purpose`; both `domain` and `algorithm` now feed the KDF.

`signature_chain` has two links: the app root key over the v1 key claim, then the KMS root key over the app root public key. `docs/guest-api-v1.md` is the normative spec for verifying it — it gives the claim encoding, the recovery steps, and, critically, why the KMS root key has to come from a source you trust independently of the agent you are checking.

### `attest(reportData, includeBoottimeGpuEvidence?)`

The only CVM attestation entry point. The versioned attestation already carries the TDX quote and the event log, so there is no separate `getQuote`.

```typescript
const { attestation } = await client.attest(Buffer.from('app-state-snapshot'))  // Uint8Array
```

Every field the proto declares `bytes` is a `Uint8Array` here, hex only on the wire.

`reportData` is 1 to 64 bytes — a `Buffer` or `Uint8Array`, never a string — zero-padded on the right by the agent. v0 accepted a string and UTF-8 encoded it, so `attest('deadbeef')` committed to eight ASCII characters rather than the four bytes they spell; v1 makes you say which you meant. `attestGpu`'s nonce is bytes only for the same reason, where a 32-character string would have passed the length check. Pass `true` as the second argument to also return the boot-time GPU evidence in `boottime_gpu_evidence`, so a verifier gets both in one round trip:

```typescript
const { attestation, boottime_gpu_evidence } = await client.attest(Buffer.from('snapshot'), true)
for (const bundle of boottime_gpu_evidence) {
  console.log(bundle.vendor, bundle.format, bundle.evidence)
}
```

`boottime_gpu_evidence` is a list of the same `GpuEvidenceBundleV1` objects `attestGpu` returns, so one parser serves both; `format` is what tells them apart (`nvidia-nvattest-boottime-json-v1` here, `nvidia-nvattest-collect-evidence-json-v1` there). Absence is the empty list, not a sentinel: it is empty unless the flag was set and the guest has boot-time output.

That evidence is not bound to `reportData` — nvattest ran at boot against its own nonce. Bind it by replaying the runtime event log and comparing sha256 of `bundle.evidence` — exactly the bytes nvattest emitted, so do not parse and re-serialize the JSON — against `evidence_sha256` in the measured `gpu-attestation` event.

### `attestGpu(nonce)`

Collect GPU evidence now, against a 32-byte nonce you choose. This answers "is the device I can talk to right now a genuine CC-enabled GPU that signs my challenge", which boot-time evidence cannot.

```typescript
const { bundles } = await client.attestGpu(crypto.randomBytes(32))
for (const bundle of bundles) {
  console.log(bundle.vendor, bundle.format, bundle.evidence)
}
```

The nonce must be exactly 32 bytes — SPDM fixes the length, and dstack applies no transform, so you can compare these bytes directly against the `eat_nonce` claim. Hash a longer challenge yourself.

Select a verifier from each bundle's `vendor` and `format`, then check the signature, certificate chain, measurements and embedded nonce. `evidence` is opaque, hex-encoded on the wire and decoded here to the vendor's bytes verbatim. It does not by itself bind the GPU to this CVM.

### `info()`

App identity and configuration. Not attestation.

```typescript
const info = await client.info()
info.app_id            // Uint8Array
info.app_name
info.compose_hash      // Uint8Array — sha256 over exactly the app_compose bytes
info.app_compose       // the deployed document, verbatim
info.instance_id       // Uint8Array
info.device_id         // Uint8Array — identifies the host machine, not this instance
info.os_image_hash     // Uint8Array
info.mr_aggregated     // Uint8Array
info.vm_config         // JSON owned by the VMM
info.key_provider_info // JSON owned by dstack-util
info.cloud_vendor      // e.g. "Google"
info.cloud_product     // e.g. "Google Compute Engine"
```

Flat, with no `tcb_info` blob and no `app_cert`. The measurement registers and the event log are deliberately absent: they belong to `attest()`, which returns them quote-backed. Everything here arrives over a local socket with no quote behind it, so confirm anything you rely on against an attestation.

Do not parse and re-serialize `app_compose` before hashing it — key order, whitespace and unknown fields all change the digest, and that digest is what gets whitelisted on chain.

### `version()`

Returns `{ version, rev }` of the guest agent.

## Compose hash

```typescript
import { getComposeHash, type AppCompose } from '@phala/dstack-sdk/get-compose-hash'

const compose: AppCompose = {
  manifest_version: 2,
  name: 'my-app',
  runner: 'docker-compose',
  docker_compose_file: '...',
  kms_enabled: true,
}

const hash = getComposeHash(compose)
const normalized = getComposeHash(compose, true) // strip bash_script/docker_compose_file overlap
```

Pure function — no TEE call required. Produces the canonical SHA-256 used by the on-chain KMS allowlist.

## Encrypted environment variables

The full deployment flow mirrors `vmm-cli.py`: fetch the env-encrypt public key from KMS, verify its signature locally, then ECIES-encrypt the env vars against it.

```typescript
import {
  verifyEnvEncryptPublicKey,
} from '@phala/dstack-sdk'
import { encryptEnvVars, type EnvVar } from '@phala/dstack-sdk/encrypt-env-vars'

const response = await fetch(`${kmsUrl}/prpc/GetAppEnvEncryptPubKey?json`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ app_id: appId }),
}).then(r => r.json())

const publicKey = Buffer.from(response.public_key, 'hex')

if (!response.signature_v1 || response.timestamp === undefined) {
  throw new Error('kms response missing timestamped signature')
}

const signer = verifyEnvEncryptPublicKey(
  publicKey,
  Buffer.from(response.signature_v1, 'hex'),
  appId,
  BigInt(response.timestamp),
)

if (!signer) throw new Error('kms signature did not verify')

const trustedSigners = new Set(['0x...']) // From the DstackKms contract or deployment config
if (!trustedSigners.has(signer)) throw new Error(`unexpected KMS signer: ${signer}`)

const envs: EnvVar[] = [
  { key: 'DATABASE_URL', value: 'postgresql://…' },
  { key: 'API_KEY', value: 'sk-test-1234' },
]
const encrypted = await encryptEnvVars(envs, response.public_key)
```

Verify functions return the signer's compressed public key (hex) on success, or `null` on failure. `verifyEnvEncryptPublicKeyLegacy` is available only for deployments that explicitly support older KMS builds without `signature_v1`; it does not provide timestamp replay protection and should not be used for new deployments.

## Compatibility

| Feature | Minimum guest agent |
| --- | --- |
| `DstackClient` (v1), all six of its methods | 0.6.0 |
| `DstackClientV0`: `getKey`, `getTlsKey`, `getQuote`, `info` | 0.3.x |
| `DstackClientV0`: `attest`, `sign`, `verify`, `version`, ed25519 keys, `info.cloud_vendor` / `cloud_product`, `getTlsKey` `notBefore` / `notAfter` / `withAppInfo` | 0.5.7 |

`emitEvent` needed 0.5.0 and was removed in 0.6.0; a 0.6.0 agent fails every call.

The SDK's release versions track guest agent versions — `0.6.0-x` targets dstack 0.6.0+, and still speaks the frozen v0 surface to older agents.

## Development

Run the standalone simulator instead of a real TDX host:

```bash
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
```

Then point `new DstackClient()` at the simulator (it picks up `DSTACK_SIMULATOR_ENDPOINT` automatically). Both clients read the same variable, and the one simulator socket serves both surfaces.

## Legacy (v0, frozen)

Everything below is the deprecated `DstackClientV0` surface, frozen at the dstack 0.5.11 shape. It is kept for apps that already published v0-derived material and therefore cannot move. New code should use `DstackClient`.

```typescript
import { DstackClientV0 } from '@phala/dstack-sdk'

const client = new DstackClientV0()
```

### Keys

#### `getKey(path?, purpose?, algorithm?)`

Derive a deterministic key. The same `(app_id, path)` returns the same raw key material; different apps deriving on the same path get different keys.

```typescript
const eth = await client.getKey('wallet/ethereum')                       // secp256k1 (default)
const sol = await client.getKey('wallet/solana', 'mainnet', 'ed25519')   // ed25519
```

Returns `{ key: Uint8Array, signature_chain: Uint8Array[] }`. The signature chain proves the key was derived inside a genuine TEE.

`purpose` is included in the signature-chain message and does not affect the private key bytes. `algorithm` selects how the derived 32-byte material is interpreted: `'secp256k1'` (default), `'k256'` (alias), or `'ed25519'`. It does not domain-separate the derivation, so use algorithm-specific paths such as `wallet/ethereum` and `wallet/solana` when those keys must be independent. ed25519 requires guest agent ≥ 0.5.7.

#### `getTlsKey(options?)`

Generate a fresh random TLS keypair plus certificate chain. Every call returns a new key — use `getKey` for deterministic material.

```typescript
const tls = await client.getTlsKey({
  subject: 'api.example.com',
  altNames: ['localhost', '127.0.0.1'],
  usageRaTls: true,           // embed TDX quote in cert extension
})
```

Options: `subject`, `altNames`, `usageRaTls`, `usageServerAuth` (default `true`), `usageClientAuth` (default `false`), and — on guest agent ≥ 0.5.7 — `notBefore`, `notAfter` (Unix seconds), `withAppInfo`. The client probes `version()` before sending the new options and throws a clear error on older agents instead of silently dropping them.

Returns `{ key: string, certificate_chain: string[], asUint8Array(maxLength?) }`. `key` is PEM-encoded.

### Attestation

#### `getQuote(reportData)`

Generate a raw TDX quote. `reportData` is up to 64 bytes (string, Buffer, or Uint8Array).
Needs Intel TDX: without it the call throws, and on GCP Confidential VMs it returns the TDX quote alone, leaving out the vTPM quote GCP's verification also binds. Call `attest()` in both cases.

```typescript
const quote = await client.getQuote('user:alice:nonce123')
quote.quote        // hex-encoded TDX quote
quote.event_log    // JSON string of measured events
```

#### `attest(reportData)`

Versioned dstack attestation that works across TDX / GCP / Nitro providers. Preferred over `getQuote` for cross-platform verifiers.

```typescript
const { attestation } = await client.attest('app-state-snapshot')
```

`reportData` only — GPU evidence is not available on this surface. Use `DstackClient.attest` or `DstackClient.attestGpu`.

#### `info()`

App identity and TCB metadata.

```typescript
const info = await client.info()
info.app_id              // application identifier
info.instance_id         // CVM instance identifier
info.tcb_info            // parsed { mrtd, rtmr0..3, event_log, ... }
info.compose_hash
info.cloud_vendor        // e.g. "Google" (guest agent ≥ 0.5.7)
info.cloud_product       // e.g. "Google Compute Engine" (guest agent ≥ 0.5.7)
```

#### `version()`

Returns `{ version, rev }` of the guest agent. Throws on agents older than 0.5.7 (the RPC didn't exist).

### Sign and verify

#### `sign(algorithm, data)`

Sign data with a derived key. The SDK rejects mismatched input early — `secp256k1_prehashed` requires a 32-byte digest.

```typescript
const res = await client.sign('ed25519', 'hello dstack')
res.signature        // Uint8Array
res.public_key       // Uint8Array
res.signature_chain  // Uint8Array[] — proves the signing key came from this TEE
```

Algorithms: `ed25519`, `secp256k1`, `secp256k1_prehashed`. Requires guest agent ≥ 0.5.7.

#### `verify(algorithm, data, signature, publicKey)`

Check a single signature through the agent. Returns `{ valid: boolean }`; throws when the agent rejects the input as malformed.

```typescript
const { valid } = await client.verify('ed25519', 'hello dstack', res.signature, res.public_key)
```

This only proves that whoever holds `publicKey` signed the data. Establishing that the signer was a dstack app under a KMS you trust means walking the whole signature chain, and that is not something the agent can tell you — its answer arrives over the socket unattested, so it is worth no more than checking it yourself.

The SDK no longer ships `verifySignature` and `verifySignatureChain`. For a v1 chain, `docs/guest-api-v1.md` is the normative spec: it gives the claim encoding, the recovery steps, and why the KMS root key must come from the `DstackKms` contract (`kmsInfo().k256Pubkey`) or a pinned value rather than from the agent under test.

One thing that spec insists on and that is easy to get wrong: never anchor a chain against `info.app_id` read from the same CVM. That value is reported by the very thing being verified, so a chain checked against it proves only that the CVM is self-consistent with itself. Use the app id you registered on chain.

#### `emitEvent(event, payload)`

Removed in dstack 0.6.0 — runtime RTMR3 events became system-owned, so a 0.6.0 agent fails every call and this surfaces the agent's own message. Bind application data through `report_data` on `attest()` instead.

### Diagnostics

#### `isReachable()`

Sub-500ms probe against `/Info`. Returns a boolean and never throws — useful for liveness checks.

### Blockchain helpers

The chain adapters are v0-era and stay that way: `toViemAccountSecure` and `toKeypairSecure` take a v0 `GetKeyResponse` or `GetTlsKeyResponse`. The v1 surface has no chain-related functionality — it returns key material, and what an application builds from those bytes is its own business.

```typescript
import { toViemAccountSecure } from '@phala/dstack-sdk/viem'

const key = await client.getKey('wallet/ethereum')
const account = toViemAccountSecure(key)
```

```typescript
import { toKeypairSecure } from '@phala/dstack-sdk/solana'

const key = await client.getKey('wallet/solana', 'mainnet', 'ed25519')
const keypair = toKeypairSecure(key)
```

Given a `GetTlsKeyResponse` both helpers hash the PEM key with SHA-256 first, which is what makes them "secure" relative to `toViemAccount` and `toKeypair`; those unhashed variants are kept for migration only and emit a warning.

### Migrating v0 to v1

| v0 | v1 |
| --- | --- |
| `new DstackClientV0()` | `new DstackClient()` |
| `client.getTlsKey({ subject })` | `client.issueCert({ subject })` |
| `client.getKey(path, purpose)` | `client.getKey(domain, algorithm)` — **different key material** |
| `client.getQuote(data)` | `client.attest(bytes)` — **bytes only**, where v0 UTF-8 encoded a string |
| `client.sign(...)` / `client.verify(...)` | sign and verify locally with the key from `getKey` |
| `client.emitEvent(...)` | bind the data through `report_data` on `attest()` |
| `info.tcb_info.*` | `attest()`, which returns measurements quote-backed |
| no equivalent | `client.attestGpu(nonce)`, GPU evidence against a fresh nonce |

Migrate a surface at a time: both clients can talk to the same agent at once, so a v1 `attest()` is safe to adopt while `getKey` still runs on v0. What cannot be mixed is key derivation — see the warning under [Two API surfaces](#two-api-surfaces).

### Migrating from TappdClient

`TappdClient` and its `deriveKey` / `tdxQuote` methods are deprecated but still exported, and still extend `DstackClientV0` — the unsuffixed alias moving to v1 did not change what they inherit or what they send.

| Old | New |
| --- | --- |
| `new TappdClient()` | `new DstackClient()` — or `new DstackClientV0()` to keep the same key material |
| `client.deriveKey(path, subject)` | `client.issueCert({ subject })` |
| `client.tdxQuote(data)` | `client.attest(bytes)` — **bytes only**, where v0 UTF-8 encoded a string |
| `/var/run/tappd.sock` | `/var/run/dstack.sock` |

## License

Apache-2.0
