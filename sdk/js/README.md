# @phala/dstack-sdk

JavaScript / TypeScript client for the dstack guest agent. Derive deterministic keys, generate TDX attestation quotes, issue TLS certificates, sign / verify payloads, and encrypt environment variables for KMS-managed deployments — all against the guest agent socket inside a confidential VM (CVM).

## Installation

```bash
npm install @phala/dstack-sdk @noble/hashes
```

`@noble/hashes` is the only required peer dependency (used by the core for sha256 / sha384). Install the matching peer when you import a submodule:

| Import path | Extra peer dependency |
| --- | --- |
| `@phala/dstack-sdk/viem` | `viem` |
| `@phala/dstack-sdk/solana` | `@solana/web3.js` |
| `@phala/dstack-sdk/encrypt-env-vars` | `@noble/curves` |
| `@phala/dstack-sdk/verify-env-encrypt-public-key` | `@noble/curves` |

> **Breaking change in 0.5.8.** Prior releases listed `@solana/web3.js`, `viem`, and `@noble/curves` under `optionalDependencies`, so npm installed them automatically. They are now opt-in peers — install them yourself when you use the corresponding submodule.

Node 18+ supported. Tested through Node 24.

## Quick start

```typescript
import { DstackClient } from '@phala/dstack-sdk'

const client = new DstackClient()

const key = await client.getKey('wallet/eth')
console.log(Buffer.from(key.key).toString('hex'))

const quote = await client.getQuote('app-state-snapshot')
console.log(quote.quote)
console.log(quote.replayRtmrs())
```

The constructor probes `/var/run/dstack.sock`, then `/run/dstack.sock`, then the `/var/run/dstack/` and `/run/dstack/` variants. Pass an explicit endpoint for HTTP or for a non-default socket:

```typescript
const client = new DstackClient('http://localhost:8090')        // simulator
const client = new DstackClient('/run/dstack/dstack.sock')      // custom path
```

`DSTACK_SIMULATOR_ENDPOINT` overrides the default when set.

## Keys

### `getKey(path?, purpose?, algorithm?)`

Derive a deterministic key. The same `(app_id, path)` returns the same raw key material; different apps deriving on the same path get different keys.

```typescript
const eth = await client.getKey('wallet/ethereum')                       // secp256k1 (default)
const sol = await client.getKey('wallet/solana', 'mainnet', 'ed25519')   // ed25519
```

Returns `{ key: Uint8Array, signature_chain: Uint8Array[] }`. The signature chain proves the key was derived inside a genuine TEE.

`purpose` is included in the signature-chain message and does not affect the private key bytes. `algorithm` selects how the derived 32-byte material is interpreted: `'secp256k1'` (default), `'k256'` (alias), or `'ed25519'`. It does not domain-separate the derivation, so use algorithm-specific paths such as `wallet/ethereum` and `wallet/solana` when those keys must be independent. ed25519 requires guest agent ≥ 0.5.7.

### `getTlsKey(options?)`

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

## Attestation

### `getQuote(reportData)`

Generate a raw TDX quote. `reportData` is up to 64 bytes (string, Buffer, or Uint8Array).

```typescript
const quote = await client.getQuote('user:alice:nonce123')
quote.quote        // hex-encoded TDX quote
quote.event_log    // JSON string of measured events
quote.replayRtmrs() // recompute RTMR[0..3] from the event log
```

### `attest(reportData)`

Versioned dstack attestation that works across TDX / GCP / Nitro providers. Preferred for cross-platform verifiers.

```typescript
const { attestation } = await client.attest('app-state-snapshot')
```

### `info()`

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

### `version()`

Returns `{ version, rev }` of the guest agent. Throws on agents older than 0.5.7 (the RPC didn't exist).

## Sign and verify

### `sign(algorithm, data)`

Sign data with a derived key. The SDK rejects mismatched input early — `secp256k1_prehashed` requires a 32-byte digest.

```typescript
const res = await client.sign('ed25519', 'hello dstack')
res.signature        // Uint8Array
res.public_key       // Uint8Array
res.signature_chain  // Uint8Array[] — proves the signing key came from this TEE
```

Algorithms: `ed25519`, `secp256k1`, `secp256k1_prehashed`. Requires guest agent ≥ 0.5.7.

### `verify(algorithm, data, signature, publicKey)`

```typescript
const ok = await client.verify('ed25519', 'hello dstack', res.signature, res.public_key)
ok.valid // boolean
```

### `emitEvent(event, payload)`

Extends RTMR3 with a custom event. The event becomes part of the next quote's event log and cannot be removed.

```typescript
await client.emitEvent('config_loaded', 'v1.0.0')
```

Requires guest agent ≥ 0.5.0.

## Diagnostics

### `isReachable()`

Sub-500ms probe against `/Info`. Returns a boolean and never throws — useful for liveness checks.

## Blockchain helpers

### Ethereum

```typescript
import { toViemAccountSecure } from '@phala/dstack-sdk/viem'
import { createWalletClient, http } from 'viem'
import { mainnet } from 'viem/chains'

const key = await client.getKey('wallet/ethereum')
const account = toViemAccountSecure(key)

const wallet = createWalletClient({ account, chain: mainnet, transport: http() })
```

`toViemAccountSecure` hashes the derived key with SHA-256 before passing it to viem's `privateKeyToAccount`. The unhashed alternative `toViemAccount` is kept for migration only and emits a warning.

### Solana

```typescript
import { toKeypairSecure } from '@phala/dstack-sdk/solana'

const key = await client.getKey('wallet/solana', 'mainnet', 'ed25519')
const keypair = toKeypairSecure(key)
console.log(keypair.publicKey.toBase58())
```

Same pattern as the Ethereum helper. `toKeypair` is the unhashed legacy variant.

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
| `getKey`, `getTlsKey`, `getQuote`, `info` | 0.3.x |
| `emitEvent` | 0.5.0 |
| `attest`, `sign`, `verify`, `version`, ed25519 keys, `info.cloud_vendor` / `cloud_product`, `getTlsKey` `notBefore` / `notAfter` / `withAppInfo` | 0.5.7 |

The SDK's release versions track guest agent versions — `0.5.8-x` targets dstack 0.5.7+.

## Development

Run the standalone simulator instead of a real TDX host:

```bash
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
```

Then point `new DstackClient()` at the simulator (it picks up `DSTACK_SIMULATOR_ENDPOINT` automatically).

## Migration from TappdClient

`TappdClient` and its `deriveKey` / `tdxQuote` methods are deprecated but still exported. Replace them with `DstackClient` and the new methods:

| Old | New |
| --- | --- |
| `new TappdClient()` | `new DstackClient()` |
| `client.deriveKey(path, subject)` | `client.getTlsKey({ subject })` |
| `client.tdxQuote(data)` | `client.getQuote(data)` |
| `/var/run/tappd.sock` | `/var/run/dstack.sock` |

`toViemAccount` and `toKeypair` are kept for the same reason; prefer their `Secure` variants in new code.

## License

Apache-2.0
