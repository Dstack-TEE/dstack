# dstack SDK for JavaScript/TypeScript

Access TEE features from your JavaScript/TypeScript application running inside dstack. Derive deterministic keys, generate attestation quotes, create TLS certificates, and sign data—all backed by hardware security.

## Installation

```bash
npm install @phala/dstack-sdk
```

## Quick Start

```typescript
import { DstackClient } from '@phala/dstack-sdk';

const client = new DstackClient();

// Derive a deterministic key for your wallet
const key = await client.getKey('wallet/eth');
console.log(key.key);  // Same path always returns the same key

// Generate an attestation quote
const quote = await client.getQuote('my-app-state');
console.log(quote.quote);
```

The client automatically connects to `/var/run/dstack.sock`. For local development with the simulator:

```typescript
const client = new DstackClient('http://localhost:8090');
```

## Core API

### Derive Keys

`getKey()` derives deterministic keys bound to your application's identity (`app_id`). The same path always produces the same key for your app, but different apps get different keys even with the same path.

```typescript
// Derive keys by path
const ethKey = await client.getKey('wallet/ethereum');
const btcKey = await client.getKey('wallet/bitcoin');

// Use path to separate keys
const mainnetKey = await client.getKey('wallet/eth/mainnet');
const testnetKey = await client.getKey('wallet/eth/testnet');
```

**Parameters:**
- `path`: Key derivation path (determines the key)
- `purpose` (optional): Included in signature chain message, does not affect the derived key

**Returns:** `GetKeyResponse`
- `key`: Hex-encoded private key
- `signature_chain`: Signatures proving the key was derived in a genuine TEE

### Generate Attestation Quotes

`getQuote()` creates a TDX quote proving your code runs in a genuine TEE.

```typescript
const quote = await client.getQuote('user:alice:nonce123');

// Replay RTMRs from the event log
const rtmrs = quote.replayRtmrs();
console.log(rtmrs);
```

**Parameters:**
- `reportData`: Exactly 64 bytes recommended. If shorter, pad with zeros. If longer, hash it first (e.g., SHA-256).

**Returns:** `GetQuoteResponse`
- `quote`: Hex-encoded TDX quote
- `event_log`: JSON string of measured events
- `replayRtmrs()`: Method to compute RTMR values from event log

### Get Instance Info

```typescript
const info = await client.info();
console.log(info.app_id);
console.log(info.instance_id);
console.log(info.tcb_info);
```

**Returns:** `InfoResponse`
- `app_id`: Application identifier
- `instance_id`: Instance identifier
- `app_name`: Application name
- `tcb_info`: TCB measurements (MRTD, RTMRs, event log)
- `compose_hash`: Hash of the app configuration
- `app_cert`: Application certificate (PEM)

### Generate TLS Certificates

`getTlsKey()` creates fresh TLS certificates. Unlike `getKey()`, each call generates a new random key.

```typescript
const tls = await client.getTlsKey({
  subject: 'api.example.com',
  altNames: ['localhost'],
  usageRaTls: true  // Embed attestation in certificate
});

console.log(tls.key);                // PEM private key
console.log(tls.certificate_chain);  // Certificate chain
```

**Parameters:**
- `subject` (optional): Certificate common name (e.g., domain name)
- `altNames` (optional): List of subject alternative names
- `usageRaTls` (optional): Embed TDX quote in certificate extension
- `usageServerAuth` (optional): Enable for server authentication (default: `true`)
- `usageClientAuth` (optional): Enable for client authentication (default: `false`)

**Returns:** `GetTlsKeyResponse`
- `key`: PEM-encoded private key
- `certificate_chain`: List of PEM certificates

### Sign and Verify

Sign data using TEE-derived keys (not yet released):

```typescript
const result = await client.sign('ed25519', 'message to sign');
console.log(result.signature);
console.log(result.public_key);

// Verify the signature
const valid = await client.verify('ed25519', 'message to sign', result.signature, result.public_key);
console.log(valid.valid);  // true
```

**`sign()` Parameters:**
- `algorithm`: `'ed25519'`, `'secp256k1'`, or `'secp256k1_prehashed'`
- `data`: Data to sign (string, Buffer, or Uint8Array)

**`sign()` Returns:** `SignResponse`
- `signature`: Hex-encoded signature
- `public_key`: Hex-encoded public key
- `signature_chain`: Signatures proving TEE origin

**`verify()` Parameters:**
- `algorithm`: Algorithm used for signing
- `data`: Original data
- `signature`: Signature to verify
- `public_key`: Public key to verify against

**`verify()` Returns:** `VerifyResponse`
- `valid`: Boolean indicating if signature is valid

### Emit Events

Extend RTMR3 with custom measurements for your application's boot sequence (requires dstack OS 0.5.0+). These measurements are append-only and become part of the attestation record.

```typescript
await client.emitEvent('config_loaded', 'production');
await client.emitEvent('plugin_initialized', 'auth-v2');
```

**Parameters:**
- `event`: Event name (string identifier)
- `payload`: Event value (string, Buffer, or Uint8Array)

## Blockchain Integration

### Ethereum with Viem

```typescript
import { toViemAccount } from '@phala/dstack-sdk/viem';
import { createWalletClient, http } from 'viem';
import { mainnet } from 'viem/chains';

const key = await client.getKey('wallet/ethereum');
const account = toViemAccount(key);

const wallet = createWalletClient({
  account,
  chain: mainnet,
  transport: http()
});
```

### Solana

```typescript
import { toKeypair } from '@phala/dstack-sdk/solana';

const key = await client.getKey('wallet/solana');
const keypair = toKeypair(key);
console.log(keypair.publicKey.toBase58());
```

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

---

## Deployment Utilities

These utilities are for deployment scripts, not runtime SDK operations.

### Encrypt Environment Variables

Encrypt secrets before deploying to dstack:

```typescript
import { encryptEnvVars, verifyEnvEncryptPublicKey, type EnvVar } from '@phala/dstack-sdk';

// Get and verify the KMS public key
// (obtain public_key and signature from KMS API)
const kmsIdentity = verifyEnvEncryptPublicKey(publicKeyBytes, signatureBytes, appId);
if (!kmsIdentity) {
  throw new Error('Invalid KMS key');
}

// Encrypt variables
const envVars: EnvVar[] = [
  { key: 'DATABASE_URL', value: 'postgresql://...' },
  { key: 'API_KEY', value: 'secret' }
];
const encrypted = await encryptEnvVars(envVars, publicKey);
```

### Calculate Compose Hash

```typescript
import { getComposeHash } from '@phala/dstack-sdk';

const hash = getComposeHash(appComposeObject);
```

---

## Migration from TappdClient

Replace `TappdClient` with `DstackClient`:

```typescript
// Before
import { TappdClient } from '@phala/dstack-sdk';
const client = new TappdClient();

// After
import { DstackClient } from '@phala/dstack-sdk';
const client = new DstackClient();
```

Method changes:
- `deriveKey()` → `getTlsKey()` for TLS certificates
- `tdxQuote()` → `getQuote()` (raw data only, no hash algorithms)
- Socket path: `/var/run/tappd.sock` → `/var/run/dstack.sock`

## License

Apache License 2.0
