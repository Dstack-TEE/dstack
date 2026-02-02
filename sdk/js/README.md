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
import { encryptEnvVars, verifyEnvEncryptPublicKey, verifyEnvEncryptPublicKeyLegacy, type EnvVar } from '@phala/dstack-sdk';

// Get and verify the KMS public key
// (obtain public_key, signature_v1, and timestamp from KMS API)

// Prefer signature_v1 with timestamp (prevents replay attacks)
const kmsIdentity = verifyEnvEncryptPublicKey(publicKeyBytes, signatureV1Bytes, appId, timestamp);
if (!kmsIdentity) {
  // Fall back to legacy signature for backward compatibility with older KMS
  const legacyIdentity = verifyEnvEncryptPublicKeyLegacy(publicKeyBytes, signatureBytes, appId);
  if (!legacyIdentity) {
    throw new Error('Invalid KMS key');
  }
  console.warn('Using legacy signature without timestamp protection');
}

// Encrypt variables
const envVars: EnvVar[] = [
  { key: 'DATABASE_URL', value: 'postgresql://...' },
  { key: 'API_KEY', value: 'secret' }
];
const encrypted = await encryptEnvVars(envVars, publicKey);
```

## API Reference

### DstackClient

#### Constructor

```typescript
new DstackClient(endpoint?: string)
```

**Parameters:**
- `endpoint` (optional): Connection endpoint
  - Unix socket path (production): `/var/run/dstack.sock`
  - HTTP/HTTPS URL (development): `http://localhost:8090`
  - Environment variable: `DSTACK_SIMULATOR_ENDPOINT`

**Production App Configuration:**

The Docker Compose configuration is embedded in `app-compose.json`:

```json
{
  "manifest_version": 1,
  "name": "production-app",
  "runner": "docker-compose",
  "docker_compose_file": "services:\n  app:\n    image: your-app\n    volumes:\n      - /var/run/dstack.sock:/var/run/dstack.sock\n    environment:\n      - NODE_ENV=production",
  "public_tcbinfo": true
}
```

**Important**: The `docker_compose_file` contains YAML content as a string, ensuring the volume binding for `/var/run/dstack.sock` is included.

#### Methods

##### `info(): Promise<InfoResponse>`

Retrieves comprehensive information about the TEE instance.

**Returns:** `InfoResponse`
- `app_id`: Unique application identifier
- `instance_id`: Unique instance identifier
- `app_name`: Application name from configuration
- `device_id`: TEE device identifier
- `tcb_info`: Trusted Computing Base information
  - `mrtd`: Measurement of TEE domain
  - `rtmr0-3`: Runtime Measurement Registers
  - `event_log`: Boot and runtime events
  - `os_image_hash`: Operating system measurement
  - `compose_hash`: Application configuration hash
- `app_cert`: Application certificate in PEM format
- `key_provider_info`: Key management configuration

##### `getKey(path: string, purpose?: string): Promise<GetKeyResponse>`

Derives a deterministic secp256k1/K256 private key for blockchain and Web3 applications. This is the primary method for obtaining cryptographic keys for wallets, signing, and other deterministic key scenarios.

**Parameters:**
- `path`: Unique identifier for key derivation (e.g., `"wallet/ethereum"`, `"signing/solana"`)
- `purpose` (optional): Additional context for key usage (default: `""`)

**Returns:** `GetKeyResponse`
- `key`: 32-byte secp256k1 private key as `Uint8Array` (suitable for Ethereum, Bitcoin, Solana, etc.)
- `signature_chain`: Array of cryptographic signatures proving key authenticity

**Key Characteristics:**
- **Deterministic**: Same path + purpose always generates identical key
- **Isolated**: Different paths produce cryptographically independent keys
- **Blockchain-Ready**: Compatible with secp256k1 curve (Ethereum, Bitcoin, Solana)
- **Verifiable**: Signature chain proves key was derived inside genuine TEE

**Use Cases:**
- Cryptocurrency wallets
- Transaction signing
- DeFi protocol interactions
- NFT operations
- Any scenario requiring consistent, reproducible keys

```typescript
// Examples of deterministic key derivation
const ethWallet = await client.getKey('wallet/ethereum', 'mainnet');
const btcWallet = await client.getKey('wallet/bitcoin', 'mainnet');
const solWallet = await client.getKey('wallet/solana', 'mainnet');

// Same path always returns same key
const key1 = await client.getKey('my-app/signing');
const key2 = await client.getKey('my-app/signing');
// key1.key === key2.key (guaranteed identical)

// Different paths return different keys
const userA = await client.getKey('user/alice/wallet');
const userB = await client.getKey('user/bob/wallet');
// userA.key !== userB.key (guaranteed different)
```

##### `getQuote(reportData: string | Buffer | Uint8Array): Promise<GetQuoteResponse>`

Generates a TDX attestation quote containing the provided report data.

**Parameters:**
- `reportData`: Data to include in quote (max 64 bytes)

**Returns:** `GetQuoteResponse`
- `quote`: TDX quote as hex string
- `event_log`: JSON string of system events
- `replayRtmrs()`: Function returning computed RTMR values

**Use Cases:**
- Remote attestation of application state
- Cryptographic proof of execution environment
- Audit trail generation

##### `attest(reportData: string | Buffer | Uint8Array): Promise<AttestResponse>`

Generates a versioned attestation containing the provided report data.

**Parameters:**
- `reportData`: Data to include in attestation (max 64 bytes)

**Returns:** `AttestResponse`
- `attestation`: Hex-encoded attestation payload

**Use Cases:**
- Remote attestation across multiple platform types
- Verifier APIs that accept versioned attestations

##### `getTlsKey(options?: TlsKeyOptions): Promise<GetTlsKeyResponse>`

Generates a fresh, random TLS key pair with X.509 certificate for TLS/SSL connections. **Important**: This method generates different keys on each call - use `getKey()` for deterministic keys.

**Parameters:** `TlsKeyOptions`
- `subject` (optional): Certificate subject (Common Name) - typically the domain name (default: `""`)
- `altNames` (optional): Subject Alternative Names - additional domains/IPs for the certificate (default: `[]`)
- `usageRaTls` (optional): Include TDX attestation quote in certificate extension for remote verification (default: `false`)
- `usageServerAuth` (optional): Enable server authentication - allows certificate to authenticate servers (default: `true`)
- `usageClientAuth` (optional): Enable client authentication - allows certificate to authenticate clients (default: `false`)

**Returns:** `GetTlsKeyResponse`
- `key`: Private key in PEM format (X.509/PKCS#8)
- `certificate_chain`: Certificate chain array

**Key Characteristics:**
- **Random Generation**: Each call produces a completely different key
- **TLS-Optimized**: Keys and certificates designed for TLS/SSL scenarios
- **RA-TLS Support**: Optional remote attestation extension in certificates
- **TEE-Signed**: Certificates signed by TEE-resident Certificate Authority

**Certificate Usage Scenarios:**

1. **Standard HTTPS Server** (`usageServerAuth: true`, `usageClientAuth: false`)
   - Web servers, API endpoints
   - Server authenticates to clients
   - Most common TLS use case

2. **Remote Attestation Server** (`usageRaTls: true`)
   - TEE-based services requiring proof of execution environment
   - Clients can verify the server runs in genuine TEE
   - Combines TLS with hardware attestation

3. **mTLS Client Certificate** (`usageServerAuth: false`, `usageClientAuth: true`)
   - Client authentication in mutual TLS
   - API clients, service-to-service communication
   - Client proves identity to server

4. **Dual-Purpose Certificate** (`usageServerAuth: true`, `usageClientAuth: true`)
   - Services that act as both client and server
   - Microservices architectures
   - Maximum flexibility for TLS roles

```typescript
// Example 1: Standard HTTPS server certificate
const serverCert = await client.getTlsKey({
  subject: 'api.example.com',
  altNames: ['api.example.com', 'www.api.example.com', '10.0.0.1']
  // usageServerAuth: true (default) - allows server authentication
  // usageClientAuth: false (default) - no client authentication
});

// Example 2: Certificate with remote attestation (RA-TLS)
const attestedCert = await client.getTlsKey({
  subject: 'secure-api.example.com',
  usageRaTls: true        // Include TDX quote for remote verification
  // Clients can verify the TEE environment through the certificate
});

// Example 3: Mutual TLS (mTLS) certificate for client authentication
const clientCert = await client.getTlsKey({
  subject: 'client.example.com',
  usageServerAuth: false, // This certificate won't authenticate servers
  usageClientAuth: true   // Enable client authentication
});

// Example 4: Certificate for both server and client authentication
const dualUseCert = await client.getTlsKey({
  subject: 'dual.example.com',
  usageServerAuth: true,  // Can authenticate as server
  usageClientAuth: true   // Can authenticate as client
});

// ⚠️ Each call generates different keys (unlike getKey)
const cert1 = await client.getTlsKey();
const cert2 = await client.getTlsKey();
// cert1.key !== cert2.key (always different)

// Use with Node.js HTTPS server
import https from 'https';
const server = https.createServer({
  key: serverCert.key,
  cert: serverCert.certificate_chain.join('\n')
}, app);
```

##### `emitEvent(event: string, payload: string | Buffer | Uint8Array): Promise<void>`

Extends RTMR3 with a custom event for audit logging.

**Parameters:**
- `event`: Event identifier string
- `payload`: Event data

**Requirements:**
- dstack OS version 0.5.0 or later
- Events are permanently recorded in TEE measurements

##### `isReachable(): Promise<boolean>`

Tests connectivity to the dstack service.

**Returns:** `boolean` indicating service availability

## Utility Functions

### Compose Hash Calculation

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
