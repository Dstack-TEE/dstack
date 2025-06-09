# Tappd SDK

This SDK provides a JavaScript/TypeScript client for communicating with the Tappd server, which available inside DStack.

## Installation

```bash
npm install @phala/dstack-sdk
```

## Basic Usage

```typescript
import { TappdClient } from '@phala/dstack-sdk';

const client = new TappdClient();

// Causion: You don't need to do this most of the time.
const httpClient = new TappdClient('http://localhost:8000');

// Check if service is reachable (500ms timeout, never throws)
const isReachable = await client.isReachable();
if (!isReachable) {
  console.log('Tappd service is not available');
  return;
}

// Get the information of the Base Image.
await client.info();

// Derive a key with optional path and subject
const keyResult = await client.deriveKey('<unique-id>');
console.log(keyResult.key); // X.509 private key in PEM format
console.log(keyResult.certificate_chain); // Certificate chain
const keyBytes = keyResult.asUint8Array(); // Get key as Uint8Array

// Generate TDX quote
const quoteResult = await client.tdxQuote('some-data', 'sha256');
console.log(quoteResult.quote); // TDX quote in hex format
console.log(quoteResult.event_log); // Event log
const rtmrs = quoteResult.replayRtmrs(); // Replay RTMRs
```

For `tdxQuote`, it supports a range of hash algorithms, including:

- `sha256`: SHA-256 hash algorithm
- `sha384`: SHA-384 hash algorithm 
- `sha512`: SHA-512 hash algorithm
- `sha3-256`: SHA3-256 hash algorithm
- `sha3-384`: SHA3-384 hash algorithm
- `sha3-512`: SHA3-512 hash algorithm
- `keccak256`: Keccak-256 hash algorithm
- `keccak384`: Keccak-384 hash algorithm
- `keccak512`: Keccak-512 hash algorithm
- `raw`: No hashing, use raw data (must be <= 64 bytes)

## Viem Integration

The SDK provides integration with [viem](https://viem.sh/) for Ethereum account management:

### ⚠️ Deprecated API (shows warning)
```typescript
import { toViemAccount } from '@phala/dstack-sdk/viem';

const keyResult = await client.deriveKey('<unique-id>');
const account = toViemAccount(keyResult); // ⚠️ Security concern, shows warning
// Use the account with viem operations
```

### ✅ Recommended Secure API
```typescript
import { toViemAccountSecure } from '@phala/dstack-sdk/viem';

const keyResult = await client.deriveKey('<unique-id>');
const account = toViemAccountSecure(keyResult); // ✅ Secure, no warning
// Use the account with viem operations
```

> **Note**: `toViemAccount` uses first 32 bytes of key material directly (deprecated due to security concerns). `toViemAccountSecure` uses SHA256 hash of complete key material for enhanced security.

## Solana Integration

The SDK provides integration with [Solana Web3.js](https://solana-labs.github.io/solana-web3.js/) for Solana account management:

### ⚠️ Deprecated API (shows warning)
```typescript
import { toKeypair } from '@phala/dstack-sdk/solana';

const keyResult = await client.deriveKey('<unique-id>');
const keypair = toKeypair(keyResult); // ⚠️ Security concern, shows warning
// Use the keypair with Solana Web3.js operations
```

### ✅ Recommended Secure API
```typescript
import { toKeypairSecure } from '@phala/dstack-sdk/solana';

const keyResult = await client.deriveKey('<unique-id>');
const keypair = toKeypairSecure(keyResult); // ✅ Secure, no warning
// Use the keypair with Solana Web3.js operations
```

> **Note**: `toKeypair` uses first 32 bytes of key material directly (deprecated due to security concerns). `toKeypairSecure` uses SHA256 hash of complete key material for enhanced security.

## Environment Variables Encryption

The SDK includes utilities for encrypting environment variables using X25519 key exchange and AES-GCM. This feature is handy for interacting with the bare DStack Teepod API or the Phala Cloud API.

```typescript
import { encryptEnvVars, type EnvVar } from '@phala/dstack-sdk/encrypt-env-vars';

const envVars: EnvVar[] = [
  { key: 'API_KEY', value: 'secret123' },
  { key: 'DATABASE_URL', value: 'postgresql://...' }
];

const publicKeyHex = '0x...'; // You need get that from Teepod API or Phala Cloud API.
const encrypted = await encryptEnvVars(envVars, publicKeyHex);
// encrypted is a hex string containing: ephemeral public key + iv + encrypted data
```

## Migration from Deprecated APIs

We've introduced secure versions of key derivation functions due to security concerns with the original implementations:

| Deprecated (⚠️ Security Warning) | Secure Replacement (✅ Recommended) |
|-----------------------------------|-------------------------------------|
| `toKeypair()` | `toKeypairSecure()` |
| `toViemAccount()` | `toViemAccountSecure()` |

**Key Differences:**
- **Deprecated APIs**: Use first 32 bytes of key material directly
- **Secure APIs**: Apply SHA256 hash to complete key material

> **Warning**: Deprecated APIs will show console warnings but continue to work for backward compatibility. The secure APIs generate different keys from the same input.

## API Reference

### TappdClient

#### Constructor
```typescript
new TappdClient(endpoint?: string)
```
- `endpoint`: Unix socket path or HTTP(S) URL. Defaults to '/var/run/tappd.sock'.
- Uses `DSTACK_SIMULATOR_ENDPOINT` environment variable if set

NOTE: Leave it empty in production. You only need to add `volumes` in your docker-compose file:

```yaml
    volumes:
      - /var/run/tappd.sock:/var/run/tappd.sock
```

For local development without TDX devices, you can use the simulator available for download here:

https://github.com/Leechael/tappd-simulator/releases

#### Methods

##### `deriveKey(path?: string, subject?: string, alt_names?: string[]): Promise<DeriveKeyResponse>`

Derives a key for the given path and subject.

**NOTE: Only the `path` affects the derived result. `subject` & `alt_names` are for the generated certificate and do not affect the derived result.**

- `path`: Optional path for key derivation
- `subject`: Optional subject name (defaults to path)
- `alt_names`: Optional alternative names for the certificate
- Returns: `DeriveKeyResponse` containing key and certificate chain

##### `tdxQuote(report_data: string | Buffer | Uint8Array, hash_algorithm?: TdxQuoteHashAlgorithms): Promise<TdxQuoteResponse>`

Generates a TDX quote. The quote is returned in hex format, and you can paste your quote into https://proof.t16z.com/ to get the attestation report.

- `report_data`: Data to include in the quote
- `hash_algorithm`: Hash algorithm to use (sha256, sha384, sha512, etc.)
- Returns: `TdxQuoteResponse` containing quote and event log

##### `info(): Promise<TappdInfoResponse>`
Retrieves server information.
- Returns: Information about the Tappd instance

##### `isReachable(): Promise<boolean>`
Checks if the Tappd service is reachable and responsive. This method uses a 500ms timeout and never throws errors, making it safe for health checks.

- Returns: `true` if the service is reachable, `false` otherwise
- Timeout: 500ms maximum
- No exceptions: Always returns a boolean result, never throws

```typescript
const client = new TappdClient();

// Safe health check - never throws
const isServiceHealthy = await client.isReachable();
if (isServiceHealthy) {
  console.log('Tappd service is available');
  // Proceed with other operations
} else {
  console.log('Tappd service is not reachable');
  // Handle gracefully
}
```

### Viem Integration Functions

#### `toViemAccount(deriveKeyResponse: DeriveKeyResponse)` ⚠️ **DEPRECATED**
> **Warning**: This function has security concerns. Use `toViemAccountSecure` instead.

Creates a Viem account using first 32 bytes of key material directly.

#### `toViemAccountSecure(deriveKeyResponse: DeriveKeyResponse)` ✅ **RECOMMENDED**
Creates a Viem account using SHA256 hash of complete key material for enhanced security.

### Solana Integration Functions

#### `toKeypair(deriveKeyResponse: DeriveKeyResponse)` ⚠️ **DEPRECATED**
> **Warning**: This function has security concerns. Use `toKeypairSecure` instead.

Creates a Solana Keypair using first 32 bytes of key material directly.

#### `toKeypairSecure(deriveKeyResponse: DeriveKeyResponse)` ✅ **RECOMMENDED**
Creates a Solana Keypair using SHA256 hash of complete key material for enhanced security.

### Types

```typescript
interface DeriveKeyResponse {
  key: string;
  certificate_chain: string[];
  asUint8Array: (max_length?: number) => Uint8Array;
}

type TdxQuoteHashAlgorithms =
  'sha256' | 'sha384' | 'sha512' | 'sha3-256' | 'sha3-384' | 'sha3-512' |
  'keccak256' | 'keccak384' | 'keccak512' | 'raw';

interface TdxQuoteResponse {
  quote: Hex;
  event_log: string;
  replayRtmrs: () => string[];
}

interface EventLog {
  imr: number;
  event_type: number;
  digest: string;
  event: string;
  event_payload: string;
}

interface TcbInfo {
  mrtd: string;
  rootfs_hash: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  event_log: EventLog[];
}

interface TappdInfoResponse {
  app_id: string;
  instance_id: string;
  app_cert: string;
  tcb_info: TcbInfo;
  app_name: string;
  public_logs: boolean;
  public_sysinfo: boolean;
}

interface EnvVar {
  key: string;
  value: string;
}
```

## License

Apache License
