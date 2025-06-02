# Dstack SDK

This SDK provides a JavaScript/TypeScript client for communicating with the dstack server, which available inside dstack.

## Installation

```bash
npm install @phala/dstack-sdk
```

## Basic Usage

```typescript
import { DstackClient } from '@phala/dstack-sdk';

const client = new DstackClient();

// Causion: You don't need to do this most of the time.
const httpClient = new DstackClient('http://localhost:8000');

// Get the information of the Base Image.
await client.info();

// Derive a key with optional path and subject
const keyResult = await client.getKey('<unique-id>');
console.log(keyResult.key); // X.509 private key in PEM format
console.log(keyResult.signature_chain); // Certificate chain
const keyBytes = keyResult.key; // Get key as Uint8Array

// Generate TDX quote
const quoteResult = await client.getQuote('some-data');
console.log(quoteResult.quote); // TDX quote in hex format
console.log(quoteResult.event_log); // Event log
const rtmrs = quoteResult.replayRtmrs(); // Replay RTMRs
```

## Viem Integration

The SDK provides integration with [viem](https://viem.sh/) for Ethereum account management:

```typescript
import { toViemAccount } from '@phala/dstack-sdk/viem';

const keyResult = await client.getKey('<unique-id>');
const account = toViemAccount(keyResult);
// Use the account with viem operations
```

## Solana Integration

The SDK provides integration with [Solana Web3.js](https://solana-labs.github.io/solana-web3.js/) for Solana account management:

```typescript
import { toKeypair } from '@phala/dstack-sdk/solana';

const keyResult = await client.getKey('<unique-id>');
const keypair = toKeypair(keyResult);
// Use the keypair with Solana Web3.js operations
```

## Environment Variables Encryption

The SDK includes utilities for encrypting environment variables using X25519 key exchange and AES-GCM. This feature is handy for interacting with the bare dstack-vmm API or the Phala Cloud API.

```typescript
import { encryptEnvVars, type EnvVar } from '@phala/dstack-sdk/encrypt-env-vars';

const envVars: EnvVar[] = [
  { key: 'API_KEY', value: 'secret123' },
  { key: 'DATABASE_URL', value: 'postgresql://...' }
];

const publicKeyHex = '0x...'; // You need get that from dstack-vmm API or Phala Cloud API.
const encrypted = await encryptEnvVars(envVars, publicKeyHex);
// encrypted is a hex string containing: ephemeral public key + iv + encrypted data
```

## API Reference

### Running the Simulator

For local development without TDX devices, you can use the simulator under `sdk/simulator`.

Run the simulator with:

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
```

### DstackClient

#### Constructor

```typescript
new DstackClient(endpoint?: string)
```

* `endpoint`: Unix socket path or HTTP(S) URL. Defaults to '/var/run/dstack.sock'.
* Uses `DSTACK_SIMULATOR_ENDPOINT` environment variable if set

NOTE: Leave it empty in production. You only need to add `volumes` in your docker-compose file:

```yaml
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
```

#### Methods

##### `info(): Promise<InfoResponse>`

Retrieves information about the CVM instance.

* Returns: Information about the CVM instance

##### `getKey(path: string, purpose?: string): Promise<GetKeyResponse>`

Derives a key for the given path and purpose.

* `path`: Path for key derivation
* `purpose`: Optional purpose for key derivation
* Returns: `GetKeyResponse` containing key and signature chain

##### `getQuote(reportData: string | Buffer | Uint8Array): Promise<GetQuoteResponse>`

Generates a TDX quote with given report data.

* `reportData`: Data to include in the quote
* Returns: `GetQuoteResponse` containing quote and event log

##### `getTlsKey(options: TlsKeyOptions): Promise<GetTlsKeyResponse>`

Derives a TLS key for the given options.

* `options`: Options for TLS key derivation
  * `subject`: Optional subject name
  * `altNames`: Optional alternative names for the certificate
  * `usageRaTls`: Optional flag to enable RA-TLS usage
  * `usageServerAuth`: Optional flag to enable server authentication
  * `usageClientAuth`: Optional flag to enable client authentication
* Returns: `GetTlsKeyResponse` containing key and certificate chain

## License

Apache License
