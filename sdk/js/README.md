# dstack SDK

The dstack SDK provides a JavaScript/TypeScript client for secure communication with the dstack Trusted Execution Environment (TEE). This SDK enables applications to derive cryptographic keys, generate remote attestation quotes, and perform other security-critical operations within confidential computing environments.

## Installation

```bash
npm install @phala/dstack-sdk
```

## Overview

The dstack SDK enables secure communication with dstack Trusted Execution Environment (TEE) instances. dstack applications are defined using `app-compose.json` (based on the `AppCompose` structure) and deployed as containerized applications using Docker Compose.

### Application Architecture

dstack applications consist of:
- **App Configuration**: `app-compose.json` defining app metadata, security settings, and Docker Compose content
- **Container Deployment**: Docker Compose configuration embedded within the app definition
- **TEE Integration**: Access to TEE functionality via Unix socket (`/var/run/dstack.sock`)

### SDK Capabilities

- **Key Derivation**: Deterministic secp256k1 key generation for blockchain and Web3 applications
- **Remote Attestation**: TDX quote generation providing cryptographic proof of execution environment
- **TLS Certificate Management**: Fresh certificate generation with optional RA-TLS support for secure connections
- **Deployment Security**: Client-side encryption of sensitive environment variables ensuring secrets are only accessible to target TEE applications
- **Blockchain Integration**: Ready-to-use adapters for Ethereum (Viem) and Solana ecosystems

### Socket Connection Requirements

To use the SDK, your Docker Compose configuration must bind-mount the dstack socket:

```yaml
# docker-compose.yml
services:
  your-app:
    image: your-app-image
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock  # dstack OS 0.5.x
      # For dstack OS 0.3.x compatibility (deprecated):
      # - /var/run/tappd.sock:/var/run/tappd.sock
```

## Basic Usage

### Application Setup

First, ensure your dstack application is properly configured:

**1. App Configuration (`app-compose.json`)**
```json
{
  "manifest_version": 1,
  "name": "my-secure-app",  
  "runner": "docker-compose",
  "docker_compose_file": "services:\n  app:\n    build: .\n    volumes:\n      - /var/run/dstack.sock:/var/run/dstack.sock\n    environment:\n      - NODE_ENV=production",
  "public_tcbinfo": true,
  "kms_enabled": false,
  "gateway_enabled": false
}
```

**Note**: The `docker_compose_file` field contains the actual Docker Compose YAML content as a string, not a file path.

### SDK Integration

```typescript
import { DstackClient } from '@phala/dstack-sdk';

// Create client - automatically connects to /var/run/dstack.sock
const client = new DstackClient();

// For local development with simulator
const devClient = new DstackClient('http://localhost:8090');

// Get TEE instance information
const info = await client.info();
console.log('App ID:', info.app_id);
console.log('Instance ID:', info.instance_id);
console.log('App Name:', info.app_name);
console.log('TCB Info:', info.tcb_info);

// Derive deterministic keys for blockchain applications
const walletKey = await client.getKey('wallet/ethereum', 'mainnet');
console.log('Derived key (32 bytes):', walletKey.key);        // secp256k1 private key
console.log('Signature chain:', walletKey.signature_chain);   // Authenticity proof

// Generate remote attestation quote
const applicationData = JSON.stringify({
  version: '1.0.0',
  timestamp: Date.now(),
  user_id: 'alice'
});

const quote = await client.getQuote(applicationData);
console.log('TDX Quote:', quote.quote);
console.log('Event Log:', quote.event_log);

// Verify measurement registers
const rtmrs = quote.replayRtmrs();
console.log('RTMR0-3:', rtmrs);
```

### Version Compatibility

- **dstack OS 0.5.x**: Use `/var/run/dstack.sock` (current)
- **dstack OS 0.3.x**: Use `/var/run/tappd.sock` (deprecated but supported)

The SDK automatically detects the correct socket path, but you must ensure the appropriate volume binding in your Docker Compose configuration.

## Advanced Features

### TLS Certificate Generation

Generate fresh TLS certificates with optional Remote Attestation support. **Important**: `getTlsKey()` generates random keys on each call - it's designed specifically for TLS/SSL scenarios where fresh keys are required.

```typescript
// Generate TLS certificate with different usage scenarios
const tlsKey = await client.getTlsKey({
  subject: 'my-secure-service',              // Certificate common name
  altNames: ['localhost', '127.0.0.1'],      // Additional valid domains/IPs
  usageRaTls: true,                          // Include remote attestation
  usageServerAuth: true,                     // Enable server authentication (default)
  usageClientAuth: false                     // Disable client authentication
});

console.log('Private Key (PEM):', tlsKey.key);
console.log('Certificate Chain:', tlsKey.certificate_chain);

// ⚠️ WARNING: Each call generates a different key
const tlsKey1 = await client.getTlsKey();
const tlsKey2 = await client.getTlsKey();
// tlsKey1.key !== tlsKey2.key (always different!)
```

### Event Logging

Extend RTMR3 with custom events for audit trails:

```typescript
// Emit custom events (requires dstack OS 0.5.0+)
await client.emitEvent('user-action', JSON.stringify({
  action: 'transfer',
  amount: 1000,
  timestamp: Date.now()
}));

// Events are automatically included in subsequent quotes
const quote = await client.getQuote('audit-data');
const events = JSON.parse(quote.event_log);
```

## Blockchain Integration

### Ethereum with Viem

```typescript
import { toViemAccount, toViemAccountSecure } from '@phala/dstack-sdk/viem';
import { createWalletClient, http } from 'viem';
import { mainnet } from 'viem/chains';

const keyResult = await client.getKey('ethereum/main', 'wallet');

// Standard account creation
const account = toViemAccount(keyResult);

// Enhanced security with SHA256 hashing (recommended)
const secureAccount = toViemAccountSecure(keyResult);

const wallet = createWalletClient({
  account: secureAccount,
  chain: mainnet,
  transport: http()
});

// Use wallet for transactions
const hash = await wallet.sendTransaction({
  to: '0x...',
  value: parseEther('0.1')
});
```

### Solana

```typescript
import { toKeypair, toKeypairSecure } from '@phala/dstack-sdk/solana';
import { Connection, PublicKey, Transaction, SystemProgram } from '@solana/web3.js';

const keyResult = await client.getKey('solana/main', 'wallet');

// Standard keypair creation
const keypair = toKeypair(keyResult);

// Enhanced security with SHA256 hashing (recommended)
const secureKeypair = toKeypairSecure(keyResult);

const connection = new Connection('https://api.mainnet-beta.solana.com');

// Create and send transaction
const transaction = new Transaction().add(
  SystemProgram.transfer({
    fromPubkey: secureKeypair.publicKey,
    toPubkey: new PublicKey('...'),
    lamports: 1000000
  })
);

const signature = await connection.sendTransaction(transaction, [secureKeypair]);
```

## Environment Variables Encryption

**Important**: This feature is specifically for **deployment-time security**, not runtime SDK operations.

The SDK provides end-to-end encryption capabilities for securely transmitting sensitive environment variables during dstack application deployment. When deploying applications to TEE instances, sensitive configuration data (API keys, database credentials, private keys, etc.) needs to be securely transmitted from the deployment client to the TEE application.

### Deployment Security Problem

During application deployment, sensitive data must traverse:
1. **Client Environment** → Deployment infrastructure → **TEE Application**
2. **Risk**: Deployment infrastructure could potentially access plaintext secrets
3. **Solution**: Client-side encryption ensures only the target TEE application can decrypt secrets

### How It Works

1. **Pre-Deployment**: Client obtains encryption public key from KMS API
2. **Encryption**: Client encrypts environment variables using X25519 + AES-GCM
3. **Transmission**: Encrypted payload is sent through deployment infrastructure  
4. **Decryption**: TEE application automatically decrypts and loads environment variables
5. **Runtime**: Application accesses secrets via standard `process.env`

This ensures **true end-to-end encryption** where deployment infrastructure never sees plaintext secrets.

### App Configuration for Encrypted Variables

Your `app-compose.json` should specify which environment variables are allowed:

```json
{
  "manifest_version": 1,
  "name": "secure-app",
  "runner": "docker-compose", 
  "docker_compose_file": "services:\n  app:\n    build: .\n    volumes:\n      - /var/run/dstack.sock:/var/run/dstack.sock\n    environment:\n      - API_KEY\n      - DATABASE_URL\n      - PRIVATE_KEY",
  "allowed_envs": ["API_KEY", "DATABASE_URL", "PRIVATE_KEY"],
  "kms_enabled": true
}
```

### Deployment Encryption Workflow

```typescript
import { encryptEnvVars, verifyEnvEncryptPublicKey, type EnvVar } from '@phala/dstack-sdk';

// 1. Define sensitive environment variables
const envVars: EnvVar[] = [
  { key: 'DATABASE_URL', value: 'postgresql://user:pass@host:5432/db' },
  { key: 'API_SECRET_KEY', value: 'your-secret-key' },
  { key: 'JWT_PRIVATE_KEY', value: '-----BEGIN PRIVATE KEY-----\n...' },
  { key: 'WALLET_MNEMONIC', value: 'abandon abandon abandon...' }
];

// 2. Obtain encryption public key from KMS API (dstack-vmm or Phala Cloud)
const response = await fetch('/prpc/GetAppEnvEncryptPubKey?json', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ app_id: 'your-app-id-hex' })
});
const { public_key, signature } = await response.json();

// 3. Verify KMS API authenticity to prevent man-in-the-middle attacks
const publicKeyBytes = new Uint8Array(Buffer.from(public_key, 'hex'));
const signatureBytes = new Uint8Array(Buffer.from(signature, 'hex'));

const trustedPubkey = verifyEnvEncryptPublicKey(publicKeyBytes, signatureBytes, 'your-app-id-hex');
if (!trustedPubkey) {
  throw new Error('KMS API provided untrusted encryption key');
}

console.log('Verified KMS public key:', trustedPubkey);

// 4. Encrypt environment variables for secure deployment
const encryptedData = await encryptEnvVars(envVars, public_key);
console.log('Encrypted payload:', encryptedData);

// 5. Deploy with encrypted configuration
await deployDstackApp({
  app_id: 'your-app-id-hex',
  encrypted_env: encryptedData,
  // ... other deployment parameters
});
```

### Security Guarantees

The environment encryption system provides several security guarantees:

**End-to-End Encryption**: Environment variables are encrypted on the client side and can only be decrypted by the target dstack application inside the TEE. Even the deployment infrastructure cannot access the plaintext values.

**KMS Authenticity Verification**: The `verifyEnvEncryptPublicKey` function validates that the encryption public key comes from a trusted KMS (Key Management Service), preventing man-in-the-middle attacks during key exchange.

**Forward Secrecy**: Each encryption operation uses ephemeral X25519 keypairs, ensuring that compromising long-term keys cannot decrypt past communications.

**Authenticated Encryption**: AES-256-GCM provides both confidentiality and integrity protection, detecting any tampering with encrypted data.

### Encryption Protocol Details

The encryption process follows this cryptographic protocol:

1. **Key Exchange**: Generate ephemeral X25519 keypair and perform ECDH with KMS public key
2. **Shared Secret**: Derive AES-256 key from ECDH shared secret
3. **Authenticated Encryption**: Encrypt JSON payload using AES-256-GCM with random IV
4. **Payload Format**: `ephemeral_pubkey(32) + iv(12) + encrypted_data + auth_tag(16)`

```typescript
// Detailed encryption example
const envVars = [{ key: 'SECRET', value: 'sensitive-data' }];
const kmsPublicKey = '0xa1b2c3d4...'; // From trusted KMS API

const encrypted = await encryptEnvVars(envVars, kmsPublicKey);
// encrypted = "a1b2c3..." (hex string)

// Inside dstack application, the encrypted data is automatically decrypted
// and made available as environment variables:
console.log(process.env.SECRET); // "sensitive-data"
```

### KMS Public Key Verification

The verification function ensures the encryption public key comes from a legitimate KMS:

```typescript
import { verifyEnvEncryptPublicKey } from '@phala/dstack-sdk';

/**
 * Verify KMS-provided encryption public key authenticity
 * 
 * @param publicKey - X25519 public key bytes (32 bytes)
 * @param signature - secp256k1 signature from KMS (65 bytes)
 * @param appId - Target application ID (hex string)
 * @returns Compressed secp256k1 public key of KMS if valid, null if invalid
 */
const kmsIdentity = verifyEnvEncryptPublicKey(publicKeyBytes, signatureBytes, appId);

if (kmsIdentity) {
  console.log('Trusted KMS identity:', kmsIdentity);
  // Proceed with encryption using the verified public key
} else {
  throw new Error('KMS signature verification failed - potential MITM attack');
}
```

### Message Format for Verification

The KMS signature covers the following message structure:
```
message = "dstack-env-encrypt-pubkey" + ":" + app_id + public_key
signature = secp256k1.sign(keccak256(message), kms_private_key)
```

This binds the encryption key to a specific application ID and prevents key substitution attacks.

## Cryptographic Security

### Key Derivation Security

The SDK implements secure key derivation using:

- **Deterministic Generation**: Keys are derived using HMAC-based Key Derivation Function (HKDF)
- **Application Isolation**: Each path produces unique keys, preventing cross-application access
- **Signature Verification**: All derived keys include cryptographic proof of origin
- **TEE Protection**: Master keys never leave the secure enclave

```typescript
// Each path generates a unique, deterministic key
const wallet1 = await client.getKey('app1/wallet', 'ethereum');
const wallet2 = await client.getKey('app2/wallet', 'ethereum');
// wallet1.key !== wallet2.key (guaranteed different)

const sameWallet = await client.getKey('app1/wallet', 'ethereum');
// wallet1.key === sameWallet.key (guaranteed identical)
```

### Remote Attestation

TDX quotes provide cryptographic proof of:

- **Code Integrity**: Measurement of loaded application code
- **Data Integrity**: Inclusion of application-specific data in quote
- **Environment Authenticity**: Verification of TEE platform and configuration

```typescript
const applicationState = JSON.stringify({
  version: '1.0.0',
  config_hash: 'sha256:...',
  timestamp: Date.now()
});

const quote = await client.getQuote(applicationState);

// Quote can be verified by external parties to confirm:
// 1. Application is running in genuine TEE
// 2. Application code matches expected measurements
// 3. Application state is authentic and unmodified
```

### Environment Encryption Protocol

The encryption scheme uses:

- **X25519 ECDH**: Elliptic curve key exchange for forward secrecy
- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **Ephemeral Keys**: New keypair generated for each encryption operation
- **Authenticated Data**: Prevents tampering and ensures integrity

## Development and Testing

### Local Development

For development without physical TDX hardware:

```bash
# Clone and build simulator
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack/sdk/simulator
./build.sh
./dstack-simulator

# Set environment variable
export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
```

### Testing Connectivity

```typescript
const client = new DstackClient();

// Check if dstack service is available
const isAvailable = await client.isReachable();
if (!isAvailable) {
  console.error('dstack service is not reachable');
  process.exit(1);
}
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

##### `getTlsKey(options?: TlsKeyOptions): Promise<GetTlsKeyResponse>`

Generates a fresh, random TLS key pair with X.509 certificate for TLS/SSL connections. **Important**: This method generates different keys on each call - use `getKey()` for deterministic keys.

**Parameters:** `TlsKeyOptions`
- `path` (optional): Path parameter (unused in current implementation)
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

const appCompose = {
  manifest_version: 1,
  name: 'my-app',
  runner: 'docker-compose',
  docker_compose_file: 'docker-compose.yml'
};

const hash = getComposeHash(appCompose);
console.log('Configuration hash:', hash);
```

### KMS Public Key Verification

Verify the authenticity of encryption public keys provided by KMS APIs:

```typescript
import { verifyEnvEncryptPublicKey } from '@phala/dstack-sdk';

// Example: Verify KMS-provided encryption key
const publicKey = Buffer.from('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a', 'hex');
const signature = Buffer.from('8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00', 'hex');
const appId = '0000000000000000000000000000000000000000';

const kmsIdentity = verifyEnvEncryptPublicKey(
  new Uint8Array(publicKey),
  new Uint8Array(signature),
  appId
);

if (kmsIdentity) {
  console.log('Trusted KMS identity:', kmsIdentity);
  // Safe to use the public key for encryption
} else {
  console.error('KMS signature verification failed');
  // Potential man-in-the-middle attack
}
```

## Security Best Practices

1. **Key Management**
   - Use descriptive, unique paths for key derivation
   - Never expose derived keys outside the TEE
   - Implement proper access controls in your application

2. **Remote Attestation**
   - Always verify quotes before trusting remote TEE instances
   - Include application-specific data in quote generation
   - Validate RTMR measurements against expected values

3. **TLS Configuration**
   - Enable RA-TLS for attestation-based authentication
   - Use appropriate certificate validity periods
   - Implement proper certificate validation

4. **Error Handling**
   - Handle cryptographic operation failures gracefully
   - Log security events for monitoring
   - Implement fallback mechanisms where appropriate

## Migration Guide

### Critical API Changes: Understanding the Separation

The legacy `deriveKey()` method mixed two different use cases that have now been properly separated:

1. **`getKey()`**: Deterministic key derivation for Web3/blockchain (secp256k1)
2. **`getTlsKey()`**: Random TLS certificate generation for HTTPS/SSL

### Method Comparison Table

| Feature | `getKey()` | `getTlsKey()` |
|---------|------------|---------------|
| **Purpose** | Web3/Blockchain keys | TLS/SSL certificates |
| **Key Generation** | Deterministic (same input = same key) | Random (different every call) |
| **Key Format** | Raw 32-byte secp256k1 private key | PEM-formatted X.509 private key |
| **Use Cases** | Wallets, signing, DeFi, NFT | HTTPS servers, mTLS, secure APIs |
| **Curve/Algorithm** | secp256k1 (K256) | Various (RSA, ECDSA, etc.) |
| **Returns** | `{ key: Uint8Array, signature_chain }` | `{ key: string (PEM), certificate_chain }` |
| **Reproducible** | ✅ Yes (same path = same key) | ❌ No (random each time) |
| **Blockchain Ready** | ✅ Yes (Ethereum, Bitcoin, Solana) | ❌ No (TLS-specific format) |
| **Certificate** | ❌ No certificate | ✅ Yes (X.509 certificate chain) |
| **RA-TLS Support** | ❌ No | ✅ Yes (optional) |

### When to Use Which Method

**Use `getKey()` when you need:**
- Cryptocurrency wallets
- Transaction signing  
- Consistent keys across app restarts
- Web3 integrations (Ethereum, Solana, etc.)
- Any deterministic cryptographic operations

**Use `getTlsKey()` when you need:**
- HTTPS server certificates
- Client authentication certificates
- Fresh keys for each connection
- Standard TLS/SSL setups
- Remote attestation via RA-TLS

### From TappdClient to DstackClient

**⚠️ BREAKING CHANGE**: `TappdClient` is deprecated and will be removed. All users must migrate to `DstackClient`.

### Complete Migration Reference

| Component | TappdClient (Old) | DstackClient (New) | Status |
|-----------|-------------------|-------------------|---------|
| **Daemon Process** | `tappd` | `dstack-guest-agent` | ✅ Updated |
| **Socket Path** | `/var/run/tappd.sock` | `/var/run/dstack.sock` | ✅ Updated |
| **HTTP URL Format** | `http://localhost/prpc/Tappd.<Method>` | `http://localhost/<Method>` | ✅ Simplified |
| **K256 Key Method** | `DeriveK256Key(...)` | `GetKey(...)` | ✅ Renamed |
| **TLS Certificate Method** | `DeriveKey(...)` | `GetTlsKey(...)` | ✅ Separated |
| **TDX Quote (Hash)** | `TdxQuote(...)` | ❌ **Removed** | ⚠️ No longer supported |
| **TDX Quote (Raw)** | `RawQuote(...)` | `GetQuote(report_data)` | ✅ Renamed |

#### For Web3/Blockchain Applications (Most Common Use Case)

```typescript
// ❌ OLD - TappdClient.deriveKey() (DEPRECATED)
import { TappdClient } from '@phala/dstack-sdk';
const client = new TappdClient();
const result = await client.deriveKey('wallet/ethereum', 'mainnet');
// This actually returned deterministic keys (confusing!)

// ✅ NEW - DstackClient.getKey() (RECOMMENDED)
import { DstackClient } from '@phala/dstack-sdk';
const client = new DstackClient();
const result = await client.getKey('wallet/ethereum', 'mainnet');
// Clear intent: deterministic key for blockchain usage
```

#### For TLS/SSL Certificate Generation

```typescript
// ❌ OLD - TappdClient.deriveKey() with TLS options (CONFUSING)
import { TappdClient } from '@phala/dstack-sdk';
const client = new TappdClient();
const result = await client.deriveKey('server', 'api.example.com', ['localhost']);
// Mixed deterministic keys with TLS concepts

// ✅ NEW - DstackClient.getTlsKey() (CLEAR PURPOSE)
import { DstackClient } from '@phala/dstack-sdk';
const client = new DstackClient();
const result = await client.getTlsKey({
  subject: 'api.example.com',
  altNames: ['localhost']
});
// Clear intent: random TLS certificate generation
```

### Migration Steps

#### Step 1: Update Imports and Client

```typescript
// Before
import { TappdClient } from '@phala/dstack-sdk';
const client = new TappdClient();

// After  
import { DstackClient } from '@phala/dstack-sdk';
const client = new DstackClient();
```

#### Step 2: Choose the Right Method

**For Web3/Blockchain (95% of use cases):**
```typescript
// Before: deriveKey() for wallet/signing
const walletKey = await client.deriveKey('wallet', 'ethereum');

// After: getKey() for deterministic keys
const walletKey = await client.getKey('wallet', 'ethereum');
```

**For TLS/SSL Certificates:**
```typescript
// Before: deriveKey() with subject/altNames
const tlsCert = await client.deriveKey('api', 'example.com', ['localhost']);

// After: getTlsKey() with proper options
const tlsCert = await client.getTlsKey({
  subject: 'example.com',
  altNames: ['localhost']
});
```

#### Step 3: Update Blockchain Integrations

```typescript
// Viem (Ethereum)
import { toViemAccountSecure } from '@phala/dstack-sdk/viem';

// Before
const keyResult = await tappdClient.deriveKey('wallet');
const account = toViemAccount(keyResult);  // Basic security

// After  
const keyResult = await dstackClient.getKey('wallet', 'ethereum');
const account = toViemAccountSecure(keyResult);  // Enhanced security

// Solana
import { toKeypairSecure } from '@phala/dstack-sdk/solana';

// Before
const keyResult = await tappdClient.deriveKey('wallet');
const keypair = toKeypair(keyResult);  // Basic security

// After
const keyResult = await dstackClient.getKey('wallet', 'solana');
const keypair = toKeypairSecure(keyResult);  // Enhanced security
```

### Why This Migration is Important

1. **API Clarity**: Separate methods for separate purposes eliminates confusion
2. **Critical Security Fixes**: Legacy integration functions have security vulnerabilities
3. **Feature Deprecation**: Hash-based TDX quotes are no longer supported
4. **Future Compatibility**: `TappdClient` will be removed in future versions
5. **Better Type Safety**: Clearer interfaces and return types

### Critical Security Issues

**⚠️ SECURITY VULNERABILITY**: Legacy blockchain integration functions have security flaws:

- **`toViemAccount()`**: Uses raw key material without proper hashing - **VULNERABLE**
- **`toKeypair()`**: Uses raw key material without proper hashing - **VULNERABLE**

**✅ SECURE ALTERNATIVES**: Always use the secure versions:
- **`toViemAccountSecure()`**: Applies SHA256 hashing for enhanced security
- **`toKeypairSecure()`**: Applies SHA256 hashing for enhanced security

### Compatibility Notes

- **`TappdClient`** remains functional for now but shows deprecation warnings
- **`DstackClient.deriveKey()`** throws an error - forcing migration to correct methods
- **Legacy integration functions** work but have security vulnerabilities - **MUST MIGRATE**

### Infrastructure Changes

**Docker Volume Binding:**
```yaml
# Old (dstack OS 0.3.x)
volumes:
  - /var/run/tappd.sock:/var/run/tappd.sock

# New (dstack OS 0.5.x)  
volumes:
  - /var/run/dstack.sock:/var/run/dstack.sock
```

**Environment Variables:**
```bash
# Old
TAPPD_SIMULATOR_ENDPOINT=http://localhost:8090

# New
DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
```

### API Method Changes

**⚠️ MAJOR BREAKING CHANGE - TDX Quote Methods:**

```typescript
// ❌ OLD - TappdClient with hash algorithms (REMOVED)
const client = new TappdClient();
await client.tdxQuote('user-data', 'sha256');    // Hash applied automatically
await client.tdxQuote('user-data', 'keccak256'); // Multiple algorithms supported
await client.tdxQuote('user-data', 'raw');       // Raw mode

// ✅ NEW - DstackClient raw data only (BREAKING CHANGE)
const client = new DstackClient();
await client.getQuote('user-data');  // Raw data only, max 64 bytes
```

**Critical Changes:**
1. **No Hash Algorithms**: `getQuote()` only accepts raw data, no automatic hashing
2. **Size Limit Change**: Report data must be ≤ 64 bytes (was flexible with hashing)
3. **Manual Hashing**: If you need hashing, do it manually before calling `getQuote()`

**Migration Example:**
```typescript
// Old approach with automatic hashing
const result = await tappdClient.tdxQuote('my-application-data', 'sha256'); 

// New approach - manual hashing if needed
import { createHash } from 'crypto';
const hash = createHash('sha256').update('my-application-data').digest();
const result = await dstackClient.getQuote(hash); // hash is 32 bytes
```

**Key Derivation Methods:**
```typescript
// Old internal method names (handled automatically by SDK)
// DeriveK256Key -> GetKey
// DeriveKey -> GetTlsKey  
// RawQuote -> GetQuote
```

### Migration Checklist

- [ ] **Infrastructure Updates:**
  - [ ] Update Docker volume binding to `/var/run/dstack.sock`
  - [ ] Change environment variables from `TAPPD_*` to `DSTACK_*`
  - [ ] Verify `dstack-guest-agent` is running (not `tappd`)

- [ ] **Client Code Updates:**
  - [ ] Replace `TappdClient` with `DstackClient`
  - [ ] Replace `deriveKey()` calls with appropriate method:
    - [ ] `getKey()` for Web3/blockchain keys (deterministic)
    - [ ] `getTlsKey()` for TLS certificates (random)
  - [ ] **CRITICAL**: Migrate TDX quote methods:
    - [ ] Replace all `tdxQuote()` calls with `getQuote()`
    - [ ] Remove hash algorithm parameters (`'sha256'`, `'keccak256'`, etc.)
    - [ ] Add manual hashing if needed (data must be ≤ 64 bytes)
    - [ ] Test with smaller data or pre-hash large data
  - [ ] **SECURITY CRITICAL**: Update blockchain integration functions:
    - [ ] Replace `toViemAccount()` with `toViemAccountSecure()` (Ethereum)
    - [ ] Replace `toKeypair()` with `toKeypairSecure()` (Solana)
    - [ ] **DO NOT** use legacy functions - they have security vulnerabilities

- [ ] **Testing:**
  - [ ] Test that deterministic keys still work as expected
  - [ ] Verify TLS certificate generation works
  - [ ] **CRITICAL**: Test quote generation changes:
    - [ ] Verify raw data fits in 64 bytes
    - [ ] Test manual hashing if using large data
    - [ ] Confirm quotes work without algorithm parameters
  - [ ] **SECURITY**: Validate blockchain integrations:
    - [ ] Test Ethereum with `toViemAccountSecure()` only
    - [ ] Test Solana with `toKeypairSecure()` only
    - [ ] Verify legacy functions are completely removed from codebase

## License

Apache License 2.0
