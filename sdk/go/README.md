# dstack SDK for Go

The dstack SDK provides a Go client for secure communication with the dstack Trusted Execution Environment (TEE). This SDK enables applications to derive cryptographic keys, generate remote attestation quotes, and perform other security-critical operations within confidential computing environments.

## Installation

```bash
go get github.com/Dstack-TEE/dstack/sdk/go
```

## Overview

The dstack SDK enables secure communication with dstack Trusted Execution Environment (TEE) instances. dstack applications are defined using `app-compose.json` (based on the `AppCompose` structure) and deployed as containerized applications using Docker Compose.

### Application Architecture

dstack applications consist of:
- **App Configuration**: `app-compose.json` defining app metadata, security settings, and Docker Compose content
- **Container Deployment**: Docker Compose configuration embedded within the app definition
- **TEE Integration**: Access to TEE functionality via Unix socket (`/var/run/dstack.sock`)

### SDK Capabilities

- **Key Derivation**: Deterministic key derivation for wallets, signing, encryption, and other application-specific secrets
- **Remote Attestation**: TDX quote generation providing cryptographic proof of execution environment
- **TLS Certificate Management**: Fresh certificate generation with optional RA-TLS support for secure connections
- **Deployment Security**: Client-side encryption of sensitive environment variables ensuring secrets are only accessible to target TEE applications
- **Blockchain Integration**: Ready-to-use adapters for Ethereum and Solana ecosystems

### Two API versions

dstack 0.6.0 splits the guest agent API into two surfaces on the same socket,
selected by URL path. The SDK mirrors both, and it is a transport mirror only:
it does not translate between them.

| Client | Paths | Status |
|---|---|---|
| `DstackClientV1` | `/v1/<Method>` | Current. Six methods: `IssueCert`, `GetKey`, `Attest`, `AttestGpu`, `Info`, `Version` |
| `DstackClientV0` | `/GetKey`, equivalently `/v0/GetKey` | Frozen at v0.5.11. Served unchanged for pre-0.6 clients, never extended |

```go
v1 := dstack.NewDstackClientV1() // current API
v0 := dstack.NewDstackClientV0() // frozen v0.5.11 API
```

`NewDstackClient` and `DstackClient` remain as deprecated aliases for the v0
client, so code written against the pre-0.6 SDK keeps compiling and keeps
talking to the same frozen surface.

What v1 changes:

- `GetTlsKey` is now `IssueCert` — certificate issuance is the operation; the key was only ever a by-product.
- `path` plus `purpose` collapse into a single `domain`, and `algorithm` is required, with no `k256` alias and no default.
- `Attest` subsumes `GetQuote`; `Info` is flat, with no `tcb_info` blob and no `app_cert`.
- `Sign`, `Verify` and `EmitEvent` are gone. Sign and verify locally with a standard library, using the key `GetKey` returns; `EmitEvent` is gone because runtime RTMR3 events became system-owned.

> **⚠️ v1 derives different key material than v0.** `v1.GetKey(ctx, "wallet", "secp256k1")`
> and `v0.GetKey(ctx, "wallet", "", "secp256k1")` return **unrelated** keys. v1 derives
> under its own HKDF salt and binds the algorithm and a versioned context tag alongside
> the domain, so secp256k1 and ed25519 no longer share one 32-byte secret either. There is
> no compatibility mode and no way to reach a v0 key through v1. An application holding
> funds or data under a v0 key must migrate them deliberately: derive the v1 key, then
> move the assets. See `docs/guest-api-v1.md` for the byte-level construction.

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

```go
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

func main() {
	// Create client - automatically connects to /var/run/dstack.sock
	client := dstack.NewDstackClientV1()

	// For local development with simulator
	// devClient := dstack.NewDstackClientV1(dstack.WithEndpoint("http://localhost:8090"))

	ctx := context.Background()

	// Get TEE instance information
	info, err := client.Info(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("App ID: %x\n", info.AppID)
	fmt.Printf("Instance ID: %x\n", info.InstanceID)
	fmt.Println("App Name:", info.AppName)
	fmt.Println("App Compose:", info.AppCompose)

	// Derive deterministic keys for application-specific secrets
	walletKey, err := client.GetKey(ctx, "wallet/ethereum", "secp256k1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Derived key (32 bytes):", hex.EncodeToString(walletKey.Key)) // secp256k1 private key
	fmt.Println("Public key:", hex.EncodeToString(walletKey.PublicKey))
	fmt.Println("Signature chain links:", len(walletKey.SignatureChain)) // Authenticity proof

	// Generate a remote attestation, bound to your own data
	applicationData := map[string]interface{}{
		"version":   "1.0.0",
		"timestamp": time.Now().Unix(),
		"user_id":   "alice",
	}

	jsonData, _ := json.Marshal(applicationData)
	digest := sha256.Sum256(jsonData) // report data is at most 64 bytes
	attestation, err := client.Attest(ctx, digest[:], false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Attestation:", hex.EncodeToString(attestation.Attestation))
}
```

The frozen surface is the same code with `NewDstackClientV0` and the v0.5.11
method signatures:

```go
v0 := dstack.NewDstackClientV0()

info, _ := v0.Info(ctx)                                   // AppID and friends are hex strings
key, _ := v0.GetKey(ctx, "wallet/ethereum", "mainnet", "secp256k1")
quote, _ := v0.GetQuote(ctx, reportData)                   // Intel TDX only
tlsKey, _ := v0.GetTlsKey(ctx, dstack.WithSubject("api.example.com"))
```

### Version Compatibility

- **dstack OS 0.5.x**: Use `/var/run/dstack.sock` (current)
- **dstack OS 0.3.x**: Use `/var/run/tappd.sock` (deprecated but supported)

The SDK automatically detects the correct socket path, but you must ensure the appropriate volume binding in your Docker Compose configuration.

## Advanced Features

### TLS Certificate Generation

Generate fresh TLS certificates with optional Remote Attestation support. **Important**: `GetTlsKey()` generates random keys on each call - it's designed specifically for TLS/SSL scenarios where fresh keys are required.

```go
// Generate TLS certificate with different usage scenarios
tlsKey, err := client.GetTlsKey(ctx, dstack.TlsKeyOptions{
	Subject:         "my-secure-service",              // Certificate common name
	AltNames:        []string{"localhost", "127.0.0.1"}, // Additional valid domains/IPs
	UsageRaTls:      true,                            // Include remote attestation
	UsageServerAuth: true,                            // Enable server authentication (default)
	UsageClientAuth: false,                           // Disable client authentication
})
if err != nil {
	log.Fatal(err)
}

fmt.Println("Private Key (PEM):", tlsKey.Key)
fmt.Println("Certificate Chain:", tlsKey.CertificateChain)

// ⚠️ WARNING: Each call generates a different key
tlsKey1, _ := client.GetTlsKey(ctx, dstack.TlsKeyOptions{})
tlsKey2, _ := client.GetTlsKey(ctx, dstack.TlsKeyOptions{})
// tlsKey1.Key != tlsKey2.Key (always different!)
```

## Optional blockchain helpers (build tags)

By default, the Go SDK builds a **core profile** (attestation, key derivation, info, signing, env encryption).

Optional helpers are split by tags:

- `ethereum` tag:
  - `ToEthereumAccount()`
  - `ToEthereumAccountSecure()`
- `solana` tag:
  - `ToSolanaKeypair()`
  - `ToSolanaKeypairSecure()`

### Enable Ethereum helpers

```bash
# add optional dependency
go get github.com/ethereum/go-ethereum@v1.16.8

# build/test with ethereum helpers enabled
go build -tags ethereum ./...
go test -tags ethereum ./...
```

### Enable Solana helpers

```bash
# no extra dependency is required for solana helper APIs
go build -tags solana ./...
go test -tags solana ./...
```

### Enable both

```bash
go get github.com/ethereum/go-ethereum@v1.16.8
go build -tags "ethereum solana" ./...
go test -tags "ethereum solana" ./...
```

If you don't need blockchain helper APIs, do not use these tags and you won't pull optional helper imports.

### Testing against a local starter app

You can validate SDK changes immediately from another Go project by using `replace`:

```go
require github.com/Dstack-TEE/dstack/sdk/go v0.0.0
replace github.com/Dstack-TEE/dstack/sdk/go => ../dstack/sdk/go
```

Then run your starter normally:

```bash
go mod tidy
go run .
```

If your starter enables optional blockchain routes, run with matching tags:

```bash
# ethereum only
go get github.com/ethereum/go-ethereum@v1.16.8
go run -tags ethereum .

# solana only
go run -tags solana .

# both
go run -tags "ethereum solana" .
```

## Blockchain Integration

### Ethereum

> requires build tag: `ethereum`

```go
import (
	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

keyResult, err := client.GetKey(ctx, "ethereum/main", "wallet", "secp256k1")
if err != nil {
	log.Fatal(err)
}

// Standard account creation
account, err := dstack.ToEthereumAccount(keyResult)
if err != nil {
	log.Fatal(err)
}

// Enhanced security with SHA256 hashing (recommended)
secureAccount, err := dstack.ToEthereumAccountSecure(keyResult)
if err != nil {
	log.Fatal(err)
}

fmt.Println("Ethereum Address:", secureAccount.Address.Hex())

// Connect to Ethereum network
ethClient, err := ethclient.Dial("https://mainnet.infura.io/v3/YOUR-PROJECT-ID")
if err != nil {
	log.Fatal(err)
}

// Use account for transactions...
```

### Solana

> requires build tag: `solana`

```go
import (
	"encoding/hex"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

keyResult, err := client.GetKey(ctx, "solana/main", "wallet", "ed25519")
if err != nil {
	log.Fatal(err)
}

secureKeypair, err := dstack.ToSolanaKeypairSecure(keyResult)
if err != nil {
	log.Fatal(err)
}

fmt.Println("Solana Public Key:", hex.EncodeToString(secureKeypair.PublicKey))

// Sign messages
message := []byte("Hello Solana")
signature := secureKeypair.Sign(message)
fmt.Println("Signature:", hex.EncodeToString(signature))

// Verify signature
isValid := secureKeypair.Verify(message, signature)
fmt.Println("Valid signature:", isValid)
```

## Environment Variables Encryption

**Important**: This feature is specifically for **deployment-time security**, not runtime SDK operations.

The SDK provides end-to-end encryption capabilities for securely transmitting sensitive environment variables during dstack application deployment.

### Deployment Encryption Workflow

```go
import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

// 1. Define sensitive environment variables
envVars := []dstack.EnvVar{
	{Key: "DATABASE_URL", Value: "postgresql://user:pass@host:5432/db"},
	{Key: "API_SECRET_KEY", Value: "your-secret-key"},
	{Key: "JWT_PRIVATE_KEY", Value: "-----BEGIN PRIVATE KEY-----\n..."},
	{Key: "WALLET_MNEMONIC", Value: "abandon abandon abandon..."},
}

// 2. Obtain encryption public key from KMS API (dstack-vmm or Phala Cloud).
// HTTP request implementation depends on your HTTP client.
kmsResponse := struct {
	PublicKey   string `json:"public_key"`
	SignatureV1 string `json:"signature_v1"`
	Timestamp   uint64 `json:"timestamp"`
}{
	// Fill these fields from /prpc/GetAppEnvEncryptPubKey?json.
}

// 3. Verify KMS API authenticity to prevent man-in-the-middle attacks
publicKeyBytes, _ := hex.DecodeString(kmsResponse.PublicKey)
signatureBytes, _ := hex.DecodeString(kmsResponse.SignatureV1)

// Prefer timestamped verification to prevent replay attacks.
kmsIdentity, err := dstack.VerifyEnvEncryptPublicKeyWithTimestamp(
	publicKeyBytes,
	signatureBytes,
	"your-app-id-hex",
	kmsResponse.Timestamp,
	nil, // use default freshness policy (max age 300s)
)
if err != nil || kmsIdentity == nil {
	log.Fatal("kms API provided untrusted encryption key")
}

expectedKMSIdentity := "0x03..." // From the DstackKms contract or deployment config
actualKMSIdentity := string(kmsIdentity)
if actualKMSIdentity != expectedKMSIdentity {
	log.Fatalf("unexpected KMS identity: got %s", actualKMSIdentity)
}

fmt.Println("Verified KMS identity:", actualKMSIdentity)

// VerifyEnvEncryptPublicKey() is available only for explicit compatibility with
// older KMS builds. It does not provide timestamp replay protection.

// 4. Encrypt environment variables for secure deployment
encryptedData, err := dstack.EncryptEnvVars(envVars, kmsResponse.PublicKey)
if err != nil {
	log.Fatal(err)
}
fmt.Println("Encrypted payload:", encryptedData)

// 5. Deploy with encrypted configuration
// deployDstackApp(..., encryptedData)
```

## Cryptographic Security

### Key Derivation Security

The SDK implements secure key derivation using:

- **Deterministic Generation**: Keys are derived using HMAC-based Key Derivation Function (HKDF)
- **Application Isolation**: Different `app_id` values derive different keys even with the same path
- **Signature Verification**: All derived keys include cryptographic proof of origin
- **TEE Protection**: Master keys never leave the secure enclave

```go
// Each path generates a unique, deterministic key
wallet1, _ := client.GetKey(ctx, "app1/wallet", "ethereum", "secp256k1")
wallet2, _ := client.GetKey(ctx, "app2/wallet", "ethereum", "secp256k1")
// wallet1.Key != wallet2.Key (guaranteed different)

sameWallet, _ := client.GetKey(ctx, "app1/wallet", "ethereum", "secp256k1")
// wallet1.Key == sameWallet.Key (guaranteed identical)
```

The examples above use the v0 client, where `algorithm` selects how one 32-byte
secret is interpreted rather than participating in the derivation. v1 binds
`algorithm` and a versioned context tag into the KDF, so the two curves never
share a secret — and, for the same reason, a v1 key is never a v0 key.

### Remote Attestation

TDX quotes provide cryptographic proof of:

- **Code Integrity**: Measurement of loaded application code
- **Data Integrity**: Inclusion of application-specific data in quote
- **Environment Authenticity**: Verification of TEE platform and configuration

```go
applicationState := map[string]interface{}{
	"version":     "1.0.0",
	"config_hash": "sha256:...",
	"timestamp":   time.Now().Unix(),
}

stateData, _ := json.Marshal(applicationState)
quote, err := client.GetQuote(ctx, stateData)
if err != nil {
	log.Fatal(err)
}

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

```go
client := dstack.NewDstackClientV0()

// Check if dstack service is available
isAvailable := client.IsReachable(context.Background())
if !isAvailable {
	log.Fatal("dstack service is not reachable")
}
```

The client automatically connects to `/var/run/dstack.sock`. For local development with the simulator:

```go
client := dstack.NewDstackClientV1(dstack.WithEndpoint("http://localhost:8090"))
```

**Options:** the same set applies to `NewDstackClientV0` and `NewDstackClientV1`.
- `WithEndpoint(endpoint string)`: Connection endpoint
  - Unix socket path (production): `/var/run/dstack.sock`
  - HTTP/HTTPS URL (development): `http://localhost:8090`
  - Environment variable: `DSTACK_SIMULATOR_ENDPOINT`
- `WithLogger(logger *slog.Logger)`: Custom logger (default: `slog.Default()`)

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

### `DstackClientV0`

The frozen v0.5.11 surface. Present so pre-0.6 applications keep working; new
code should use [`DstackClientV1`](#dstackclientv1).

#### Methods

##### `Info(ctx context.Context) (*InfoResponse, error)`

Retrieves comprehensive information about the TEE instance.

**Returns:** `InfoResponse`
- `AppID`: Unique application identifier
- `InstanceID`: Unique instance identifier  
- `AppName`: Application name from configuration
- `DeviceID`: TEE device identifier
- `TcbInfo`: Trusted Computing Base information
  - `Mrtd`: Measurement of TEE domain
  - `Rtmr0-3`: Runtime Measurement Registers
  - `EventLog`: Boot and runtime events
- `AppCert`: Application certificate in PEM format

##### `GetKey(ctx context.Context, path string, purpose string, algorithm string) (*GetKeyResponse, error)`

Derives deterministic private key material for wallets, signing, encryption, stable service identities, and other application-specific secrets.

**Parameters:**
- `path`: Unique identifier for key derivation (e.g., `"wallet/ethereum"`, `"signing/solana"`)
- `purpose`: Included in the signature-chain message; does not affect the private key bytes
- `algorithm`: `"secp256k1"` (default behavior), `"k256"` (alias), or `"ed25519"`

**Returns:** `GetKeyResponse`
- `Key`: 32-byte private key material as a hex string
- `SignatureChain`: Array of cryptographic signatures proving key authenticity

**Key Characteristics:**
- **Deterministic**: Same path always generates identical raw key material for the same app
- **Isolated**: Different paths produce cryptographically independent keys  
- **Blockchain-Ready**: Use `secp256k1` for Ethereum and Bitcoin-style signing; use `ed25519` with a Solana-specific path for independent Solana keys
- **Verifiable**: Signature chain proves key was derived inside genuine TEE

For compatibility, `algorithm` selects how the same derived 32-byte material is interpreted; it does not domain-separate the derivation. Use algorithm-specific paths when independent keys are required.

**Use Cases:**
- Stable service identity keys
- Application signing keys
- Encryption key seeds
- Cryptocurrency wallets and transaction signing
- Any scenario requiring consistent, reproducible keys

```go
// Examples of deterministic key derivation
ethWallet, _ := client.GetKey(ctx, "wallet/ethereum", "mainnet", "secp256k1")
btcWallet, _ := client.GetKey(ctx, "wallet/bitcoin", "mainnet", "secp256k1")
solWallet, _ := client.GetKey(ctx, "wallet/solana", "mainnet", "ed25519")

// Same path always returns same key
key1, _ := client.GetKey(ctx, "my-app/signing", "", "secp256k1")
key2, _ := client.GetKey(ctx, "my-app/signing", "", "secp256k1")
// key1.Key == key2.Key (guaranteed identical)

// Different paths return different keys
userA, _ := client.GetKey(ctx, "user/alice/wallet", "", "secp256k1")
userB, _ := client.GetKey(ctx, "user/bob/wallet", "", "secp256k1")  
// userA.Key != userB.Key (guaranteed different)
```

##### `GetQuote(ctx context.Context, reportData []byte) (*GetQuoteResponse, error)`

Generates a TDX attestation quote containing the provided report data. Intel TDX
only; on any other platform it returns an error and you should call `Attest()`
instead.

**Parameters:**
- `reportData`: Data to include in quote (max 64 bytes)

**Returns:** `GetQuoteResponse`
- `Quote`: TDX quote as hex string
- `EventLog`: JSON string of system events

**Use Cases:**
- Remote attestation of application state
- Cryptographic proof of execution environment
- Audit trail generation

##### `Attest(ctx context.Context, reportData []byte) (*AttestResponse, error)`

Produces a versioned dstack attestation over `reportData` (at most 64 bytes),
covering every supported platform rather than Intel TDX alone.

**Returns:** `AttestResponse`
- `Attestation`: the versioned attestation bytes

There is no GPU option on this surface. GPU attestation is v1 only — see
`DstackClientV1.Attest` and `DstackClientV1.AttestGpu`.

##### `Sign(ctx context.Context, algorithm string, data []byte) (*SignResponse, error)`

Signs a payload with the app signing key. `algorithm` is `ed25519`, `secp256k1`,
or `secp256k1_prehashed` (where `data` is already a 32-byte digest).

##### `Verify(ctx context.Context, algorithm string, data, signature, publicKey []byte) (*VerifyResponse, error)`

Asks the agent to check a signature. Frozen surface only: v1 has no `Verify`,
because verification needs no key material and no attestation, so the agent's
answer arrives unattested and is no better than checking the signature yourself.
See `docs/guest-api-v1.md` for how to verify a v1 chain.

##### `EmitEvent(ctx context.Context, event string, payload []byte) error`

**Removed server-side in dstack 0.6.0.** Runtime RTMR3 events became
system-owned, so an agent from 0.6.0 on answers this with an error, which the
client returns rather than swallowing — an application that believes it measured
something it did not is worse off than one that fails loudly. The method remains
so that pre-0.6 code still compiles. Bind application data through `reportData`
on `Attest` instead.

##### `GetTlsKey(ctx context.Context, options TlsKeyOptions) (*GetTlsKeyResponse, error)`

Generates a fresh, random TLS key pair with X.509 certificate for TLS/SSL connections. **Important**: This method generates different keys on each call - use `GetKey()` for deterministic keys.

**Parameters:** `TlsKeyOptions`
- `Subject`: Certificate subject (Common Name) - typically the domain name (default: `""`)
- `AltNames`: Subject Alternative Names - additional domains/IPs for the certificate (default: `[]`)
- `UsageRaTls`: Include TDX attestation quote in certificate extension for remote verification (default: `false`)
- `UsageServerAuth`: Enable server authentication - allows certificate to authenticate servers (default: `true`)
- `UsageClientAuth`: Enable client authentication - allows certificate to authenticate clients (default: `false`)

**Returns:** `GetTlsKeyResponse`
- `Key`: Private key in PEM format (X.509/PKCS#8)
- `CertificateChain`: Certificate chain array

**Key Characteristics:**
- **Random Generation**: Each call produces a completely different key
- **TLS-Optimized**: Keys and certificates designed for TLS/SSL scenarios
- **RA-TLS Support**: Optional remote attestation extension in certificates
- **TEE-Signed**: Certificates signed by TEE-resident Certificate Authority

```go
// Example 1: Standard HTTPS server certificate
serverCert, _ := client.GetTlsKey(ctx, dstack.TlsKeyOptions{
	Subject:  "api.example.com",
	AltNames: []string{"api.example.com", "www.api.example.com", "10.0.0.1"},
	// UsageServerAuth: true (default) - allows server authentication
	// UsageClientAuth: false (default) - no client authentication
})

// Example 2: Certificate with remote attestation (RA-TLS)
attestedCert, _ := client.GetTlsKey(ctx, dstack.TlsKeyOptions{
	Subject:    "secure-api.example.com",
	UsageRaTls: true, // Include TDX quote for remote verification
	// Clients can verify the TEE environment through the certificate
})

// ⚠️ Each call generates different keys (unlike GetKey)
cert1, _ := client.GetTlsKey(ctx, dstack.TlsKeyOptions{})
cert2, _ := client.GetTlsKey(ctx, dstack.TlsKeyOptions{})
// cert1.Key != cert2.Key (always different)
```

##### `IsReachable(ctx context.Context) bool`

Tests connectivity to the dstack service.

**Returns:** `bool` indicating service availability

### `DstackClientV1`

The current API. Constructed the same way as the v0 client, with the same
options and the same endpoint resolution — the two surfaces share one socket and
differ only in the URL path.

```go
client := dstack.NewDstackClientV1()
```

Protobuf `bytes` fields travel as lowercase hex on the wire and are exposed as
`[]byte`; the fields carrying JSON documents (`AppCompose`, `VmConfig`,
`KeyProviderInfo`) stay `string`.

##### `IssueCert(ctx context.Context, options ...IssueCertV1Option) (*IssueCertV1Response, error)`

Issues a certificate for this application. Options are `WithCertSubject`,
`WithCertAltNames`, `WithCertUsageRaTls`, `WithCertUsageServerAuth`,
`WithCertUsageClientAuth`, `WithCertAppInfo`, `WithCertNotBefore`,
`WithCertNotAfter`.

**Returns:** `Key` (PEM) and `CertificateChain` (PEM, leaf first).

The key is freshly generated on every call and is **not** derived from the app
identity — that is what `GetKey` is for. v0 called this `GetTlsKey`.

##### `GetKey(ctx context.Context, domain string, algorithm string) (*GetKeyV1Response, error)`

Derives an application key from `(domain, algorithm)`.

- `domain`: any byte string, including one containing `:`, `/` or NUL. Derivation
  is **flat**: `a/b` is not a child of `a`, and two domains yield unrelated keys.
- `algorithm`: `secp256k1` or `ed25519`. **Required** — there is no default and
  no `k256` alias, so a typo is an error rather than a key of the wrong type
  under a name you thought meant something else. An empty value is rejected
  client-side.

**Returns:** `Key` (32 bytes), `PublicKey` (33 bytes SEC1-compressed for
secp256k1, 32 raw bytes for ed25519), and a two-element `SignatureChain`.

```go
key, err := client.GetKey(ctx, "wallet/ethereum", "secp256k1")
```

##### `Attest(ctx context.Context, reportData []byte, includeBoottimeGpuEvidence bool) (*AttestV1Response, error)`

Produces a versioned attestation over `reportData` (1–64 bytes, zero-padded on
the right to 64). The sole CVM attestation entry point in v1: the attestation
already carries the TDX quote and the event log, so there is no `GetQuote`.

Setting `includeBoottimeGpuEvidence` also returns `BoottimeGpuEvidence`, the GPU
evidence `nvattest` recorded at boot, as `[]GpuEvidenceBundle` — the same type
`AttestGpu` returns, so one parser serves both methods. Absence is the empty
slice, not a sentinel: it stays empty unless you asked for it *and* the guest has
boot-time output.

It is **not** bound to `reportData`: bind a bundle by replaying the runtime event
log and comparing sha256 of its `Evidence` against the `evidence_sha256` field of
the measured `gpu-attestation` event. `Evidence` holds the exact bytes `nvattest`
wrote, byte for byte, and that exactness is what makes the comparison work —
re-serializing the JSON changes the digest.

```go
att, err := client.Attest(ctx, reportData, true)
for _, bundle := range att.BoottimeGpuEvidence {
    // bundle.Format == "nvidia-nvattest-boottime-json-v1"
    digest := sha256.Sum256(bundle.Evidence)
    // compare digest against the `gpu-attestation` event's evidence_sha256
}
```

##### `AttestGpu(ctx context.Context, nonce []byte) (*AttestGpuV1Response, error)`

Collects GPU evidence now, against a nonce you choose. The nonce must be
**exactly 32 bytes** (checked client-side): SPDM fixes the evidence nonce at that
length and dstack passes it through verbatim, so you can compare it directly
against the `eat_nonce` claim rather than reversing a hash.

**Returns:** `Bundles`, each a `GpuEvidenceBundle` with `Vendor`, `Format` and
opaque `Evidence` bytes — the same type `Attest` returns in
`BoottimeGpuEvidence`. `Format` is what separates them: these carry
`nvidia-nvattest-collect-evidence-json-v1`, the boot-time record carries
`nvidia-nvattest-boottime-json-v1`, and a verifier for one does not appraise the
other.

This is evidence, not a verdict — select a verifier by vendor and format, then
check the signature, certificate chain, measurements and embedded nonce. It
still does not bind the GPU to this CVM.

##### `Info(ctx context.Context) (*InfoV1Response, error)`

Identity and configuration, in a flat shape: `AppID`, `AppName`, `ComposeHash`,
`AppCompose`, `InstanceID`, `DeviceID`, `OsImageHash`, `MrAggregated`,
`VmConfig`, `KeyProviderInfo`, `CloudVendor`, `CloudProduct`.

No `TcbInfo` and no `AppCert`. The measurement registers and the event log live
on the attestation `Attest` returns, which is the only place they are
quote-backed. Nothing here is evidence — it arrives over a local socket with no
quote behind it, so confirm the hashes against an attestation before relying on
them.

`ComposeHash` is sha256 over the exact `AppCompose` bytes. Do not parse and
re-serialize before hashing: key order, whitespace and unknown fields all change
the digest, and that digest is what gets whitelisted on chain.

##### `Version(ctx context.Context) (*VersionV1Response, error)`

Returns the agent `Version` and `Rev`. The cheapest probe for whether an agent
speaks v1 at all: an agent that predates v1 has no `/v1` mount and answers with
a plain HTTP 404.

## Utility Functions

### Compose Hash Calculation

```go
import "github.com/Dstack-TEE/dstack/sdk/go/dstack"

appCompose := dstack.AppCompose{
	ManifestVersion:   &[]int{1}[0],
	Name:             "my-app",
	Runner:           "docker-compose",
	DockerComposeFile: "docker-compose.yml",
}

hash, err := dstack.GetComposeHash(appCompose)
if err != nil {
	log.Fatal(err)
}
fmt.Println("Configuration hash:", hash)
```

### Signature Verification

The SDK no longer ships local signature or signature-chain helpers, and v1 has
no `Verify` RPC. Verification needs no key material and no attestation, so the
guest agent is not the right place for it: its answer arrives over the socket
unattested, which is no better than checking the signature yourself. Sign and
verify locally with a standard Go crypto library, using the key `GetKey` returns.

**`docs/guest-api-v1.md` is the normative specification for verifying a v1
chain.** It pins the bytes: the length-prefixed claim encoding, the KDF, and the
step-by-step procedure a relying party follows. In outline, `GetKey` returns two
links —

```text
[0]  app root key  signs  keccak256(LP("dstack-guest-v1-key-claim") || LP(algorithm) || LP(domain) || LP(public_key))
[1]  KMS root key  signs  keccak256("dstack-kms-issued" || ":" || app_id || app_root_pubkey)
```

— and the step that carries the security of all the others is the anchor: obtain
the KMS root public key from a source you trust independently of the agent being
checked, either the `DstackKms` contract's `kmsInfo().k256Pubkey` or a value
pinned out of band. An attacker who can answer your query for the anchor can also
mint a self-consistent chain, so reading it from the KMS you are checking proves
nothing. The same goes for `app_id`: use the one you registered on chain, not the
one `Info()` echoed back from the CVM you are verifying.

The frozen v0 surface still serves `Verify` for pre-0.6 clients, via
`DstackClientV0.Verify`. It reports the agent's verdict, not an attested one.

### KMS Public Key Verification

Verify the authenticity of encryption public keys provided by KMS APIs:

```go
import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

// Example: Verify a KMS response from /prpc/GetAppEnvEncryptPubKey?json
kmsResponse := struct {
	PublicKey   string `json:"public_key"`
	SignatureV1 string `json:"signature_v1"`
	Timestamp   uint64 `json:"timestamp"`
}{
	// Fill these fields from the KMS API response.
}
publicKey, _ := hex.DecodeString(kmsResponse.PublicKey)
signature, _ := hex.DecodeString(kmsResponse.SignatureV1)
appID := "0000000000000000000000000000000000000000"

kmsIdentity, err := dstack.VerifyEnvEncryptPublicKeyWithTimestamp(publicKey, signature, appID, kmsResponse.Timestamp, nil)

if err != nil || kmsIdentity == nil {
	log.Fatal("kms signature verification failed")
}

expectedKMSIdentity := "0x03..." // From the DstackKms contract or deployment config
actualKMSIdentity := string(kmsIdentity)
if actualKMSIdentity != expectedKMSIdentity {
	log.Fatalf("unexpected KMS identity: got %s", actualKMSIdentity)
}

fmt.Println("Trusted KMS identity:", actualKMSIdentity)
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
   - Fail closed on security-critical cryptographic errors
   - Log security events for monitoring
   - Avoid fallback behavior that weakens verification or key isolation

## Migration Guide

### Critical API Changes: Understanding the Separation

The legacy client mixed two different use cases that have now been properly separated:

1. **`GetKey()`**: Deterministic key derivation for application-specific secrets
2. **`GetTlsKey()`**: Random TLS certificate generation for HTTPS/SSL

### From TappdClient to DstackClient

**⚠️ BREAKING CHANGE**: `TappdClient` is deprecated and will be removed. All users must migrate to `DstackClient`.

### Complete Migration Reference

| Component | TappdClient (Old) | DstackClient (New) | Status |
|-----------|-------------------|-------------------|--------|
| **Socket Path** | `/var/run/tappd.sock` | `/var/run/dstack.sock` | ✅ Updated |
| **HTTP URL Format** | `http://localhost/prpc/Tappd.<Method>` | `http://localhost/<Method>` | ✅ Simplified |
| **K256 Key Method** | `DeriveKey(...)` | `GetKey(...)` | ✅ Renamed |
| **TLS Certificate Method** | `DeriveKey(...)` | `GetTlsKey(...)` | ✅ Separated |
| **TDX Quote** | `TdxQuote(...)` | `GetQuote(report_data)` | ✅ Renamed |

#### Migration Steps

**Step 1: Update Imports and Client**

```go
// Before
import "github.com/Dstack-TEE/dstack/sdk/go/tappd"
client := tappd.NewTappdClient()

// After  
import "github.com/Dstack-TEE/dstack/sdk/go/dstack"
client := dstack.NewDstackClientV0()
```

The table above maps tappd onto the v0 method set, which is the smallest step
away from `TappdClient`. New code should target `NewDstackClientV1`; see
[Two API versions](#two-api-versions) for what changes, including the warning
that v1 derives different key material.

**Step 2: Update Method Calls**

```go
// For deterministic application keys (most common)
// Before: TappdClient methods
keyResult, _ := client.DeriveKey(ctx, "wallet")

// After: DstackClient methods
keyResult, _ := client.GetKey(ctx, "wallet/ethereum", "ethereum", "secp256k1")

// For TLS certificates
// Before: DeriveKey with TLS options
tlsCert, _ := client.DeriveKeyWithSubjectAndAltNames(ctx, "api", "example.com", []string{"localhost"})

// After: GetTlsKey with proper options
tlsCert, _ := client.GetTlsKey(ctx, dstack.TlsKeyOptions{
	Subject:  "example.com",
	AltNames: []string{"localhost"},
})
```

### Migration Checklist

- [ ] **Infrastructure Updates:**
  - [ ] Update Docker volume binding to `/var/run/dstack.sock`
  - [ ] Change environment variables from `TAPPD_*` to `DSTACK_*`

- [ ] **Client Code Updates:**
  - [ ] Replace `tappd.NewTappdClient()` with `dstack.NewDstackClientV0()`
  - [ ] Replace `DeriveKey()` calls with appropriate method:
    - [ ] `GetKey()` for deterministic application keys
    - [ ] `GetTlsKey()` for TLS certificates (random)
  - [ ] Replace `TdxQuote()` calls with `GetQuote()`
  - [ ] **SECURITY CRITICAL**: Update blockchain integration functions:
    - [ ] Replace `ToEthereumAccount()` with `ToEthereumAccountSecure()` (Ethereum)
    - [ ] Replace `ToSolanaKeypair()` with `ToSolanaKeypairSecure()` (Solana)

- [ ] **Testing:**
  - [ ] Test that deterministic keys still work as expected
  - [ ] Verify TLS certificate generation works
  - [ ] Test quote generation with new interface
  - [ ] Verify blockchain integrations work with secure functions

## Development

### Running the Simulator

For local development without TDX devices, you can use the simulator:

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
```

### Running Tests

```bash
# Set environment variables and run tests
TAPPD_SIMULATOR_ENDPOINT=/path/to/simulator/tappd.sock \
DSTACK_SIMULATOR_ENDPOINT=/path/to/simulator/dstack.sock \
go test -v ./dstack ./tappd
```

Run tests:

```bash
go test -v ./dstack
```

---

## Migration from TappdClient

Replace `tappd` package with `dstack`:

```go
// Before
import "github.com/Dstack-TEE/dstack/sdk/go/tappd"
client := tappd.NewTappdClient()

// After
import "github.com/Dstack-TEE/dstack/sdk/go/dstack"
client := dstack.NewDstackClientV0()
```

Socket path: `/var/run/tappd.sock` → `/var/run/dstack.sock`

## License

Apache License 2.0
