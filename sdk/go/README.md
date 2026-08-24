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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

func main() {
	// Create client - automatically connects to /var/run/dstack.sock
	client := dstack.NewDstackClient()

	// For local development with simulator
	// devClient := dstack.NewDstackClient(dstack.WithEndpoint("http://localhost:8090"))

	ctx := context.Background()

	// Get TEE instance information
	info, err := client.Info(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("App ID:", info.AppID)
	fmt.Println("Instance ID:", info.InstanceID)
	fmt.Println("App Name:", info.AppName)
	fmt.Println("TCB Info:", info.TcbInfo)

	// Derive deterministic keys for application-specific secrets
	walletKey, err := client.GetKey(ctx, "wallet/ethereum", "mainnet", "secp256k1")
	if err != nil {
		log.Fatal(err)
	}

	keyBytes, _ := walletKey.DecodeKey()
	fmt.Println("Derived key (32 bytes):", hex.EncodeToString(keyBytes))        // secp256k1 private key
	fmt.Println("Signature chain:", walletKey.SignatureChain)                   // Authenticity proof

	// Generate remote attestation quote
	applicationData := map[string]interface{}{
		"version":   "1.0.0",
		"timestamp": time.Now().Unix(),
		"user_id":   "alice",
	}

	jsonData, _ := json.Marshal(applicationData)
	quote, err := client.GetQuote(ctx, jsonData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("TDX Quote:", quote.Quote)
	fmt.Println("Event Log:", quote.EventLog)
}
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
client := dstack.NewDstackClient()

// Check if dstack service is available
isAvailable := client.IsReachable(context.Background())
if !isAvailable {
	log.Fatal("dstack service is not reachable")
}
```

The client automatically connects to `/var/run/dstack.sock`. For local development with the simulator:

```go
client := dstack.NewDstackClient(dstack.WithEndpoint("http://localhost:8090"))
```

**Options:**
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

##### `AttestGpu(ctx context.Context, nonce []byte) (*AttestGpuResponse, error)`

Runs NVIDIA GPU attestation now, against a 32-byte nonce you choose. Use it after
anything that may have reinitialised the GPU — a driver reload leaves a device that
answers NVML but can no longer attest.

```go
resp, err := client.AttestGpu(ctx, nonce)
if err != nil {
	log.Fatal(err)
}
fmt.Println(resp.Evidence)
```

> [!IMPORTANT]
> `evidence` is GPU-signed and checkable by anyone — the base64 SPDM report and its
> certificate chain, over your nonce. `appraisal` is the local verifier's verdict on
> those same bytes and does **not** travel (`alg:none` EAT), so a remote party should
> appraise `evidence` itself and ignore `appraisal`.
>
> Neither binds the GPU to this CVM: an NVIDIA report binds the device and nonce and
> nothing else, so it is relayable until TDISP/TEE-IO. For TD-bound evidence use the
> boot-time `gpu-attestation` event. Calls are rate-limited to one per 10s.

##### `GpuInfo(ctx context.Context) (*GpuInfoResponse, error)`

Returns GPU information collected during boot. Currently, this includes the
complete NVIDIA `nvattest` JSON output.

```go
gpu, err := client.GpuInfo(ctx)
if err != nil {
	log.Fatal(err)
}
fmt.Println(gpu.Attestation)
```

The `Attestation` field is empty when no GPU attestation output is available.
The raw output is not trusted by itself; remote verifiers should compare its
digest with the measured `gpu-attestation` runtime event.

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

Signatures produced by `client.Sign()` are verified **locally**. Verification
needs no key material and no attestation, so it does not belong behind an RPC to
the guest agent: the agent's answer would arrive over the socket unattested,
which is no better than checking the signature yourself. The `Verify` RPC these
functions replace was removed in v0.6.0.

#### `VerifySignature(algorithm string, data, signature, publicKey []byte) (bool, error)`

Checks one signature against a public key you already have. `algorithm` is
`ed25519`, `secp256k1` (alias `k256`), or `secp256k1_prehashed`, where `data` is
already a 32-byte digest. secp256k1 public keys are SEC1 (compressed or
uncompressed) and signatures are raw 64-byte `r || s`, not DER.

Returns `(false, nil)` when the inputs are well-formed but the signature does not
check out, and a non-nil error when they are not well-formed at all (bad key
encoding, wrong signature length, unknown algorithm, non-canonical high-S
signature) — a malformed input is a caller bug, not a verdict.

```go
signResp, err := client.Sign(ctx, "secp256k1", payload)
if err != nil {
	log.Fatal(err)
}

valid, err := dstack.VerifySignature("secp256k1", payload, signResp.Signature, signResp.PublicKey)
if err != nil {
	log.Fatalf("malformed signature input: %v", err)
}
fmt.Println("signature valid:", valid)
```

On its own this proves only that whoever holds `signResp.PublicKey` signed the
data. To establish that the signer was a dstack app, verify the chain.

#### `VerifySignatureChain(input SignatureChainInput) ([]byte, error)`

Walks the full chain from a `SignResponse` back to a KMS root key **you supply**,
and returns the app root public key (compressed SEC1, 33 bytes). Three links must
all hold:

1. `SignatureChain[0]` is a signature over `Data` by `PublicKey`.
2. `SignatureChain[1]` is the app root key attesting `"{purpose}:{hex(PublicKey)}"`.
3. `SignatureChain[2]` is `KMSRootPubKey` attesting that app root key for `AppID`.

Link 3 is the one that matters. Without comparing against a KMS root key you
independently trust, a chain is just three signatures an attacker could have
produced with their own keys. Get the root from the `DstackKms` contract
(`kmsInfo().k256Pubkey`) or pin it. Reading it from the KMS you are verifying
against proves nothing.

```go
// Both anchors come from you, not from the CVM being checked.
appID, _ := hex.DecodeString("a9019d1b2c3d4e5f60718293a4b5c6d7e8f90a1b")
kmsRoot, _ := hex.DecodeString("03...") // pinned, or read from the DstackKms contract

appRootPubKey, err := dstack.VerifySignatureChain(dstack.SignatureChainInput{
	Algorithm:      "secp256k1",
	Data:           payload,
	PublicKey:      signResp.PublicKey,
	SignatureChain: signResp.SignatureChain,
	AppID:          appID,
	KMSRootPubKey:  kmsRoot,
	// Purpose defaults to dstack.SignPurpose ("signing"), which is what Sign uses.
})
if err != nil {
	log.Fatalf("signature chain rejected: %v", err)
}
fmt.Printf("app root key: %x\n", appRootPubKey)
```

Note what the example does *not* do: it never passes `info.AppID` from
`client.Info()` straight through. That value is reported by the very CVM being
verified, so a chain checked against it proves only that the CVM is
self-consistent with itself. Use the app id you registered on chain, and if you
want `Info` in the picture, compare it against that value rather than trusting
it.

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
client := dstack.NewDstackClient()
```

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
  - [ ] Replace `tappd.NewTappdClient()` with `dstack.NewDstackClient()`
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

# Run cross-language consistency tests
TAPPD_SIMULATOR_ENDPOINT=/path/to/simulator/tappd.sock \
DSTACK_SIMULATOR_ENDPOINT=/path/to/simulator/dstack.sock \
go run test-outputs.go
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
client := dstack.NewDstackClient()
```

Socket path: `/var/run/tappd.sock` → `/var/run/dstack.sock`

## License

Apache License 2.0
