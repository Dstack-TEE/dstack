# dstack SDK for Go

Access TEE features from your Go application running inside dstack. Derive deterministic keys, generate attestation quotes, create TLS certificates, and sign data—all backed by hardware security.

## Installation

```bash
go get github.com/Dstack-TEE/dstack/sdk/go
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

func main() {
	client := dstack.NewDstackClient()

	// Derive a deterministic key for your wallet
	key, _ := client.GetKey(context.Background(), "wallet/eth", "", "secp256k1")
	fmt.Println(key.Key)  // Same path always returns the same key

	// Generate an attestation quote
	attest, _ := client.Attest(context.Background(), []byte("my-app-state"))
	fmt.Println(attest.Attestation)
}
```

The client automatically connects to `/var/run/dstack.sock`. For local development with the simulator:

```go
client := dstack.NewDstackClient(dstack.WithEndpoint("http://localhost:8090"))
```

## Core API

### Derive Keys

`GetKey()` derives deterministic keys bound to your application's identity (`app_id`). The same path always produces the same key for your app, but different apps get different keys even with the same path.

```go
// Derive keys by path
ethKey, _ := client.GetKey(ctx, "wallet/ethereum", "", "secp256k1")
btcKey, _ := client.GetKey(ctx, "wallet/bitcoin", "", "secp256k1")

// Use path to separate keys
mainnetKey, _ := client.GetKey(ctx, "wallet/eth/mainnet", "", "secp256k1")
testnetKey, _ := client.GetKey(ctx, "wallet/eth/testnet", "", "secp256k1")

// Different algorithm
edKey, _ := client.GetKey(ctx, "signing/key", "", "ed25519")
```

**Parameters:**
- `path`: Key derivation path (determines the key)
- `purpose`: Included in signature chain message, does not affect the derived key
- `algorithm`: `"secp256k1"` or `"ed25519"`

**Returns:** `*GetKeyResponse`
- `Key`: Hex-encoded private key
- `SignatureChain`: Signatures proving the key was derived in a genuine TEE

### Generate Attestation Quotes

`GetQuote()` creates a TDX quote proving your code runs in a genuine TEE.

```go
quote, _ := client.GetQuote(ctx, []byte("user:alice:nonce123"))

// Replay RTMRs from the event log
rtmrs, _ := quote.ReplayRTMRs()
fmt.Println(rtmrs)
```

**Parameters:**
- `reportData`: Exactly 64 bytes recommended. If shorter, pad with zeros. If longer, hash it first (e.g., SHA-256).

**Returns:** `*GetQuoteResponse`
- `Quote`: TDX quote as bytes
- `EventLog`: JSON string of measured events
- `ReplayRTMRs()`: Method to compute RTMR values from event log

`Attest()` creates a versioned attestation with the given report data.

```go
attest, _ := client.Attest(ctx, []byte("my-app-state"))
fmt.Println(attest.Attestation)
```

**Parameters:**
- `reportData`: Exactly 64 bytes recommended. If shorter, pad with zeros. If longer, hash it first (e.g., SHA-256).

**Returns:** `*AttestResponse`
- `Attestation`: Versioned attestation as bytes

### Get Instance Info

```go
info, _ := client.Info(ctx)
fmt.Println(info.AppID)
fmt.Println(info.InstanceID)
fmt.Println(info.TcbInfo)

// Decode TCB info for detailed measurements
tcb, _ := info.DecodeTcbInfo()
fmt.Println(tcb.Mrtd)
```

**Returns:** `*InfoResponse`
- `AppID`: Application identifier
- `InstanceID`: Instance identifier
- `AppName`: Application name
- `TcbInfo`: TCB measurements (JSON string)
- `ComposeHash`: Hash of the app configuration
- `AppCert`: Application certificate (PEM)
- `DecodeTcbInfo()`: Helper method to parse TcbInfo JSON

### Generate TLS Certificates

`GetTlsKey()` creates fresh TLS certificates. Unlike `GetKey()`, each call generates a new random key.

```go
tls, _ := client.GetTlsKey(
	ctx,
	dstack.WithSubject("api.example.com"),
	dstack.WithAltNames([]string{"localhost"}),
	dstack.WithUsageRaTls(true),  // Embed attestation in certificate
	dstack.WithUsageServerAuth(true),
)

fmt.Println(tls.Key)               // PEM private key
fmt.Println(tls.CertificateChain)  // Certificate chain
```

**Options:**
- `WithSubject(subject)`: Certificate common name (e.g., domain name)
- `WithAltNames(altNames)`: List of subject alternative names
- `WithUsageRaTls(bool)`: Embed TDX quote in certificate extension
- `WithUsageServerAuth(bool)`: Enable for server authentication
- `WithUsageClientAuth(bool)`: Enable for client authentication

**Returns:** `*GetTlsKeyResponse`
- `Key`: PEM-encoded private key
- `CertificateChain`: List of PEM certificates

### Sign and Verify

Sign data using TEE-derived keys (not yet released):

```go
result, _ := client.Sign(ctx, "ed25519", []byte("message to sign"))
fmt.Println(result.Signature)
fmt.Println(result.PublicKey)

// Verify the signature
valid, _ := client.Verify(ctx, "ed25519", []byte("message to sign"), result.Signature, result.PublicKey)
fmt.Println(valid.Valid)  // true
```

**`Sign()` Parameters:**
- `algorithm`: `"ed25519"`, `"secp256k1"`, or `"secp256k1_prehashed"`
- `data`: Data to sign

**`Sign()` Returns:** `*SignResponse`
- `Signature`: Signature bytes
- `PublicKey`: Public key bytes
- `SignatureChain`: Signatures proving TEE origin

**`Verify()` Parameters:**
- `algorithm`: Algorithm used for signing
- `data`: Original data
- `signature`: Signature to verify
- `publicKey`: Public key to verify against

**`Verify()` Returns:** `*VerifyResponse`
- `Valid`: Boolean indicating if signature is valid

### Emit Events

Extend RTMR3 with custom measurements for your application's boot sequence (requires dstack OS 0.5.0+). These measurements are append-only and become part of the attestation record.

```go
client.EmitEvent(ctx, "config_loaded", []byte("production"))
client.EmitEvent(ctx, "plugin_initialized", []byte("auth-v2"))
```

**Parameters:**
- `event`: Event name (string identifier)
- `payload`: Event value (bytes)

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
