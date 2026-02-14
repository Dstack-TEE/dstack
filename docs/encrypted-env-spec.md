# Encrypted Environment Variables

dstack uses an ECIES variant (X25519 + AES-256-GCM) to protect application environment variables. The client encrypts env vars with an X25519 public key at deploy time. At boot, the CVM obtains the corresponding private key from KMS via TDX remote attestation and decrypts inside the TEE.

## Encryption Public Key Source

### Key Derivation Chain

The KMS deterministically derives a per-application key pair from its root CA key:

```
KMS root CA key (P-256 KeyPair)
  │
  └─ derive_dh_secret(context = [app_id, "env-encrypt-key"])
       → SHA256(derived_P256_key_DER) → 32 bytes
       → X25519 StaticSecret (private key = env_crypt_key, delivered to TEE)
       → X25519 PublicKey (public key, exposed to client for encryption)
```

The same `app_id` always derives the same key pair.

### Computing `app_id`

```
app_id = SHA256(app-compose.json)[0..20]    // first 20 bytes, 40 hex characters
```

Example:

```javascript
const composeHash = sha256(composeJsonString);   // 32 bytes hex
const appId = composeHash.slice(0, 40);          // first 20 bytes = 40 hex chars
```

### RPC Interface

The public key is exposed through a two-level RPC chain:

```
Client/UI  ──→  VMM (GetAppEnvEncryptPubKey)  ──→  KMS (GetAppEnvEncryptPubKey)
                       pass-through proxy              actual key derivation
```

**Request**:

```protobuf
message AppId {
  bytes app_id = 1;    // 20-byte app_id
}
```

**Response**:

```protobuf
message PublicKeyResponse {
  bytes public_key = 1;     // 32-byte X25519 public key
  bytes signature = 2;      // Legacy k256 signature (no timestamp)
  uint64 timestamp = 3;     // Unix timestamp in seconds when response was generated
  bytes signature_v1 = 4;   // New k256 signature (with timestamp, replay-resistant)
}
```

**HTTP call example** (prpc protocol):

```
POST {vmm_url}/prpc/Vmm.GetAppEnvEncryptPubKey
Content-Type: application/json

{"app_id": "<hex or base64 encoded 20 bytes>"}
```

### Public Key Signature Verification

The response includes k256 (secp256k1) signatures from the KMS root key:

- **signature** (legacy): `sign(Keccak256("dstack-env-encrypt-pubkey" + ":" + app_id + public_key))`
- **signature_v1** (new): `sign(Keccak256("dstack-env-encrypt-pubkey" + ":" + app_id + timestamp_be_bytes + public_key))`

## Encrypt/Decrypt Protocol

### Ciphertext Binary Format

```
Offset   Length      Content
───────────────────────────────────
0        32 bytes    ephemeral_public_key  (sender's ephemeral X25519 public key)
32       12 bytes    iv                    (AES-GCM nonce)
44       N+16 bytes  ciphertext + auth_tag (AES-GCM ciphertext + authentication tag)
```

Stored as raw binary in `.encrypted-env`. SDK functions may return hex strings.

### Plaintext Format

```json
{"env": [{"key": "FOO", "value": "bar"}, {"key": "SECRET", "value": "123"}]}
```

### Encryption Flow (Client-Side)

Input: `env_vars` (key-value list), `remote_public_key` (X25519 public key, 32 bytes)

```
1. plaintext     = JSON.encode({"env": [{"key": k, "value": v}, ...]})
2. ephemeral_sk  = X25519.random_private_key()               // 32 bytes
3. ephemeral_pk  = X25519.public_key(ephemeral_sk)            // 32 bytes
4. shared_secret = X25519.dh(ephemeral_sk, remote_public_key) // 32 bytes
5. iv            = random(12)                                  // 12 bytes
6. ciphertext    = AES-256-GCM.encrypt(
                       key       = shared_secret,  // DH output used directly as AES key, no KDF
                       nonce     = iv,
                       plaintext = plaintext,
                       aad       = None            // no associated data
                   )
7. output        = ephemeral_pk || iv || ciphertext
```

### Decryption Flow (Inside TEE)

Input: `env_crypt_key` (X25519 private key, 32 bytes), `data` (complete ciphertext)

```
1. ephemeral_pk   = data[0..32]
2. iv             = data[32..44]
3. ciphertext     = data[44..]       // includes 16-byte GCM auth tag
4. shared_secret  = X25519.dh(env_crypt_key, ephemeral_pk)  // 32 bytes
5. plaintext      = AES-256-GCM.decrypt(
                        key        = shared_secret,
                        nonce      = iv,
                        ciphertext = ciphertext,
                        aad        = None
                    )
6. result         = JSON.decode(plaintext)  // → {"env": [...]}
```

### Algorithm Parameters

| Parameter | Value |
|-----------|-------|
| Key agreement | X25519 (RFC 7748), **not** ECDH P-256 |
| Symmetric encryption | AES-256-GCM |
| KDF | None — shared secret is used directly as the AES key |
| IV / Nonce | 12 bytes, randomly generated |
| AAD | None (no associated data) |
| Auth tag | 16 bytes (GCM default), appended to ciphertext |
| Key format | Raw 32 bytes, not PEM/DER |

## `.appkeys.json` File Specification

Path inside TEE: `/dstack/.host-shared/.appkeys.json`

### JSON Structure

```json
{
  "disk_crypt_key": "aabbccdd...",
  "env_crypt_key": "0123456789abcdef...(64 hex chars)...",
  "k256_key": "...",
  "k256_signature": "...",
  "gateway_app_id": "some-app-id",
  "ca_cert": "-----BEGIN CERTIFICATE-----\n...",
  "key_provider": {
    "Kms": {
      "url": "https://kms.example.com/prpc",
      "pubkey": "...",
      "tmp_ca_key": "-----BEGIN PRIVATE KEY-----\n...",
      "tmp_ca_cert": "-----BEGIN CERTIFICATE-----\n..."
    }
  }
}
```

### Fields

| Field | Rust Type | JSON Serialization | Description |
|-------|-----------|-------------------|-------------|
| `disk_crypt_key` | `Vec<u8>` | hex string | Disk encryption key |
| `env_crypt_key` | `Vec<u8>` | hex string | **X25519 private key (32 bytes = 64 hex chars)**, may be absent |
| `k256_key` | `Vec<u8>` | hex string | secp256k1 signing private key |
| `k256_signature` | `Vec<u8>` | hex string | KMS signature of the k256 key |
| `gateway_app_id` | `String` | plain string | Gateway application ID |
| `ca_cert` | `String` | PEM string | CA certificate |
| `key_provider` | tagged enum | see below | Key provider information |

All `Vec<u8>` fields are hex strings in JSON (via `serde-human-bytes`, **not** base64). `env_crypt_key` may be absent (defaults to empty).

### `key_provider` Field

Rust externally tagged enum — an object with exactly one key:

```json
{"None":  {"key": "<PEM>"}}
{"Local": {"key": "<PEM>", "mr": "<hex>"}}
{"Tpm":   {"key": "<PEM>", "pubkey": "<hex>"}}
{"Kms":   {"url": "...", "pubkey": "<hex>", "tmp_ca_key": "<PEM>", "tmp_ca_cert": "<PEM>"}}
```

The tag is one of `"None"` / `"Local"` / `"Tpm"` / `"Kms"`.

## Language Implementation Guides

### Parsing `.appkeys.json`

**Rust**:

```rust
use dstack_types::AppKeys;
let keys: AppKeys = serde_json::from_str(&json_str)?;
```

**Go**:

```go
type AppKeys struct {
    DiskCryptKey  string          `json:"disk_crypt_key"`
    EnvCryptKey   string          `json:"env_crypt_key"`
    K256Key       string          `json:"k256_key"`
    K256Signature string          `json:"k256_signature"`
    GatewayAppId  string          `json:"gateway_app_id"`
    CaCert        string          `json:"ca_cert"`
    KeyProvider   json.RawMessage `json:"key_provider"`
}

keyBytes, err := hex.DecodeString(appKeys.EnvCryptKey)
```

**Python**:

```python
import json

with open(".appkeys.json") as f:
    keys = json.load(f)

env_crypt_key = bytes.fromhex(keys.get("env_crypt_key", ""))
```

**TypeScript**:

```typescript
const keys = JSON.parse(fs.readFileSync(".appkeys.json", "utf-8"));
const envCryptKey = Buffer.from(keys.env_crypt_key ?? "", "hex");
```

**Parsing `key_provider`**:

```go
var raw map[string]json.RawMessage
json.Unmarshal([]byte(appKeys.KeyProvider), &raw)
```

```python
provider = keys["key_provider"]            # {"Kms": {"url": "...", ...}}
provider_type = list(provider.keys())[0]   # "Kms"
provider_data = provider[provider_type]
```

### Decryption

**Rust** (see `dstack-util/src/crypto.rs`):

```rust
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn decrypt(secret: [u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let ephemeral_pk: [u8; 32] = data[..32].try_into()?;
    let iv = &data[32..44];
    let ct = &data[44..];

    let sk = StaticSecret::from(secret);
    let pk = PublicKey::from(ephemeral_pk);
    let shared = sk.diffie_hellman(&pk).to_bytes();

    let cipher = Aes256Gcm::new_from_slice(&shared)?;
    cipher.decrypt(Nonce::from_slice(iv), ct)
}
```

**Go**:

```go
import (
    "crypto/aes"
    "crypto/cipher"
    "fmt"

    "golang.org/x/crypto/curve25519"
)

func Decrypt(envCryptKey [32]byte, data []byte) ([]byte, error) {
    if len(data) < 44 {
        return nil, fmt.Errorf("ciphertext too short")
    }
    ephPk := data[:32]
    iv := data[32:44]
    ct := data[44:]

    shared, err := curve25519.X25519(envCryptKey[:], ephPk)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(shared)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    return gcm.Open(nil, iv, ct, nil)
}
```

**Python**:

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt(env_crypt_key: bytes, data: bytes) -> bytes:
    if len(data) < 44:
        raise ValueError("ciphertext too short")
    eph_pk = X25519PublicKey.from_public_bytes(data[:32])
    iv     = data[32:44]
    ct     = data[44:]

    sk     = X25519PrivateKey.from_private_bytes(env_crypt_key)
    shared = sk.exchange(eph_pk)

    return AESGCM(shared).decrypt(iv, ct, None)
```

**TypeScript**:

```typescript
import { x25519 } from "@noble/curves/ed25519";
import crypto from "crypto";

async function decrypt(envCryptKey: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const ephPk = data.slice(0, 32);
  const iv    = data.slice(32, 44);
  const ct    = data.slice(44);

  const shared = x25519.getSharedSecret(envCryptKey, ephPk);

  const importedKey = await crypto.subtle.importKey(
    "raw", shared, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, importedKey, ct
  );
  return new Uint8Array(plaintext);
}
```

### Encryption

**Python** (see `sdk/python/src/dstack_sdk/encrypt_env_vars.py`):

```python
import json, secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(envs: list[dict], public_key: bytes) -> bytes:
    plaintext = json.dumps({"env": envs}).encode()

    sk = X25519PrivateKey.generate()
    eph_pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    remote_pk = X25519PublicKey.from_public_bytes(public_key)
    shared    = sk.exchange(remote_pk)

    iv = secrets.token_bytes(12)
    ct = AESGCM(shared).encrypt(iv, plaintext, None)

    return eph_pk + iv + ct
```

**TypeScript** (see `sdk/js/src/encrypt-env-vars.ts`):

```typescript
async function encrypt(envs: EnvVar[], publicKey: Uint8Array): Promise<Uint8Array> {
  const plaintext = new TextEncoder().encode(JSON.stringify({ env: envs }));

  const privateKey = x25519.utils.randomPrivateKey();
  const ephPk      = x25519.getPublicKey(privateKey);
  const shared     = x25519.getSharedSecret(privateKey, publicKey);

  const importedKey = await crypto.subtle.importKey(
    "raw", shared, { name: "AES-GCM", length: 256 }, true, ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, importedKey, plaintext)
  );

  const result = new Uint8Array(ephPk.length + iv.length + ct.length);
  result.set(ephPk);
  result.set(iv, ephPk.length);
  result.set(ct, ephPk.length + iv.length);
  return result;
}
```

## End-to-End Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ Deployment Phase (Client-Side)                                  │
│                                                                 │
│  1. Write docker-compose.yaml                                   │
│  2. Normalize to app-compose.json                               │
│  3. app_id = SHA256(app-compose.json)[0..20]                    │
│  4. Call VMM.GetAppEnvEncryptPubKey({ app_id })                 │
│     → VMM proxies → KMS derives X25519 key pair from root key  │
│     → Returns PublicKeyResponse { public_key, signature, ... }  │
│  5. Encrypt env vars with public_key → encrypted-env file       │
│  6. Submit app-compose.json + encrypted-env to VMM for deploy   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Boot Phase (Inside CVM / TEE)                                   │
│                                                                 │
│  7. dstack-util setup reads encrypted-env from host-shared      │
│  8. Requests AppKeys from KMS via TDX remote attestation        │
│     → KMS verifies TDX quote → derives and returns              │
│       env_crypt_key (X25519 private key)                        │
│  9. AppKeys written to /dstack/.host-shared/.appkeys.json       │
│ 10. Decrypts encrypted-env using env_crypt_key → JSON plaintext │
│ 11. Writes .decrypted-env (shell format) and                    │
│     .decrypted-env.json (JSON format)                           │
│ 12. App containers consume env vars via env_file or direct read │
└─────────────────────────────────────────────────────────────────┘
```
