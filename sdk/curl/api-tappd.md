# dstack Tappd RPC API Documentation (Legacy)

This document describes the legacy REST API endpoints for the dstack Tappd service. These APIs are deprecated as of version 0.4.2. For newer versions, please refer to [api.md](api.md) which contains the current API documentation.

## Base URL

The dstack Tappd service listens on a Unix domain socket at `/var/run/tappd.sock`. All API requests should be made to this socket using the `--unix-socket` flag with curl.

Make sure to map the Unix socket in your Docker Compose file:

```yaml
services:
  jupyter:
    image: quay.io/jupyter/base-notebook
    volumes:
      - /var/run/tappd.sock:/var/run/tappd.sock
```

## Endpoints

### 1. Derive Key

Derives a cryptographic key from the specified key path and returns it along with its certificate chain.

**Endpoint:** `/prpc/Tappd.DeriveKey`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `path` | string | Path used to derive the private key | `"my/key/path"` |
| `subject` | string | The subject name for the certificate | `"example.com"` |
| `alt_names` | array of strings | List of Subject Alternative Names (SANs) for the certificate | `["www.example.com", "api.example.com"]` |
| `usage_ra_tls` | boolean | Whether to include quote in the certificate for RA-TLS | `true` |
| `usage_server_auth` | boolean | Enable certificate for server authentication | `true` |
| `usage_client_auth` | boolean | Enable certificate for client authentication | `false` |
| `random_seed` | boolean | Derive from random seed | `false` |

**Example:**
```bash
curl --unix-socket /var/run/tappd.sock -X POST \
  http://localhost/prpc/Tappd.DeriveKey \
  -H 'Content-Type: application/json' \
  -d '{
    "path": "my/key/path",
    "subject": "example.com",
    "alt_names": ["www.example.com", "api.example.com"],
    "usage_ra_tls": true,
    "usage_server_auth": true,
    "usage_client_auth": false,
    "random_seed": false
  }'
```

**Response:**
```json
{
  "key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "certificate_chain": [
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  ]
}
```

### 2. Derive K256 Key

Derives a new ECDSA key with k256 EC curve.

**Endpoint:** `/prpc/Tappd.DeriveK256Key`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `path` | string | Path to the key to derive | `"my/key/path"` |
| `purpose` | string | Purpose of the key | `"signing"` |

**Example:**
```bash
curl --unix-socket /var/run/tappd.sock -X POST \
  http://localhost/prpc/Tappd.DeriveK256Key \
  -H 'Content-Type: application/json' \
  -d '{
    "path": "my/key/path",
    "purpose": "signing"
  }'
```

**Response:**
```json
{
  "k256_key": "<hex-encoded-key>",
  "k256_signature_chain": [
    "<hex-encoded-signature-1>",
    "<hex-encoded-signature-2>"
  ]
}
```

### 3. TDX Quote

Generates a TDX quote with report data.

**Endpoint:** `/prpc/Tappd.TdxQuote`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `report_data` | string | Report data to be included in the quote | `"1234deadbeaf"` |
| `hash_algorithm` | string | Hash algorithm to process the report data. Default is `sha512`. Options: `sha256`, `sha384`, `sha512`, `sha3-256`, `sha3-384`, `sha3-512`, `keccak256`, `keccak384`, `keccak512`, `raw` | `"sha512"` |
| `prefix` | string | Custom prefix to prepend to report data before hashing. Defaults to 'app-data:' when hash_algorithm is not 'raw' | `"app-data:"` |

**Example:**
```bash
curl --unix-socket /var/run/tappd.sock -X POST \
  http://localhost/prpc/Tappd.TdxQuote \
  -H 'Content-Type: application/json' \
  -d '{
    "report_data": "1234deadbeaf",
    "hash_algorithm": "sha512",
    "prefix": "app-data:"
  }'
```

**Response:**
```json
{
  "quote": "<hex-encoded-quote>",
  "event_log": "quote generation log",
  "hash_algorithm": "sha512",
  "prefix": "app-data:"
}
```

### 4. Raw Quote

Generates a TDX quote with raw report data. This is a low-level API that should be used with caution.

**Endpoint:** `/prpc/Tappd.RawQuote`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `report_data` | string | 64 bytes of raw report data(hex encoded)| `"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"` |

**Example:**
```bash
curl --unix-socket /var/run/tappd.sock -X POST \
  http://localhost/prpc/Tappd.RawQuote \
  -H 'Content-Type: application/json' \
  -d '{
    "report_data": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  }'
```

Or

```bash
curl --unix-socket /var/run/tappd.sock http://localhost/prpc/Tappd.RawQuote?report_data=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

**Response:**
```json
{
  "quote": "<hex-encoded-quote>",
  "event_log": "quote generation log"
}
```

### 5. Info

Retrieves worker information.

**Endpoint:** `/prpc/Tappd.Info`

**Example:**
```bash
curl --unix-socket /var/run/tappd.sock http://localhost/prpc/Tappd.Info
```

**Response:**
```json
{
  "app_id": "<hex-encoded-app-id>",
  "instance_id": "<hex-encoded-instance-id>",
  "app_cert": "<certificate-string>",
  "tcb_info": "<tcb-info-string>",
  "app_name": "my-app",
  "device_id": "<hex-encoded-device-id>",
  "os_image_hash": "<hex-encoded-os-image-hash>",
  "key_provider_info": "<key-provider-info-string>",
  "compose_hash": "<hex-encoded-compose-hash>"
}
```

## Error Responses

All endpoints may return the following HTTP status codes:

- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters
- `500 Internal Server Error`: Server-side error

Error responses will include a JSON body with error details:
```json
{
  "error": "Error description"
}
```
