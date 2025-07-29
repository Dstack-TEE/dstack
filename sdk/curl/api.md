# dstack Guest Agent RPC API Documentation

This document describes the REST API endpoints for the dstack Guest Agent RPC service.

## Base URL

The dstack Guest Agent listens on a Unix domain socket at `/var/run/dstack.sock`. All API requests should be made to this socket using the `--unix-socket` flag with curl.

Make sure to map the Unix socket in your Docker Compose file:

```yaml
services:
  jupyter:
    image: quay.io/jupyter/base-notebook
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
```

## Endpoints

### 1. Get TLS Key

Derives a cryptographic key and returns it along with its TLS certificate chain. This API can be used to generate a TLS key/certificate for RA-TLS.

**Endpoint:** `/GetTlsKey`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `subject` | string | The subject name for the certificate | `"example.com"` |
| `alt_names` | array of strings | List of Subject Alternative Names (SANs) for the certificate | `["www.example.com", "api.example.com"]` |
| `usage_ra_tls` | boolean | Whether to include quote in the certificate for RA-TLS | `true` |
| `usage_server_auth` | boolean | Enable certificate for server authentication | `true` |
| `usage_client_auth` | boolean | Enable certificate for client authentication | `false` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/GetTlsKey \
  -H 'Content-Type: application/json' \
  -d '{
    "subject": "example.com",
    "alt_names": ["www.example.com", "api.example.com"],
    "usage_ra_tls": true,
    "usage_server_auth": true,
    "usage_client_auth": false
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

### 2. Get Key

Generates an ECDSA key using the k256 elliptic curve, derived from the application key, and returns both the key and its signature chain. Sutable for ETH key generation.

**Endpoint:** `/GetKey`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `path` | string | Path for the key | `"my/key/path"` |
| `purpose` | string | Purpose for the key. Can be any string. This is used in the signature chain. | `"signing"` | `"encryption"` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/GetKey \
  -H 'Content-Type: application/json' \
  -d '{
    "path": "my/key/path",
    "purpose": "signing"
  }'
```

Or

```bash
curl --unix-socket /var/run/dstack.sock http://dstack/GetKey?path=my/key/path&purpose=signing
```

**Response:**
```json
{
  "key": "<hex-encoded-key>",
  "signature_chain": [
    "<hex-encoded-signature-1>",
    "<hex-encoded-signature-2>"
  ]
}
```

### 3. Get Quote

Generates a TDX quote with given plain report data.

**Endpoint:** `/GetQuote`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `report_data` | string | Report data of max length 64 bytes. Padding with 0s if less than 64 bytes. | `"1234deadbeaf"` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/GetQuote \
  -H 'Content-Type: application/json' \
  -d '{
    "report_data": "1234deadbeaf"
  }'
```
Or
```bash
curl --unix-socket /var/run/dstack.sock http://dstack/GetQuote?report_data=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

**Response:**
```json
{
  "quote": "<hex-encoded-quote>",
  "event_log": "quote generation log",
  "report_data": "<hex-encoded-report-data>"
}
```

### 4. Get Info

Retrieves worker information.

**Endpoint:** `/Info`

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock http://dstack/Info
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

### 5. Emit Event

Emit an event to be extended to RTMR3 on TDX platform. This API requires dstack OS 0.5.0 or later.

**Endpoint:** `/EmitEvent`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `event` | string | The event name | `"custom-event"` |
| `payload` | string | Hex-encoded payload data | `"deadbeef"` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/EmitEvent \
  -H 'Content-Type: application/json' \
  -d '{
    "event": "custom-event",
    "payload": "deadbeef"
  }'
```

**Response:**
Empty response with HTTP 200 status code on success.

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
