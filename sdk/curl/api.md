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
| `not_before` | uint64 | Certificate validity start time as seconds since UNIX epoch | `0` |
| `not_after` | uint64 | Certificate validity end time as seconds since UNIX epoch | `0` |
| `with_app_info` | boolean | Whether to include app info in the certificate | `false` |

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

Generates a deterministic private key from the application key and returns both the key and its signature chain. Suitable for ETH key generation when using the default `secp256k1` algorithm.

**Endpoint:** `/GetKey`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `path` | string | Path for the key. This is the domain separator for deterministic key material. | `"my/key/path"` |
| `purpose` | string | Purpose for the key. Can be any string. This is used in the signature chain and does not affect the private key bytes. | `"signing"` |
| `algorithm` | string | `secp256k1` (default), `k256` (alias), or `ed25519`. For compatibility, this selects how the same derived 32-byte material is interpreted; it does not domain-separate the derivation. | `ed25519` |

Use algorithm-specific paths, such as `wallet/ethereum` and `wallet/solana`, when independent keys are required across algorithms.

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/GetKey \
  -H 'Content-Type: application/json' \
  -d '{
    "path": "my/key/path",
    "purpose": "signing",
    "algorithm": "ed25519"
  }'
```

Or

```bash
curl --unix-socket /var/run/dstack.sock http://dstack/GetKey?path=my/key/path&purpose=signing&algorithm=ed25519
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

Generates a TDX quote with given plain report data. Needs Intel TDX: on a
platform without it this returns an error. On GCP Confidential VMs it answers
with the TDX quote alone, leaving out the vTPM quote GCP's verification also
binds. For evidence a verifier can check in full on any platform, use
[Attest](#7-attest) instead.

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
  "event_log": "<json-event-log>",
  "report_data": "<hex-encoded-report-data>",
  "vm_config": "<json-vm-config-string>"
}
```

**Note on Event Log:**
The `event_log` field contains a JSON array of TDX event log entries. For RTMR 0-2 (boot-time measurements), only the digest is included; the payload is stripped to reduce response size. For RTMR3 (runtime measurements), both digest and payload are included. To verify the event log, submit it along with the quote to the [verifier service](../../dstack/verifier/README.md).

### 4. Get Info

Retrieves worker information, including the detected cloud platform.

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
  "mr_aggregated": "<hex-encoded-mr-aggregated>",
  "os_image_hash": "<hex-encoded-os-image-hash>",
  "key_provider_info": "<key-provider-info-string>",
  "compose_hash": "<hex-encoded-compose-hash>",
  "vm_config": "<json-vm-config-string>",
  "cloud_vendor": "<detected-cloud-vendor>",
  "cloud_product": "<detected-cloud-product>"
}
```

The `cloud_vendor` and `cloud_product` fields report the detected cloud platform.

### 5. Sign

Signs a payload.

**Endpoint:** `/Sign`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `algorithm` | string | `ed25519`, `secp256k1_prehashed` or `secp256k1`| `ed25519` |
| `data` | string | Hex-encoded payload data | `deadbeef` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/Sign \
  -H 'Content-Type: application/json' \
  -d '{
    "algorithm": "ed25519",
    "data": "deadbeef"
  }'
```

**Response:**
```json
{
  "signature": "<hex-encoded-signature>",
  "signature_chain": [
    "<hex-encoded-signature-1>",
    "<hex-encoded-signature-2>",
    "<hex-encoded-signature-3>"
  ],
  "public_key": "<hex-encoded-public-key>"
}
```

> **Removed in v0.6.0:** there was a `/Verify` endpoint here. Checking a signature
> needs no key material and no attestation, and the agent's answer came back over
> the socket unattested, so a caller gained nothing over checking the signature
> itself. Verification now lives in the SDKs (`verify_signature` /
> `verify_signature_chain`), which can also walk the `signature_chain` back to a
> KMS root key the caller independently trusts -- something this endpoint never did.

### 6. Attest

Generates a versioned attestation with the given report data. Returns a dstack-defined attestation format that supports different attestation modes across platforms.
You can submit the returned `attestation` directly to the verifier `/verify` endpoint.

**Endpoint:** `/Attest`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `report_data` | string | Report data of max length 64 bytes. Padding with 0s if less than 64 bytes. | `"1234deadbeaf"` |
| `include_boottime_gpu_evidence` | boolean | Optional, defaults to `false`. Also returns the boot-time GPU attestation evidence in `boottime_gpu_evidence`. | `true` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/Attest \
  -H 'Content-Type: application/json' \
  -d '{
    "report_data": "1234deadbeaf",
    "include_boottime_gpu_evidence": true
  }'
```
Or
```bash
curl --unix-socket /var/run/dstack.sock 'http://dstack/Attest?report_data=1234deadbeaf&include_boottime_gpu_evidence=true'
```

**Response:**
```json
{
  "attestation": "<hex-encoded-attestation>",
  "boottime_gpu_evidence": "{\"result_code\": 0, \"claims\": [...]}"
}
```

`boottime_gpu_evidence` carries the same bytes [`GpuInfo`](#7-gpu-info) serves, so one call
returns both the quote and the GPU evidence a verifier needs. It is empty unless
`include_boottime_gpu_evidence` was set and boot-time GPU attestation output exists. It is
**not** bound to `report_data` — authenticate it with the `evidence_sha256`
procedure documented under `GpuInfo` below.

### 7. GPU Info

Returns GPU information collected during boot. Currently, this includes the
complete JSON output produced by NVIDIA `nvattest`.
The `attestation` field is empty when no GPU attestation output is available,
for example on a VM without an NVIDIA GPU or when GPU attestation was disabled.

**Endpoint:** `/GpuInfo`

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock http://dstack/GpuInfo
```

**Response:**
```json
{
  "attestation": "{\"result_code\": 0, \"claims\": [...]}"
}
```

`GpuInfo.attestation` is the exact UTF-8 `nvattest` output saved during boot;
calling this endpoint does not perform a new attestation. To authenticate it on
TDX, first verify the quote and replay the supplied event log to the quote's
RTMR3. Then decode the `gpu-attestation` event payload and compare its
`evidence_sha256` with the SHA-256 digest of the exact returned string:

```python
import hashlib
import json

gpu_info = json.load(open("gpu-info.json"))
quote_response = json.load(open("quote.json"))
events = quote_response["event_log"]
if isinstance(events, str):
    events = json.loads(events)

entry = next(event for event in events if event["event"] == "gpu-attestation")
measured = json.loads(bytes.fromhex(entry["event_payload"]))
actual = hashlib.sha256(gpu_info["attestation"].encode()).hexdigest()
assert actual == measured["evidence_sha256"]
```

The comparison above is meaningful only after quote verification and RTMR3
event-log replay have succeeded. See the
[security model](../../docs/security/security-model.md#gpu-security-for-ai-workloads)
for the event ordering and AWS/AMD SEV-SNP verification paths.

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
