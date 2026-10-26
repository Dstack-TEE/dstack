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

## API versions

The agent serves two surfaces on this socket, chosen by URL path:

| Path | Surface |
|---|---|
| `/v1/<Method>` | `dstack.guest.v1`, the current API |
| `/v0/<Method>` | the frozen v0.5.11 API |
| `/<Method>` | the same frozen API, under its historical path |

**`/v1` is the current API** and what new integrations should target. It is
specified byte-for-byte in
[`docs/guest-api-v1.md`](../../docs/guest-api-v1.md), which is the normative
reference -- this page is a curl-oriented tour, not the contract.

`/v1` serves exactly six methods:

| Endpoint | Purpose |
|---|---|
| `/v1/IssueCert` | Issue a certificate, with a freshly generated key |
| `/v1/GetKey` | Derive an application key with its signature chain |
| `/v1/Attest` | Versioned attestation, optionally with boot-time GPU evidence |
| `/v1/AttestGpu` | Collect GPU evidence now, against a nonce you choose |
| `/v1/Info` | Application identity and configuration |
| `/v1/Version` | Agent version |

> **v1 derives different key material than v0 for the same name**, on purpose,
> with no compatibility mode. See the migration note in the spec.

The remaining sections document the **legacy v0 surface**. It is frozen at
v0.5.11 and keeps working unchanged, reachable at `/v0/<Method>` and at the
unversioned `/<Method>` paths it has always had. It too has a normative
specification --
[`docs/guest-api-v0.md`](../../docs/guest-api-v0.md) pins its KDF, its signature
chain encoding, and its per-algorithm `Sign` and `Verify` modes -- and the
sections below are a curl-oriented tour of it, not the contract. Sections marked
*(v1)* describe the current API instead.

## Endpoints (legacy v0)

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

Use algorithm-specific paths, such as `backup-signing/secp256k1` and `backup-signing/ed25519`, when independent keys are required across algorithms.

The KDF, the public key encodings, the `purpose`-based chain claim and the steps
to verify the returned `signature_chain` are specified in
[Guest API v0: GetKey](../../docs/guest-api-v0.md#getkey).

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
[Attest](#6-attest) instead.

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
| `algorithm` | string | `ed25519`, `secp256k1_prehashed` or `secp256k1` (`k256` is an alias). No default: an empty string is an error | `ed25519` |
| `data` | string | Hex-encoded payload. Raw bytes for `ed25519` and `secp256k1`; for `secp256k1_prehashed` it is the digest, exactly 32 bytes, signed as-is | `deadbeef` |

The key is always the one derived at path `vms` with purpose `signing`. Each
mode's exact bytes, hash, signature encoding and three-link `signature_chain` are
specified in [Guest API v0: Sign](../../docs/guest-api-v0.md#sign).

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

> **Deprecated:** `/Verify` is still served on this frozen surface, and the SDKs'
> v0 clients still expose it. Checking a signature needs no key material and no
> attestation, and the agent's answer comes back over the socket unattested, so a
> caller gains nothing over checking the signature itself. v1 has no counterpart.
> See [Guest API v0: Verify](../../docs/guest-api-v0.md#verify) for the accepted
> algorithms and encodings, and
> [Verifying a chain](../../docs/guest-api-v0.md#verifying-a-chain) for walking a
> `signature_chain` back to a KMS root key you independently trust -- something
> this endpoint never did.

### 6. Attest

Generates a versioned attestation with the given report data. Returns a dstack-defined attestation format that supports different attestation modes across platforms.
You can submit the returned `attestation` directly to the verifier `/verify` endpoint.

**Endpoint:** `/Attest`

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `report_data` | string | Report data of max length 64 bytes. Padding with 0s if less than 64 bytes. | `"1234deadbeaf"` |

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/Attest \
  -H 'Content-Type: application/json' \
  -d '{
    "report_data": "1234deadbeaf"
  }'
```
Or
```bash
curl --unix-socket /var/run/dstack.sock http://dstack/Attest?report_data=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

**Response:**
```json
{
  "attestation": "<hex-encoded-attestation>"
}
```

> **v1 only.** `include_boottime_gpu_evidence` and the `boottime_gpu_evidence`
> response field are not on this frozen endpoint. Use
> [`/v1/Attest`](#8-boot-time-gpu-evidence-v1) for them; a request sending
> `include_boottime_gpu_evidence` here is ignored, not honoured.

### 7. Attest GPU *(v1)*

Collects vendor-native GPU evidence for a caller-chosen 32-byte nonce.

**Endpoint:** `/v1/AttestGpu`

> **v1 only.** This method is not on the frozen surface. It never appeared in a
> v0.5.x release, so no existing client is affected.

**Request Parameters:**

| Field | Type | Description | Example |
|-------|------|-------------|----------|
| `nonce` | string | Exactly 32 bytes, hex-encoded and passed to the GPU verbatim. | `"ab...ab"` (64 hex chars) |

**Response:**

```json
{
  "bundles": [{
    "vendor": "nvidia",
    "format": "nvidia-nvattest-collect-evidence-json-v1",
    "evidence": "<hex-encoded opaque evidence>"
  }]
}
```

Select a verifier using each bundle's `vendor` and `format`. The verifier must check
the evidence signature, certificate chain, measurements, and embedded nonce. The
agent does not appraise the evidence. Evidence does not by itself bind the GPU to this
CVM.

> An image that ships no GPU attestation answers `501 Not Implemented`, not
> `400`. Retrying with a different nonce will not help; fall back to whatever
> your application does without a GPU. A nonce that is not exactly 32 bytes is
> still a `400`.

### 8. Boot-time GPU evidence *(v1)*

Returns the complete output NVIDIA `nvattest` produced during boot, as part of
an attestation -- so one round trip fetches the evidence together with the
attestation needed to authenticate it.

**Endpoint:** `/v1/Attest`

**Example:**
```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/v1/Attest \
  -H 'Content-Type: application/json' \
  -d '{
    "report_data": "1234deadbeaf",
    "include_boottime_gpu_evidence": true
  }'
```

**Response:**
```json
{
  "attestation": "<hex-encoded-attestation>",
  "boottime_gpu_evidence": [
    {
      "vendor": "nvidia",
      "format": "nvidia-nvattest-boottime-json-v1",
      "evidence": "<hex-encoded UTF-8 nvattest output>"
    }
  ]
}
```

`boottime_gpu_evidence` uses the same `GpuEvidenceBundle` shape
[`/v1/AttestGpu`](#7-attest-gpu-v1) returns, so one parser handles both. Dispatch
on `format`: `nvidia-nvattest-boottime-json-v1` is the record written at boot,
`nvidia-nvattest-collect-evidence-json-v1` is collected on demand against a
nonce you choose. A verifier for one does not appraise the other.

It is an empty list when the flag was not set or the guest has no boot-time GPU
output — there is no sentinel value.

Each bundle's `evidence` decodes to the exact UTF-8 `nvattest` output saved
during boot, byte for byte. Requesting it does not perform a new attestation,
and it is **not** bound to `report_data`.

To authenticate it on TDX, first verify the quote and replay the supplied event
log to the quote's RTMR3. Then decode the `gpu-attestation` event payload and
compare its `evidence_sha256` with the SHA-256 digest of the exact returned
string:

```python
import hashlib
import json

attest_response = json.load(open("attest.json"))
quote_response = json.load(open("quote.json"))
events = quote_response["event_log"]
if isinstance(events, str):
    events = json.loads(events)

entry = next(event for event in events if event["event"] == "gpu-attestation")
measured = json.loads(bytes.fromhex(entry["event_payload"]))
# sha256 over the exact bytes the agent read from disk. Do not parse and
# re-serialize the JSON first: that changes the digest.
bundle = next(
    b for b in attest_response["boottime_gpu_evidence"]
    if b["format"] == "nvidia-nvattest-boottime-json-v1"
)
actual = hashlib.sha256(bytes.fromhex(bundle["evidence"])).hexdigest()
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
- `501 Not Implemented`: The agent cannot serve this method in this image; only
  `/v1/AttestGpu` answers this, and only when the image ships no GPU attestation
- `500 Internal Server Error`: Server-side error

Error responses will include a JSON body with error details:
```json
{
  "error": "Error description"
}
```
