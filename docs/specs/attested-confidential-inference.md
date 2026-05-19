# Attested Confidential Inference

> **Status:** draft specification.
> **Reference implementation:** [`Dstack-TEE/private-ai-gateway`](https://github.com/Dstack-TEE/private-ai-gateway).
> **Conformance language:** MUST, SHOULD, MAY, and related terms are used in the RFC 2119 sense.

Attested Confidential Inference (ACI) is an interoperable interface for AI inference services that want clients to verify a private single-service or nested inference path. It proves that an AI service is the workload it claims to be, then binds API results back to that workload.

The central object is not a model name, provider name, or domain name. It is a **workload identity**: a stable identity public key, an optional profile-interpreted subject, and an attested keyset for TLS, E2EE, and receipt signing. The identity key endorses the current keyset, and the TEE attestation binds both the stable `workload_id` and the endorsed `workload_keyset_digest`. Once a client accepts that report, it can verify that later artifacts - TLS sessions, E2EE sessions, API responses, and receipts - came from the same workload and keyset epoch.

ACI v1 is intentionally narrow:

- It covers OpenAI-compatible completion endpoints plus attestation and receipt endpoints.
- It defines a common attestation report shape.
- It defines signed inference receipts as per-request event logs.
- It defines client-facing E2EE v2.
- It keeps inherited dstack vLLM proxy behavior in a compatibility profile.
- It does not define routing, upstream selection, upstream verification, billing, provider preference, canonical model ids, pricing, or upstream-evidence retrieval APIs.

## 1. Trust Model

ACI establishes two claims:

1. **Privacy:** plaintext prompts, tool inputs, and outputs are visible only inside accepted workloads.
2. **Integrity:** responses are bound to request bytes, service-side transformations, and attested code.

An ACI verifier accepts those claims by checking hardware-rooted TEE evidence, `report_data` binding to `workload_id` and `workload_keyset_digest`, keyset endorsement by the workload identity key, source provenance, freshness, and profile-defined private-key lifecycle.

Attestation establishes the service identity and current keyset. Receipts establish what happened for a specific inference.

### 1.1 Derived Work

After accepting a workload identity and keyset:

- TLS is ACI-verifiable only when the observed server certificate SPKI is listed in `tls_public_keys`.
- E2EE is ACI-verifiable only when the service E2EE key is listed in `e2ee_public_keys`.
- Receipts are ACI-verifiable only when signed by a key listed in `receipt_signing_keys`.

If plaintext HTTPS terminates outside the accepted workload, a valid WebPKI certificate does not provide ACI assurance. SPKI binding is the required baseline because it works with ordinary HTTPS stacks. RA-TLS, attested TLS certificate extensions, and TLS exporter binding are optional stronger profiles.

RATS-unaware clients, such as ordinary OpenAI SDKs, can use ACI through a verifier SDK, agent runtime, local proxy, or attestation-aware credential issuer. A client that only checks WebPKI gets WebPKI assurance, not ACI assurance.

### 1.2 Aggregators

An ACI aggregator is itself the client-facing workload. It proves its own identity to downstream clients.

ACI v1 does not standardize upstream routing, upstream verification, or raw upstream evidence retrieval. An aggregator MAY record implementation-specific receipt events describing upstream decisions, but generic ACI verifiers treat those events only as signed claims made by the accepted aggregator workload.

### 1.3 Verifier Profiles

An ACI service publishes one report plus evidence. It does not advertise verifier profiles. A relying party selects one trusted verifier profile, which composes TEE verification, source provenance, private-key lifecycle, TLS SPKI, and any platform-specific checks such as dstack app-id/KMS or SPIFFE/WebPKI validation.

A report is accepted if at least one trusted profile verifies it completely. ACI core does not define profile names, profile negotiation, profile registries, or service-advertised supported-profile lists.

A profile MUST define evidence acquisition. Required evidence MUST be inline, digest-bound and fetchable from profile-defined locations, directly observed by the verifier, or supplied by local policy. Missing required evidence is fail-closed.

## 2. Core Terms

- **ACI service:** a service implementing this protocol.
- **Individual LLM service:** an ACI service that performs inference itself.
- **Aggregator:** an ACI service that forwards to one or more upstream inference services.
- **Upstream:** an implementation-specific service selected by an aggregator to perform inference.
- **Workload identity:** the canonical object containing the stable public identity key and an optional profile-interpreted subject.
- **Workload keyset:** the canonical document listing the workload identity, keyset epoch, and operational public keys for receipt signing, E2EE, and TLS.
- **Workload keyset digest:** `sha256:<hex>`, where the hex value is `sha256(JCS(workload_keyset))`.
- **Keyset epoch:** the version and validity metadata for one endorsed workload keyset.
- **Keyset endorsement:** the identity key's signature over the current workload keyset digest.
- **Attestation statement:** the canonical report-data payload binding `workload_id`, `workload_keyset_digest`, and nonce.
- **Replica workload:** one of multiple workload instances that are functionally indistinguishable to clients and intentionally share one workload identity.
- **Attestation report:** the service's current evidence for its workload identity and keyset.
- **Inference receipt:** a signed per-inference event log binding request bytes, response bytes, and service decisions to an established workload identity and keyset.

## 3. Conformance Summary

An ACI-conformant service MUST:

1. Run the client-facing workload inside a TEE with hardware-rooted attestation.
2. Publish its own attestation report at `GET /v1/attestation/report`.
3. Bind the `workload_id` and `workload_keyset_digest` into the TEE attestation.
4. Publish source provenance sufficient for an independent verifier to connect the attested workload to public code or build artifacts.
5. Bind any plaintext HTTPS endpoint's TLS public key to the workload keyset.
6. Ensure every listed private key is generated inside the attested workload, sealed exclusively to it, or released only after successful attestation.
7. Support client-facing E2EE v2 for both non-streaming and streaming `POST /v1/chat/completions`.
8. Compute receipt hashes inside the TEE from bytes the workload actually received and emitted.
9. Sign receipts with a receipt signing key listed in the workload keyset.

A service MAY also implement the dstack vLLM proxy compatibility profile in Appendix A.

## 4. Workload Identity

### 4.1 Identity And Keyset

An ACI workload has one stable identity public key and MAY have one profile-interpreted subject. `workload_identity.public_key` has no `key_id`; labels do not define identity. `workload_identity.subject`, when present, is naming metadata such as a dstack app-id URI, SPIFFE ID, or DNS name. Generic verifiers MUST NOT trust `subject` alone.

The public identifier is:

```text
workload_id = "sha256:" || hex(sha256(JCS(workload_identity.public_key)))
```

`subject` is included in `workload_keyset_digest` but not `workload_id`; relabeling rotates the keyset, not the stable identity. A workload keyset is:

```json
{
  "workload_identity": {
    "public_key": {
      "algo": "ed25519" | "ecdsa-secp256k1" | "<other>",
      "public_key": "<hex>"
    },
    "subject": "<opaque-string-or-null>"
  },
  "keyset_epoch": {
    "version": 0,
    "not_after": 0
  },
  "receipt_signing_keys": [
    {
      "key_id": "<stable-key-id>",
      "algo": "ecdsa-secp256k1" | "ed25519",
      "public_key": "<hex>"
    }
  ],
  "e2ee_public_keys": [
    {
      "key_id": "<stable-key-id>",
      "algo": "secp256k1-aes-256-gcm-hkdf-sha256" | "x25519-aes-256-gcm-hkdf-sha256" | "<other>",
      "public_key": "<hex>"
    }
  ],
  "tls_public_keys": [
    {
      "spki_sha256": "<sha256-hex>"
    }
  ]
}
```

`keyset_epoch.version` MUST increase monotonically for each `workload_id`; stateful verifiers SHOULD reject rollback. `keyset_epoch.not_after` is a Unix timestamp after which verifiers MUST NOT use the keyset for new TLS, E2EE, or receipt acceptance. Effective expiry is the earlier of `keyset_epoch.not_after` and `attestation.freshness.stale_after`. Archival verification after expiry requires local policy.

The workload keyset digest is:

```text
workload_keyset_digest = "sha256:" || hex(sha256(JCS(workload_keyset)))
```

`JCS` means the JSON Canonicalization Scheme defined by RFC 8785.

`workload_id` is stable across operational key rotation. `workload_keyset_digest` changes when the subject, epoch metadata, receipt keys, E2EE keys, or TLS keys change. Historical receipts reference the old digest and the report that established it.

The identity key endorses the whole keyset by signing `workload_keyset_digest` (§4.2). Every keyset rotation MUST produce a new `keyset_epoch.version`, keyset endorsement, and fresh attestation report binding the new digest. ACI v1 has no soft-rotation path where endorsement alone updates the keyset.

A service MUST NOT list a public key unless the matching private key is generated inside the attested workload, sealed exclusively to it, or released only after successful attestation of an equivalent workload. Verifier profiles MUST specify how this is checked for identity, receipt, E2EE, and TLS keys.

Multiple replicas MAY share one workload identity when they are functionally indistinguishable to clients and each replica independently satisfies the attestation and key-release requirements. ACI v1 does not standardize the key-store protocol for shared replica keys.

`tls_public_keys` is required for services accepting sensitive plaintext over HTTPS. The digest is over certificate SPKI, not the whole certificate, so certificate renewal need not rotate the keyset when the TLS key is unchanged. Rotating the TLS key changes `workload_keyset_digest`, not `workload_id`.

SPKI binding is the required ACI v1 mechanism for normal HTTPS. RA-TLS, attested TLS certificate extensions, or per-session channel binding MAY provide a stronger transport profile, especially for local verifier proxies, but a conformant ACI client MUST still be able to verify the baseline SPKI binding.

`e2ee_public_keys` MUST contain at least one client-facing ACI E2EE key.

### 4.2 Attestation Binding

The hardware quote MUST bind the stable identity and current keyset digest:

```text
attestation_statement = {
  "purpose": "aci.report_data.v1",
  "workload_id": workload_id,
  "workload_keyset_digest": workload_keyset_digest,
  "nonce": <nonce-or-null>
}

report_data = sha256(JCS(attestation_statement))
```

`nonce` is the URL-decoded UTF-8 `nonce` query parameter string when supplied. If the query parameter is omitted, `nonce` is the JSON literal `null`, not the string `"null"`.

Verifier profiles define how this 32-byte value is encoded in TDX, SEV-SNP, or other evidence formats. They MUST NOT change the digest calculation.

The report MUST also contain:

```text
keyset_endorsement_payload = JCS({
  "purpose": "aci.keyset.endorsement.v1",
  "workload_keyset_digest": workload_keyset_digest
})
```

`keyset_endorsement.value` is a signature over `keyset_endorsement_payload` by the private key corresponding to `workload_keyset.workload_identity.public_key`.

A verifier MUST NOT accept keys that are merely returned next to the quote but not bound through the report-data calculation and the keyset endorsement.

### 4.3 Rationale

ACI attests one keyset epoch, not every derived artifact. Receipts are per request and are signed by a key in the attested keyset; hashing receipts into `report_data` would require a fresh quote per inference.

`report_data` binds only workload-owned public-key state and nonce. It excludes provenance, capabilities, freshness metadata, verifier policy, and raw evidence because those are either already in TEE measurements/evidence, too large, mutable, or verifier-local.

The quote and endorsement are complementary. The quote proves the endorsed keyset was active inside the measured workload at quote time. The endorsement proves the identity private key endorsed that keyset. Either check alone is insufficient.

## 5. Attestation Report

`GET /v1/attestation/report` returns the service's own attestation report. The endpoint is service-scoped, not model-scoped.

### 5.1 Query Parameters

| Parameter | Status | Meaning |
| --- | --- | --- |
| `nonce` | current | Fresh client nonce included in report data; `null` when omitted. |

Deprecated compatibility parameters are listed in Appendix A. If a compatibility client sends them, they MUST NOT affect the service-scoped attestation report.

### 5.2 Response

```json
{
  "api_version": "aci/1",
  "workload_id": "sha256:<hex>",
  "workload_keyset_digest": "sha256:<hex>",
  "attestation": {
    "vendor": "phala" | "nearai" | "chutes" | "tinfoil" | "aci-service" | "<other>",
    "tee_type": "tdx" | "sev_snp" | "<other>",
    "workload_keyset": {
      "...": "workload keyset from section 4.1"
    },
    "report_data": "<hex>",
    "keyset_endorsement": {
      "algo": "ed25519" | "ecdsa-secp256k1" | "<other>",
      "value": "<hex>"
    },
    "source_provenance": {
      "repo_url": "<https-url-or-null>",
      "repo_commit": "<git-commit-or-null>",
      "image_digest": "<sha256-prefixed-digest-or-null>",
      "image_provenance": { "...": "..." } | null
    },
    "freshness": {
      "fetched_at": 0,
      "stale_after": 0
    },
    "evidence": {
      "...": "TEE-type-specific evidence"
    }
  },
  "service_capabilities": {
    "supported_e2ee_versions": ["2"],
    "body_retention_seconds": 2592000
  }
}
```

`workload_id` MUST equal the digest of `attestation.workload_keyset.workload_identity.public_key` defined in §4.1. `workload_keyset_digest` MUST equal the digest of `attestation.workload_keyset` defined in §4.1. `keyset_endorsement` MUST verify under `attestation.workload_keyset.workload_identity.public_key` using the §4.2 payload.

At least one source provenance arm MUST be present: `repo_url` plus `repo_commit`, or `image_digest`. Verifier profiles decide which arms are sufficient and how `image_provenance` is interpreted. A launcher profile MAY satisfy this by proving that an attested, provenance-signed launcher fetched and executed a pinned repository commit. If a receipt contains implementation-specific security events, accepted source provenance needs to cover the code path that emits them.

The report is valid only until the earlier of `attestation.workload_keyset.keyset_epoch.not_after` and `attestation.freshness.stale_after`.

`service_capabilities.supported_e2ee_versions` lists client-facing ACI E2EE versions only. Upstream-only encryption formats are not advertised here.

`service_capabilities.body_retention_seconds` declares the maximum period during which retained request bodies may be available through §9.5. `0` means bodies are not retained.

### 5.3 Attestation Evidence Rules

`tee_type` selects the evidence format, not the relying party's verifier profile:

- `tdx` uses Intel TDX quote verification.
- `sev_snp` uses AMD SEV-SNP report verification.
- Any other value requires a published verifier extension document.

The `evidence` object is interpreted according to `tee_type`. Extensions MAY define additional evidence formats, but those formats MUST be named and documented. A relying party MAY apply different verifier profiles to reports with the same `tee_type`.

## 6. Models Endpoint

`GET /v1/models` remains OpenAI-compatible. ACI does not add required fields to model entries.

Trust metadata is service-level and belongs in `GET /v1/attestation/report`. In particular:

- `canonical_id` is out of scope for ACI.
- Upstream `attestation_provider` is out of scope for ACI.
- Upstream-only E2EE flavors such as `chutes` MUST NOT be advertised as client-facing ACI E2EE versions.

Compatibility fields on model entries are described in Appendix A. New ACI clients SHOULD NOT infer trust from `/v1/models`.

## 7. E2EE

ACI v1 defines client-facing E2EE v2 for OpenAI-compatible completion endpoints. A service that advertises E2EE v2 MUST support it on `POST /v1/chat/completions` and MAY support it on `POST /v1/completions`.

The service terminates client-facing E2EE itself. If it forwards to an upstream, it forwards the decrypted request over an implementation-specific protected transport, typically TLS. Upstream encryption protocols are translation details and are not advertised to downstream clients.

### 7.1 E2EE v2 AAD

Request AAD:

```text
v2|req|algo={algo}|model={model}|m={msg_idx}|c={content_idx}|n={nonce}|ts={timestamp}
```

Completion request AAD:

```text
v2|req|algo={algo}|model={model}|field=prompt|n={nonce}|ts={timestamp}
```

Response AAD:

```text
v2|resp|algo={algo}|model={model}|id={resp_id}|choice={choice_idx}|field={field}|n={nonce}|ts={timestamp}
```

`{model}` is always the top-level `payload.model` JSON string value from the request as received by the ACI service, after decrypting encrypted fields and before service-side mutation. The service encodes that parsed string value as UTF-8 with no trimming, case-folding, alias expansion, Unicode normalization, or other mutation. A request with an absent, non-string, or `|`/CR/LF-containing `model` value MUST be rejected before AAD construction.

The response AAD uses this same request `model`, not the upstream response's `model` field. This lets the client derive response AAD from its own request plus clear response metadata.

The service MAY rewrite `payload.model` later for routing. That does not affect AAD. The rewrite is audited through the receipt.

For streaming responses, E2EE v2 encrypts the same response fields inside each streamed chunk. Each chunk uses the response AAD above, with `resp_id`, `choice_idx`, and `field` taken from the clear chunk metadata and `{model}` taken from the original request.

`X-E2EE-Timestamp` is a Unix timestamp in seconds. A service MUST reject E2EE v2 requests whose timestamp is outside a 300-second clock-skew window, or a narrower window published by the service. A service MUST reject replayed `(client_public_key, model_public_key, nonce)` tuples within that window. An in-memory 300-second replay cache is acceptable for ACI v1.

`{algo}` is determined by the selected service E2EE public key in the attested workload keyset. Clients MUST use a compatible client public key format. Compatibility-only headers such as `X-Signing-Algo` do not define E2EE v2 AAD.

### 7.2 Upstream Encryption

Chutes-style anti-tamper handshakes, or any other upstream-specific encryption format, are not ACI client-facing E2EE versions. An aggregator may use them upstream after terminating ACI E2EE downstream.

## 8. Chat API

ACI v1 covers `POST /v1/chat/completions`.

The request and response bodies follow the OpenAI-compatible API, with the headers below.

### 8.1 Request Headers

| Header | Status | Meaning |
| --- | --- | --- |
| `Authorization: Bearer <api_key>` | inherited | Service authentication. |
| `X-Client-Pub-Key` | E2EE | Client E2EE public key. |
| `X-Model-Pub-Key` | E2EE | Service E2EE public key. For an aggregator, this is the aggregator's key. |
| `X-E2EE-Version` | E2EE | `2`. |
| `X-E2EE-Nonce` | E2EE v2 | Client nonce. |
| `X-E2EE-Timestamp` | E2EE v2 | Client timestamp. |

### 8.2 Response Headers

| Header | Meaning |
| --- | --- |
| `X-ACI-Version: aci/1` | Protocol version. |
| `X-ACI-Identity` | `workload_id` that served the request. |
| `X-ACI-Keyset-Digest` | `workload_keyset_digest` that served the request. |
| `X-Receipt-Id` | Receipt lookup id. |
| `X-E2EE-Applied` | `true` or `false`. |
| `X-E2EE-Version` | Present when E2EE is active. |
| `X-E2EE-Algo` | Present when E2EE is active. |

`X-ACI-Identity` is not a chat id. It is the stable workload id. `X-ACI-Keyset-Digest` identifies the attested operational keyset used for this request. `chat_id` identifies an OpenAI-compatible chat completion. A receipt binds all three when they exist.

## 9. Inference Receipts

`GET /v1/receipt/{response_id}` returns the signed receipt for a previous inference.

### 9.1 Lookup

The path id is the OpenAI-compatible response `id` returned by the completion endpoint. Legacy dstack vLLM proxy clients often call this value `chat_id`; the receipt body preserves the `chat_id` field for that compatibility.

```text
GET /v1/receipt/{response_id}
```

`receipt_id` is ACI-native and identifies one receipt inside the signed body. ACI v1 does not define a separate receipt-id lookup route.

The receipt endpoint MUST require an authenticated caller authorized for the original request. A service MAY expose redacted receipt metadata publicly, but public metadata MUST NOT include retained bodies or sensitive event fields.

### 9.2 Receipt Shape

```json
{
  "api_version": "aci/1",
  "receipt_id": "<opaque-id>",
  "chat_id": "<chat-id-or-null>",
  "workload_id": "sha256:<hex>",
  "workload_keyset_digest": "sha256:<hex>",
  "endpoint": "/v1/chat/completions",
  "method": "POST",
  "served_at": 0,

  "event_log": [
    {
      "seq": 0,
      "type": "request.received",
      "body_hash": "sha256:<hex>"
    },
    {
      "seq": 1,
      "type": "request.forwarded",
      "body_hash": "sha256:<hex>"
    },
    {
      "seq": 2,
      "type": "transparency.request_modified"
    },
    {
      "seq": 3,
      "type": "response.returned",
      "cleartext_hash": "sha256:<hex>",
      "wire_hash": "sha256:<hex>"
    }
  ],

  "signature": {
    "algo": "ecdsa-secp256k1" | "ed25519",
    "key_id": "<receipt-signing-key-id>",
    "value": "<hex>"
  }
}
```

Receipts do not embed fresh attestation. They bind back to an established `workload_id`, `workload_keyset_digest`, and receipt signing key. `event_log` is signed as part of the receipt, is not a global transparency log, and MAY contain extension events. `event_log[].seq` values MUST be strictly increasing. The first event MUST be `request.received`.

### 9.3 Required Event Types

All event hashes MUST be computed inside the TEE.

| Event | Required when | Meaning |
| --- | --- | --- |
| `request.received` | every receipt | Hash of request bytes received by the service after E2EE decryption and before mutation. |
| `request.forwarded` | every receipt | Hash of exact request bytes forwarded to the model executor or upstream. If no request rewrite happened, equals `request.received.body_hash`. |
| `response.returned` | every receipt | Hash of cleartext response bytes returned to the client and hash of wire bytes emitted to the client. |

Common transparency events include `transparency.request_modified` and `transparency.response_modified`. They carry no required fields; the hash events carry the before/after evidence. Implementations MAY add provider-specific events such as routing or upstream selection decisions.

For streaming, `response.returned` hashes cover the complete ordered stream. Unknown events MUST be ignored by generic verifiers unless local policy requires them. Large artifacts MAY be represented by digests and references.

### 9.4 Receipt Signature

The receipt signature covers the JCS canonical serialization of the whole receipt with only `signature.value` omitted.

```text
canonical_bytes = JCS(receipt without signature.value)
key = established_workload_keyset.receipt_signing_keys[signature.key_id]
verify(signature.value, canonical_bytes, key.public_key)
```

For `ecdsa-secp256k1`, `signature.value` is a 65-byte recoverable signature over `sha256(canonical_bytes)`, encoded as hex. This is intentionally not the JOSE `ES256K` `r || s` shape.

For `ed25519`, `signature.value` is an RFC 8032 Ed25519 signature over `canonical_bytes`, encoded as hex.

The verifier MUST also check that:

- `receipt.signature.key_id` names a receipt signing key in the established workload keyset.
- `receipt.signature.algo` matches that key.
- `receipt.workload_id` equals the established `workload_id`.
- `receipt.workload_keyset_digest` equals the established `workload_keyset_digest`.

### 9.5 Request Body Endpoint

`GET /v1/receipt/{response_id}/body` returns the post-rewrite request body covered by `request.forwarded.body_hash`; it never returns the pre-rewrite body. Services MAY retain bodies for any duration, including zero seconds. If retained bodies are supported:

- The original authenticated requester, using the same bearer credential or an authorization grant tied to the original request, MUST be able to fetch the unredacted body within the retention window.
- Other callers MUST receive only a redacted body, or `403 redaction_required` for unredacted requests.
- If no body is retained, return `404 receipt_body_not_retained`.

## 10. Verification Procedure

### 10.1 Establish Workload Identity

A relying party verifies an ACI report by selecting one trusted verifier profile and running the checks that profile composes. The checks below are the minimum every profile MUST include; profiles compose additional checks, such as vendor-specific event-log expectations, SPIFFE or WebPKI validation, KMS path checks, or source-provenance policy, on top.

1. The hardware evidence verifies to the TEE vendor root.
2. `workload_id` equals `"sha256:" || hex(sha256(JCS(attestation.workload_keyset.workload_identity.public_key)))`.
3. `workload_keyset_digest` equals `"sha256:" || hex(sha256(JCS(attestation.workload_keyset)))`.
4. The report data binds `workload_id`, `workload_keyset_digest`, and the requested nonce using the §4.2 `attestation_statement`.
5. `keyset_endorsement` verifies under `attestation.workload_keyset.workload_identity.public_key`.
6. `attestation.workload_keyset.keyset_epoch.not_after` and `attestation.freshness.stale_after` have not expired.
7. The source provenance matches public source or build artifacts.
8. The accepted verifier profile explains how listed private keys are generated, sealed, or released under attestation.
9. The accepted verifier profile accepts `workload_identity.subject`, when present.
10. Any direct TLS or E2EE key used by the client is present in the attested workload keyset. For TLS, compare the observed endpoint certificate SPKI digest to `tls_public_keys`.

A profile MAY require additional checks. Missing evidence required by the selected profile is fail-closed. A profile MUST NOT relax the minimum checks above.

Only after these checks should a client treat the workload identity as verified.

### 10.2 Verify An Inference

Given an established workload identity, workload keyset, and receipt, a verifier checks:

1. The receipt signature verifies under a receipt signing key listed in the attested workload keyset.
2. The receipt `workload_id` matches the established `workload_id`.
3. The receipt `workload_keyset_digest` matches the established `workload_keyset_digest`.
4. `request.received.body_hash` matches the client's original request bytes, when available.
5. `response.returned.cleartext_hash` matches the decrypted response, when available.
6. `response.returned.wire_hash` matches observed wire bytes, when available.
7. Any extension event required by local policy is understood and accepted.

## 11. Errors

All errors use the OpenAI-compatible shape:

```json
{
  "error": {
    "message": "...",
    "type": "<type>",
    "code": null,
    "param": null
  }
}
```

ACI defines these error types:

- `receipt_not_found`
- `redaction_required`
- `receipt_body_not_retained`
- `e2ee_header_missing`
- `e2ee_invalid_public_key`
- `e2ee_model_key_mismatch`
- `e2ee_invalid_version`
- `e2ee_invalid_nonce`
- `e2ee_replay_detected`
- `e2ee_invalid_timestamp`
- `e2ee_invalid_payload_model`
- `e2ee_decryption_failed`

Compatibility-only errors are listed in Appendix A.

## 12. Security Notes

- A receipt signature is not TEE verification unless the signing key is linked to an accepted `workload_id` and `workload_keyset_digest`.
- Public-key binding is not private-key custody. The accepted verifier profile must cover the private-key lifecycle for identity, receipt, E2EE, and TLS keys.
- Keyset endorsement and hardware attestation are both required. Each keyset rotation needs a fresh report binding the new `workload_keyset_digest`.
- ACI v1 receipts are not a substitute for an external timestamp or append-only transparency log when long-term non-repudiation is required.
- ACI proves workload identity, not user, organization, billing, or AI-agent delegation identity.
- Client-supplied hashes are advisory. Receipt hashes are computed inside the workload.
- Plain HTTPS is ACI-verifiable only when the observed TLS SPKI is bound to the workload keyset and the client, agent runtime, or local proxy checks that binding.
- Assurance depends on the relying party's verifier profile; ACI standardizes bindings, not a universal trust policy.
- A changed `X-ACI-Identity` means a changed stable workload identity. A changed `X-ACI-Keyset-Digest` means operational key rotation under the same identity. Clients should re-fetch attestation before sending sensitive data.

## 13. Out Of Scope For ACI v1

- Provider routing, upstream selection, upstream verification, preferences, BYOK upstream credentials, billing, quotas, pricing, cost metadata, and canonical model ids.
- Per-model upstream attestation metadata in `GET /v1/models`.
- Standard raw upstream evidence retrieval or integration with a global append-only transparency log.
- Standard continuity across workload identity key rotation. Operational key rotation under one identity is in scope.
- Credential issuance for RATS-unaware relying parties, such as X.509 or JWT/WIT issuance after attestation.
- JWS, COSE, X.509, OpenPGP, or per-subkey certificates for the core keyset endorsement. Future profiles may define those encodings.
- An ACI-core revocation list, CRL, OCSP equivalent, or soft-rotation path that updates keyset contents without fresh attestation.
- Cross-provider replica key-release, verifier profile registries, profile negotiation, or service-advertised supported-profile lists.
- Non-completion OpenAI-compatible endpoints.

## Appendix A. dstack vLLM Proxy Compatibility Profile

This appendix preserves inherited behavior for existing clients. ACI-only clients MUST NOT depend on these fields, headers, or endpoints.

Compatibility query parameters for `GET /v1/attestation/report`:

| Parameter | Meaning |
| --- | --- |
| `signing_public_key` | Legacy filter for a receipt signing key. An ACI v1 report remains service-scoped. |
| `signing_address` | Legacy vLLM proxy filter. |
| `signing_algo` | Legacy signing algorithm selector. |
| `model` | Compatibility no-op; does not select upstream attestation. |

A service MAY still return legacy report fields such as `all_attestations`, `signing_address`, or `signing_algo`. New ACI clients SHOULD ignore them and use `attestation.workload_keyset`.

The legacy wire value `ecdsa` means `ecdsa-secp256k1`. New ACI fields SHOULD use `ecdsa-secp256k1`; inherited vLLM proxy headers and legacy signature responses may continue to use `ecdsa`.

Compatibility fields on `/v1/models`, such as `e2ee_supported_versions` or `attestation_provider`, describe only the client-facing ACI service when present. They MUST NOT be interpreted as upstream trust metadata.

`POST /v1/completions` MAY be supported for OpenAI compatibility. E2EE headers are valid on this endpoint as an optional add-on when the service advertises E2EE v2; plaintext compatibility is unchanged.

Compatibility request headers:

| Header | Meaning |
| --- | --- |
| `X-Request-Hash` | Advisory cache hint only. MUST NOT influence signed receipt hashes. |
| `X-Signing-Algo` | Legacy E2EE/signature algorithm selector. |

Compatibility E2EE may support inherited dstack vLLM proxy modes selected by `X-Signing-Algo: ecdsa` or `X-Signing-Algo: ed25519`. The legacy `ecdsa` mode uses secp256k1 ECDH with HKDF info `ecdsa_encryption`; the legacy `ed25519` mode converts Ed25519 keys to X25519 and uses HKDF info `ed25519_encryption`. E2EE v1 has no AAD and no replay protection. New clients SHOULD use ACI E2EE v2 without `X-Signing-Algo`.

The legacy signature endpoint is:

```text
GET /v1/signature/{chat_id}
```

It returns the historical signed pair:

```json
{
  "text": "{request_hash}:{response_hash}",
  "signature": "<hex>",
  "signing_address": "<0x-address>",
  "signing_algo": "ecdsa" | "ed25519"
}
```

Its hash semantics remain legacy-compatible. New verifiers SHOULD use inference receipts instead.

Compatibility-only errors:

- `e2ee_invalid_signing_algo`

## 14. References

- dstack vLLM proxy compatibility API.
- dstack KMS key sealing and app identity model.
- Intel TDX and AMD SEV-SNP attestation.
- RFC 8785 JSON Canonicalization Scheme.
- RFC 8032 Ed25519 signature scheme.
- Sigstore or equivalent build provenance systems.
- Trustworthy workload identity work in RATS, WIMSE, and related confidential-computing systems informed the `workload_id` plus `workload_keyset_digest` shape.
