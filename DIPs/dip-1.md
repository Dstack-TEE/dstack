---
dip: 1
title: Self-Describing Identifiers for Attestation ReportData
status: Draft
author: Hang Yin <hangyin@phala.network>
created: 2025-09-13
---

## Abstract

This DIP defines `dip1`, a compact self-describing identifier that fits within the 64-byte Intel DCAP `reportdata` field. A fixed scope prefix (`dip1`) is followed by an algorithm label and either a digest or inline payload. The canonical form for hashed payloads is:

```
dip1:<algo>:<base64url-digest>
```

The actual payload, which encodes purpose/content-type metadata, is transmitted or embedded separately. An inline variant allows very small payloads to fit entirely inside the identifier.

## Motivation

Attestation workflows need a short, unambiguous identifier for application-defined data that can be carried inside `reportdata`. Without such structure, a verifier that receives a TDX quote can only check the quote envelope itself; it has no portable way to interpret what the embedded `reportdata` is supposed to prove.

By reserving the `dip1` prefix and standardising how algorithms and payload descriptors appear in the identifier, we make `reportdata` self-describing without exceeding the 64-byte budget. A verification platform can inspect the `dip1` string to learn which hash algorithm was used and what content type the payload represents, then route the quote to specialised validation plugins whenever they are available.

## Specification

The general grammar is:

```
dip1:<algo>:<data>
```

* `dip1`: Literal ASCII prefix reserving the namespace for this format.
* `<algo>`: Lowercase token indicating how to interpret `<data>`.
* `<data>`: Algorithm-dependent ASCII payload.

### Hashed payloads

For cryptographic digests:

```
dip1:sha256:<base64url-digest>
```

* `<base64url-digest>` is the URL-safe Base64 (unpadded) encoding of a SHA-256 digest (43 characters).
* The digest is computed over a canonical payload byte string supplied alongside the attestation evidence. The payload SHOULD begin with its own content-type prefix, e.g. `ratls-pubkey:<hex>`.
* Other algorithms MAY be supported in the future, but **SHA-256 is normative** for interoperability.

### Inline payloads

Short payloads can be embedded directly using the reserved `inline` algorithm:

```
dip1:inline:<type>:<base64url-payload>
```

* `<type>`: Short token (≤8 characters recommended) describing the payload, e.g. `ra-pk`.
* `<base64url-payload>`: URL-safe Base64 (unpadded) encoding of the raw payload bytes.
* Inline payloads MUST keep the entire identifier within 64 bytes.

For maximal brevity, the `inline` algorithm MAY be omitted. The double-colon form is an alias for the inline variant:

```
dip1::<type>:<base64url-payload>
```

### Size considerations

For the SHA-256 variant:

* Prefix + separators: `dip1:` (5 chars) + second colon (1 char)
* Algorithm token: `sha256` (6 chars)
* Digest: 43 chars

Total: 55 characters, fitting comfortably within the 64-byte requirement.

For inline payloads, the combined length of `<type>` and `<base64url-payload>` MUST keep the string within 64 characters.

## Rationale

* Fixed namespace (`dip1`) prevents collisions with other project-defined encodings.
* Algorithm tag enables future extensions without ambiguity.
* Separating purpose metadata into the payload simplifies domain separation and allows richer payload structures.
* Base64url encoding maximises information density while remaining safe for textual channels.

## Implementation Notes

* Existing digest libraries can be reused by serialising payloads as `<algo>:<base64url>` before prefixing with `dip1:`.
* Canonical payload serialisation (e.g. `content-type:value`) should be specified by higher-level protocols.
* Inline payloads are best suited for small tokens such as capability flags or truncated keys.

## Security Considerations

* Security strength is determined by the chosen algorithm (SHA-256 recommended).
* Payload canonicalisation must be consistent to avoid digest mismatches.
* Inline payloads are not hashed; consumers must validate them according to application policy.

## Test Vectors

| Case                      | Identifier                                                      | Payload (when hashed)                                                                           |
| ------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| SHA-256 of payload        | `dip1:sha256:HmdI7tOxX-IxZngR8Aok9miZ4A5DzUj-HW-VUZ1Et0E`        | `ratls-pubkey:ee218f44a5f0a9c3233f9cc09f0cd41518f376478127feb989d5cf1292c56a01`                |
| Inline ra-pk sample       | `dip1:inline:ra-pk:LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ` | _Embedded in identifier_                                                                        |
| Inline alias (short form) | `dip1::ra-pk:LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ`       | _Embedded in identifier_                                                                        |

## References

* [Intel SGX DCAP Attestation Architecture](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-software-guard-extensions-data-center-attestation-primitives.html)
* [RFC 6920: Naming Things with Hashes (ni://)](https://www.rfc-editor.org/rfc/rfc6920)
* [W3C Subresource Integrity (SRI)](https://www.w3.org/TR/SRI/)

## Copyright

Copyright and related rights waived via CC0.
