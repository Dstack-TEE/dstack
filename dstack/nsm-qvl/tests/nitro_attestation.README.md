<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# AWS Nitro Enclave NSM attestation test fixture

A real AWS Nitro Enclave NSM attestation document, used by
`tests/verify_test.rs` for offline parsing and an end-to-end verification of the
COSE Sign1 signature and certificate chain (`src/verify.rs`).

## Files

| File | Description |
| --- | --- |
| `nitro_attestation.bin` | Raw NSM attestation response (4682 bytes). Its COSE_Sign1 payload is the CBOR-encoded `AttestationDocument` — module id, digest, timestamp, PCRs, the signing certificate, and the cabundle. |

The document is signed with ECDSA P-384 / SHA-384 (COSE alg `-35`, ES384; a
fixed 96-byte signature). `tests/verify_test.rs` locates the `COSE_Sign1` array
by scanning for its CBOR marker (`0x84 0x44`), so the short framing prefix ahead
of it in the `.bin` is tolerated and no exact offset is assumed.

The AWS Nitro Enclaves G1 root CA is **not** bundled here — the verifier uses the
root embedded in the crate (`certs/AWS_NitroEnclaves_Root-G1.pem`, exposed as
`AWS_NITRO_ENCLAVES_ROOT_G1`), and the cabundle's own root (index 0) is dropped so
trust is anchored only on the verifier-provided root. The full chain therefore
verifies offline. CRL revocation checking is exercised only when the test runs
with `TEST_FETCH_CRL` set (that path reaches AWS CRL endpoints over the network).

## Provenance

- Captured from a live AWS Nitro Enclave on EC2 instance `i-0827e799ec9232d44`
  in `us-east-1` — values read directly out of the document's `module_id` and the
  signing certificate subject, not asserted externally.
- The signing certificate is valid `2025-12-25 13:15:34Z` – `2025-12-25 16:15:37Z`
  (NSM leaf certs are short-lived, ~3h), which dates the capture to
  **2025-12-25**; the document `timestamp` falls inside that window.
- Added to the repo alongside the `nsm-attest` crate.
- The exact capture command, host operator, and the enclave workload were **not
  recorded** in-repo — treat those as unknown.

## Refreshing

NSM leaf certificates expire a few hours after issuance, so this fixture's
certificate chain is **already past its wall-clock validity window**. The verify
test compensates by pinning `now` to the document's own `timestamp`
(`Some(attestation_time)`) instead of the system clock, so the fixture stays
deterministic and never "expires" for the offline test.

To refresh, capture a new NSM attestation document from a Nitro Enclave, drop it
in as `nitro_attestation.bin`, and confirm `cargo test -p nsm-qvl` passes — the
tests re-derive the pinned time from the new document, so no other edits are
needed. Only the `TEST_FETCH_CRL` path additionally depends on AWS CRL endpoints
being reachable.
