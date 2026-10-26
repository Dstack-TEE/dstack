<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# TPM 2.0 quote sample fixture

`tpm_quote_sample.bin` is a captured TPM quote body — the raw `TPMS_ATTEST`
structure that the TPM `Quote` command signs, i.e. the `message` field of a
`TpmQuote` (see `TpmContext::create_quote` in `src/lib.rs`). It is a small,
self-contained golden vector for exercising quote-message parsing without a live
vTPM.

## Format

The bytes are a marshaled `TPMS_ATTEST` with a `TPMS_QUOTE_INFO` attested body,
in the layout parsed by `parse_tpm_attest` in `tpm-qvl/src/verify.rs`:

| Field | Value |
| --- | --- |
| `magic` | `0xff544347` (`TPM_GENERATED_VALUE`) |
| `type` | `0x8018` (`TPM_ST_ATTEST_QUOTE`) |
| `qualifiedSigner` | SHA-256 name (`TPM_ALG_SHA256`, 32-byte digest) |
| `extraData` (qualifying data) | `0x12345678` (4-byte placeholder nonce) |
| `clockInfo` | `resetCount = 16`, `restartCount = 0`, `safe = true` |
| `attested.pcrSelect` | SHA-256 bank, PCRs 0, 1, 2 |
| `attested.pcrDigest` | 32-byte SHA-256 digest over the selected PCRs |

Total length: 117 bytes.

## Provenance

The in-tree history does not record the capturing host, image, or tool for this
fixture, so nothing beyond the decoded structure above is asserted here. The
short 4-byte qualifying data (`0x12345678`) rather than a real 32-byte report
nonce, and the generic PCR 0/1/2 selection, indicate a hand-captured or
synthetic sample rather than a full dstack attestation (dstack's own policy is
SHA-256 PCRs 0, 2, 14 — see `dstack_pcr_policy` in `src/lib.rs`).

## Refreshing

If regenerated, capture the raw `TpmQuote.message` bytes from a `Quote` command
and keep this description in sync with the new `extraData`, bank, and PCR
selection. The file is licensed `CC0-1.0` via `REUSE.toml`.
