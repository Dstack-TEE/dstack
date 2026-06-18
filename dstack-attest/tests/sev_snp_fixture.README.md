<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# AMD SEV-SNP attestation test fixture

Real AMD SEV-SNP attestation captured from a live dstack CVM, used by
`tests/sev_snp_verify.rs` for an offline end-to-end verification test.

## Files

| File | Description |
| --- | --- |
| `sev_snp_attestation.bin` | `VersionedAttestation` (SCALE V0) — the full attestation as produced inside the CVM. Contains the 1184-byte SNP report + the `mr_config` document. |
| `sev_snp_ask.pem` | AMD SEV intermediate cert (ASK, `CN=SEV-Milan`) for the chip that signed the report. |
| `sev_snp_vcek.pem` | Per-chip VCEK (`CN=SEV-VCEK`) for the report's `chip_id` + reported TCB. |

The AMD root key (ARK) is **not** bundled — `sev-snp-qvl` uses its built-in ARK,
so the test verifies the full chain ARK → ASK → VCEK → report signature with
nothing fetched from AMD KDS (fully offline / deterministic).

## Provenance

- Captured 2026-06-17 from a dstack SEV-SNP CVM (app `attest-test`) running the
  merged `dstack-nvidia-0.6.0.a2` image on an AMD EPYC Milan host.
- Generated inside the guest with:
  ```
  dstack-util quote-report \
    --report-data 6174746573742d746573742d666978747572652d32303236 \
    --output attest.json
  ```
  (`report-data` = ASCII `attest-test-fixture-2026`, the marker the test asserts.)
- The `attestation` hex field of that JSON was decoded to `sev_snp_attestation.bin`.
- ASK/VCEK were fetched from AMD KDS (`https://kdsintf.amd.com/vcek/v1/Milan/...`)
  for the report's `chip_id` and TCB and pinned here so the test stays offline.

## Verified values (informational)

```
chip_id:    38d174589d2dff97a6d40cb9f9d90b9507c027491219083cef3ce73e
            d18f7289142d941ad61eabecd27d25f268c1095d665f6001358e98a4769c82734a6bb877
measurement 7f51e17f72a04d5422cb2c00998166536019a217376f3aa45a630e59c805a599...
host_data:  783f0057820acb99249af56cc3b07b4e8d80f65183167cba9cf437bb680f742f
tcb_status: OutOfDate   (this host's firmware TCB; acceptable per KMS allowed_tcb_statuses)
```

## Refreshing

VCEK/ASK are immutable for a given chip + TCB, so these never expire. If the
report itself is regenerated (e.g. different host or firmware), re-capture all
three files together — the VCEK must match the new report's `chip_id`/TCB.
