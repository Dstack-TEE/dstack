# Dstack GCP Attestation Flow (GCP TDX + TPM)

This document describes how dstack produces and verifies attestation on GCP using
TDX plus a TPM quote. It follows the implementation in `dstack-attest`.

## Components
- TDX quote generator: `tdx-attest::get_quote`
- TDX event log reader: `cc-eventlog::tdx::read_event_log`
- TPM quote generator: `tpm-attest::TpmContext::create_quote`
- Verifier: `dstack-attest` + `dcap-qvl` + `tpm-qvl`

## Attestation Creation (guest side)
1. **Collect report_data** (64 bytes), optionally bound to RA TLS pubkey.
2. **Generate TDX quote** via `tdx-attest::get_quote(report_data)`.
3. **Read TDX event log** via `cc-eventlog::tdx::read_event_log()`.
4. **Compute TPM qualifying data** as `sha256(tdx_quote)`.
5. **Create TPM quote** with qualifying data and dstack PCR policy:
   `tpm_attest::TpmContext::create_quote(qualifying_data, policy)`.
6. **Bundle** into `DstackGcpTdxQuote { tdx_quote, tpm_quote }`.
7. **Include config** from `/dstack/.host-shared/.sys-config.json`.

## Attestation Verification (verifier side)
Verification runs in `Attestation::verify_with_time` and splits into TDX + TPM.

### TDX verification
1. **Fetch TDX collateral** and verify quote:
   `dcap_qvl::collateral::get_collateral_and_verify(quote, pccs_url)`.
2. **Validate TCB**:
   - Debug mode must be off.
   - `mr_signer_seam` must be all-zero.
3. **Replay runtime events** to compute RTMR3 and compare with quote RTMR3.
4. **Check report_data** in TD report equals the attestation `report_data`.

### TPM verification
1. **Fetch TPM collateral** and verify quote:
   `tpm_qvl::get_collateral_and_verify(tpm_quote)`.
2. **Replay runtime events** to compute runtime PCR and compare with quoted PCR.
3. **Check qualifying data** equals `sha256(tdx_quote)`.

### Optional RA TLS binding
If the verifier provides a RA TLS pubkey, it enforces:
`report_data == QuoteContentType::RaTlsCert.to_report_data(pubkey)`.

## Output
The verifier returns `DstackVerifiedReport::DstackGcpTdx` containing:
- `tdx_report` (verified TDX report and collateral info)
- `tpm_report` (verified TPM quote and PCRs)

## Relevant Code
- `dstack-attest/src/attestation.rs`
