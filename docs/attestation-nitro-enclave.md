# Dstack Nitro Enclave Attestation Flow (NSM)

> **AWS Nitro Support:** Attestation verification is fully implemented. For AWS deployment options, [book a call](https://calendly.com/aspect-ux/30min) with our team.

This document describes how dstack produces and verifies attestation on AWS
Nitro Enclaves using the NSM attestation document. It follows the
implementation in `dstack-attest` and `nsm-qvl`.

## Components
- NSM attestation generator: `nsm-attest::get_attestation`
- Verifier: `dstack-attest` + `nsm-qvl`

## Attestation Creation (enclave side)
1. **Collect report_data** (64 bytes), optionally bound to RA TLS pubkey.
2. **Request NSM attestation** with user_data = report_data:
   `nsm_attest::get_attestation(report_data)`.
3. **Bundle** into `DstackNitroQuote { nsm_quote }`.
4. **Include config** derived from PCRs:
   `os_image_hash = sha256(PCR0 || PCR1 || PCR2)` (all zeros if PCRs are zero).

The NSM attestation document (COSE_Sign1 payload) includes:
- `module_id`, `digest`, `timestamp`
- `pcrs` map
- signing `certificate` and `cabundle`
- optional `user_data`, `nonce`, `public_key`

## Attestation Verification (verifier side)
Verification runs in `Attestation::verify_with_time`:

### COSE and document checks (nsm-qvl)
1. **Parse COSE_Sign1** and require `alg = ES384 (-35)`.
2. **Validate COSE critical headers** (`crit`) if present.
3. **Parse attestation document** from payload and enforce:
   - `digest == "SHA384"`
   - PCR lengths are 48 bytes
   - freshness window against `now`

### Certificate chain and signature
4. **Verify cert chain** to `AWS_NITRO_ENCLAVES_ROOT_G1`.
5. **Verify COSE signature** using the leaf certificate P-384 key.
6. **Key usage sanity** on leaf cert (if present):
   - must allow `digitalSignature`
   - must not allow `keyCertSign` or `cRLSign`

### Optional CRL verification
`nsm-qvl` exposes async CRL verification via:
`verify_attestation_with_crl(..., enable_crl, ...)`.
This is **disabled by default** in `dstack-attest` because CRL fetch from
S3 may return 403. The caller can enable CRL explicitly.

### Dstack-specific checks
7. **Match user_data** to `report_data`.
8. **Decode PCRs** and return verified report.

## Output
The verifier returns `DstackVerifiedReport::DstackNitroEnclave` containing:
- `module_id`
- `pcrs` (PCR0/1/2)
- `user_data` (report_data)
- `timestamp`

## KMS key release

Key release to a Nitro Enclave is gated locally by `nitro_enclave_key_release`
in `kms.toml`, which defaults to `false`:

```toml
[core]
nitro_enclave_key_release = true
```

This gate sits *after* full attestation verification and after the external auth
policy decision, so both must also pass. It mirrors `sev_snp_key_release` and
`aws_nitro_tpm_key_release`: platforms whose confidentiality guarantee does not
come from a CPU the way Intel TDX's does are opt-in, so that enabling one never
implies another.

Two properties of this platform are worth knowing before enabling it:

- The AWS hypervisor is in the TCB. The NSM document is signed by an AWS root,
  and PCR0/1/2 measure the enclave image, but there is no hardware memory
  encryption isolating the enclave from the platform operator.
- dstack extends no runtime measurement register on this variant, so `app_id`
  and `instance_id` in the attestation come from an event list that nothing
  replays against a quoted register. `os_image_hash` and `compose_hash`, which
  are derived from the signed PCRs, are unaffected.

## Relevant Code
- `dstack-attest/src/attestation.rs`
- `nsm-qvl/src/verify.rs`
- `kms/src/main_service.rs` (`ensure_key_release_allowed`)
