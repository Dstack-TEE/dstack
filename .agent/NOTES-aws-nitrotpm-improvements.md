# AWS NitroTPM improvement intent (operator notes)

Status: **decided 2026-07-13 — implementing on aws-attestation-platform-spec**

## Decisions (locked)

1. **MR_CONFIG → PCR8** (dedicated OS PCR; not cmdline/PCR4)
2. **Config delivery: S1 shared disk only** (no UKI cmdline rewrite)
3. **K1: keep `system-ready` as replay/auth boundary** (single PCR14 lane)
4. **`check_kms` pins early MR (boot-mr-done)** — same as bare TDX
5. **N2: single emit API** (no launch/runtime split; all events → PCR14 sha384)
6. **Work on AWS PR branch; push commits there**
7. **#777 empty TPM key-provider id: already merged** — rebase/include as needed

## Work items

1. No runtime config via UKI cmdline → shared disk + PCR8
2. Unified `os_image_hash` = sha256(sha256sum.txt) + measurement.aws bind PCR4/7/12
3. PCR8 for mr_config-like binding
4. Remove `aws-pcr14-fault-injection`
5. `check_kms` only `mrAggregated` (early / boot-mr-done)
6. Remove GetAppKey v2 recipient + GetQuote `attestation_options`
7. Single event PCR14; drop PCR23 runtime split; N2 one emit API
