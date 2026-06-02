# AMD SEV-SNP Review Readiness

This branch adds AMD SEV-SNP support and now includes a controlled, explicitly opt-in KMS key/cert release gate for SNP.

## Current review boundary

Implemented and intended for review:

- AMD SEV-SNP evidence plumbing in the v1 attestation format.
- SNP report verification with AMD Genoa ARK/ASK/VCEK chain verification.
- Report-data challenge binding and fail-closed report policy checks.
- SNP launch-measurement recomputation from OVMF/kernel/initrd/cmdline inputs.
- KMS SNP `BootInfo` construction from verified report measurement, chip id, launch inputs, TCB status, and advisory ids.
- Auth-policy evaluation through the existing KMS auth flow.
- Controlled SNP key/cert release guarded by both external auth policy and local KMS config.
- Onboarding attestation-info reporting for SNP identity fields.
- VMM explicit `platform = "amd-sev-snp"` launch path.

Default posture:

- SNP app key release, KMS/root/temp CA key release, and app certificate release are still disabled by default.
- Operators must explicitly set `[core.sev_snp_key_release].enabled = true` before any SNP `BootInfo` can release sensitive material.
- KMS startup rejects `enabled = true` unless `enforce_self_authorization = true`, so the self-authorized `GetTempCaCert` path cannot silently bypass the SNP release gate in production config.
- Even with the local KMS gate enabled, the existing auth API must first allow the verified SNP `BootInfo` for the app/KMS identity.

## Fail-closed policy summary

- `platform = "auto"` remains conservative while SNP is experimental; operators must explicitly set `platform = "amd-sev-snp"` to launch an SNP guest.
- SNP launch measurement is recomputed from trusted KMS config/input and compared to the hardware-verified report measurement.
- SNP `BootInfo.tcb_status` is verifier-derived from signed AMD SNP report TCB fields:
  - `UpToDate` only when current/reported/committed/launch TCB versions all match.
  - `OutOfDate` otherwise.
- SNP advisory ids are propagated from verifier output into `BootInfo`; currently this list is explicit and empty because the AMD report/VCEK evidence used here does not carry a direct advisory-list field.
- `auth-simple` defaults remain strict: only `UpToDate` is accepted and any advisory id is denied unless explicitly allowlisted.
- The local KMS release gate mirrors that strict default:
  - `[core.sev_snp_key_release].enabled = false` by default.
  - `allowed_tcb_statuses = ["UpToDate"]` by default.
  - `allowed_advisory_ids = []` by default, so any advisory remains fail-closed unless explicitly allowlisted.

Example opt-in gate:

```toml
[core.sev_snp_key_release]
enabled = true
allowed_tcb_statuses = ["UpToDate"]
allowed_advisory_ids = []
```

Sensitive release surfaces using this gate:

- `GetAppKey`: app disk/env/k256 key material.
- `GetKmsKey`: temp CA key plus root CA/k256 key material for authorized KMS transfer.
- `SignCert`: app certificate chain signing.
- `GetTempCaCert`: temp CA material for self-authorized KMS instances.

## Live golden-vector proof

The ignored live regression test cross-checks dstack's pure Rust SNP measurement recomputation against `sev-snp-measure` on the SNP-capable host.

Command:

```bash
cargo test -p dstack-kms --all-features recomputation_matches_sev_snp_measure_live_golden_vector -- --ignored --nocapture
```

Latest local proof:

```text
DSTACK_SEV_SNP_MEASURE_GOLDEN_VECTOR_BEGIN
utc=2026-06-02T19:49:14Z
host=dedicated-m24-fork
uname=Linux dedicated-m24-fork 6.11.0-rc3-snp-host-85ef1ac03941 #2 SMP Sat May  3 11:42:34 EDT 2025 x86_64 GNU/Linux
sev_snp_measure=/usr/local/bin/sev-snp-measure
sev_snp_measure_version=sev-snp-measure 0.0.10
ovmf_path=/opt/AMDSEV/usr/local/share/qemu/OVMF.fd
ovmf_sha256=67e7a7027437823e9c166a60d00666d5d5391e13050488cad5cc2acd913fab4a
kernel_fixture_sha256=3f73f96a321b35a4c5561b05cfa6e9b5c573159380d37abe76f9a8ebe113a72e
initrd_fixture_sha256=e8790816224329cd76675c2aba4e62e885b5a4e0ec056227da70e775191d6d56
vcpus=2
vcpu_type=EPYC-v4
guest_features=0x1
append=console=ttyS0 loglevel=7 docker_compose_hash=2222222222222222222222222222222222222222222222222222222222222222 rootfs_hash=3333333333333333333333333333333333333333333333333333333333333333 app_id=1111111111111111111111111111111111111111
sev_snp_measurement=6497fb9f90dc4a322228a8a5eb14742e09067bc44c184c2068d583ef628b5bae8c6cf15d91fe1bc0b7a8cbcc575be370
cargo_live_test=cargo test -p dstack-kms --all-features recomputation_matches_sev_snp_measure_live_golden_vector -- --ignored --nocapture
cargo_live_test_result=passed locally on this host at 2026-06-02T19:49:14Z
DSTACK_SEV_SNP_MEASURE_GOLDEN_VECTOR_END
```

## Guest attestation proof

A prior SNP guest smoke proof confirmed the guest kernel exposed SEV-SNP report support and could produce a report containing the expected challenge bytes.

```text
Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP
SEV: SNP running at VMPL0.
sev-guest sev-guest: Initialized SEV guest driver (using vmpck_id 0)
DSTACK_SEV_SNP_ATTESTATION_PROOF_BEGIN
source=configfs-tsm
report_size=1184
report_data_offset=80
report_contains_expected_report_data=true
DSTACK_SEV_SNP_ATTESTATION_PROOF_END
```

## Validation commands

Run locally for this review-ready staging branch:

```bash
cargo fmt --all
cargo test -p dstack-kms --all-features
cargo test -p dstack-attest --all-features
cargo test -p dstack-vmm --all-features
cargo check --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings --allow unused_variables
git diff --check
cd kms/auth-simple && npx oxlint . && npx vitest run
```

## Remaining production follow-up

The release gate is controlled and production-oriented, but AMD advisory/revocation collateral is still limited by the evidence source available here: SNP reports/VCEKs do not directly carry an advisory list, so `advisory_ids` currently propagates as an explicit empty list. Future collateral fetchers can populate this field and will be denied by both auth-simple and the local KMS release gate unless each advisory is explicitly allowlisted.
