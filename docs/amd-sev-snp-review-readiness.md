# AMD SEV-SNP Review Readiness

This branch stages AMD SEV-SNP support for review while keeping SNP key/cert release fail-closed.

## Current review boundary

Implemented and intended for review:

- AMD SEV-SNP evidence plumbing in the v1 attestation format.
- SNP report verification with AMD Genoa ARK/ASK/VCEK chain verification.
- Report-data challenge binding and fail-closed report policy checks.
- SNP launch-measurement recomputation from OVMF/kernel/initrd/cmdline inputs.
- KMS SNP `BootInfo` construction from verified report measurement, chip id, launch inputs, TCB status, and advisory ids.
- Dry-run auth-policy evaluation through existing KMS auth flow.
- Onboarding attestation-info reporting for SNP identity fields.
- VMM explicit `platform = "amd-sev-snp"` launch path.

Intentionally not enabled yet:

- SNP app key release.
- SNP KMS/root/temp CA key release.
- SNP app certificate/signing certificate release.
- Production SNP key release policy.

The KMS still rejects SNP `BootInfo` before returning secrets or certificates. Treat this branch as review-ready staging, not production SNP key release.

## Fail-closed policy summary

- `platform = "auto"` remains conservative while SNP is experimental; operators must explicitly set `platform = "amd-sev-snp"` to launch an SNP guest.
- SNP launch measurement is recomputed from trusted KMS config/input and compared to the hardware-verified report measurement.
- SNP `BootInfo.tcb_status` is verifier-derived from signed AMD SNP report TCB fields:
  - `UpToDate` only when current/reported/committed/launch TCB versions all match.
  - `OutOfDate` otherwise.
- SNP advisory ids are propagated from verifier output into `BootInfo`; currently this list is explicit and empty because the AMD report/VCEK evidence used here does not carry a direct advisory-list field.
- `auth-simple` defaults remain strict: only `UpToDate` is accepted and any advisory id is denied unless explicitly allowlisted.

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

## Next milestone after review

Production SNP key release should be a separate milestone. Before removing the SNP release guards, define and test the final key-release policy contract, including revocation/advisory collateral handling, chip identity treatment, app/compose/rootfs binding, and every sensitive KMS output path.
