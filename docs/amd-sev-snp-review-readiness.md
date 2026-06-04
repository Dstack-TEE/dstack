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
- VMM-provided SNP launch inputs in `.sys-config.json` so KMS self/app auth can recompute the same launch measurement used by QEMU.
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

## Manual dstack E2E smoke status

An additional manual smoke was attempted on the SNP host (`chris@173.234.27.162`) using the PR branch, release-built `dstack-vmm`/`supervisor`/`dstack-kms`, QEMU 10.0.2, and the SNP-capable OVMF at `/opt/AMDSEV/usr/local/share/qemu/OVMF.fd`. The reusable version of that smoke is checked in at `test-scripts/snp-e2e-smoke.sh` for follow-up debugging on SNP hosts.

That smoke exposed and fixed several VMM/KMS-auth integration issues before the guest reached KMS:

- `.sys-config.json` did not include the `sev_snp_measurement` launch input object needed by KMS SNP `BootInfo` recomputation.
- The VMM launch path required `metadata.json.rootfs_hash`, while the released `dstack-0.5.11` images carry the rootfs hash in `dstack.rootfs_hash=...` on the kernel cmdline.
- The VMM SNP QEMU path now uses the SNP measurement CPU model (`EPYC-v4`) and confidential virtio PCI options (`disable-legacy=on,iommu_platform=true`) for SNP-launched virtio devices, matching the host's working SNP launch posture more closely.

After those fixes, the manual smoke progressed through full dstack-managed SNP guest boot, KMS self-bootstrap, app guest boot, app quote verification, and `GetAppKey` release. Additional smoke/debug fixes made the path work end-to-end:

- Minimal guest boot now keeps DNS usable when `systemd-resolved`/`chronyd` are unavailable early in smoke boots and detects `sev-guest` before trying the TDX guest module.
- SNP guests skip TDX-only `mr_config_id` and app-info RTMR decoding while still preserving non-SNP behavior.
- Configfs TSM report collection falls back to the SEV-SNP extended-report ioctl when configfs does not carry certificate collateral.
- If guest evidence still lacks ASK/VCEK collateral, the verifier fetches AMD KDS ARK/ASK/VCEK using the report `chip_id` and reported TCB, then verifies the signed report fail-closed.
- KMS measurement recomputation now uses the image's original kernel cmdline as the measurement base before appending `docker_compose_hash`, `rootfs_hash`, and `app_id`, matching the VMM QEMU `-append` path.

Sanitized smoke result:

```text
remote_host=chris@173.234.27.162
qemu_version=10.0.2
ovmf_sha256=67e7a7027437823e9c166a60d00666d5d5391e13050488cad5cc2acd913fab4a
image=dstack-dev-0.5.11-snp-dnsfix
platform=amd-sev-snp
vmm_branch=feat/amd-sev-snp-conversion + local smoke fixes
kms_guest=booted SNP Linux/userspace and started dstack-kms
app_guest=booted SNP Linux/userspace and requested app keys
kms_auth=/bootAuth/kms 200 and /bootAuth/app 200
tcb_status=OutOfDate in this lab host policy run
failure_gate=default UpToDate-only policy rejected release with "tcb_status is not allowed"
success_gate=explicit lab allowlist ["UpToDate", "OutOfDate"] released GetTempCaCert and GetAppKey
kms_metrics=dstack_kms_attestation_requests_total 1, dstack_kms_attestation_failures_total 0
no_secret_material_logged=true
```

This means the PR now has live SNP report proof, live golden-vector measurement proof, release-gate unit/integration coverage, and a manual full dstack-managed SNP guest -> KMS `GetAppKey` hardware E2E proof. The success run required an explicit lab-only TCB allowlist because this host reports `OutOfDate`; production defaults remain fail-closed (`UpToDate` only).

### Hardware smoke portability notes

The checked-in smoke is enough to reproduce the proven KMS/app-key flow on a compatible SNP host, but reviewers should treat the guest image/kernel as part of the hardware matrix:

- Known-good full E2E host: `chris@173.234.27.162` with AMDSEV QEMU 10.0.2, the SNP-capable OVMF above, and `dstack-dev-0.5.11-snp-dnsfix`.
- A separate local SNP host can run SNP Linux guests, but the stock `meta-dstack` v0.5.11 `6.9.0-dstack` kernel stops after OVMF/EFI loads kernel+initrd and QEMU reports `cpus are not resettable, terminating`, even when using QEMU 10.0.2.
- On that same local host, a newer Lit SNP guest kernel (`6.13.0-snp-guest-ffd294d346d1`) reaches Linux/SNP markers, which isolates that local failure to the dstack guest image/kernel compatibility layer rather than Chipotle/KMS/auth policy or basic host SNP enablement.

Practical implication for reviewers/testers: first run `test-scripts/snp-e2e-smoke.sh` unchanged and confirm it reaches `SNP_KMS_CONTAINER_STARTED` / `SNP_APP_CONTAINER_STARTED` before substituting a real app workload. If the smoke stops after `EFI stub: Loaded initrd ...` with `cpus are not resettable`, use a host/image/kernel that is known to boot dstack under SNP (or build a coherent newer `meta-dstack` guest image with matching kernel, modules, initramfs, rootfs, and verity metadata) before debugging app-level behavior.

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
