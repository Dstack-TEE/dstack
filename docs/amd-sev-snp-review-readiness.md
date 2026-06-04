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

After those fixes, the manual smoke progressed through full dstack-managed SNP guest boot and KMS self-bootstrap on the known-good remote host. Additional smoke/debug fixes made the host/KMS side reach the app-key boundary:

- Minimal guest boot now keeps DNS usable when `systemd-resolved`/`chronyd` are unavailable early in smoke boots and detects `sev-guest` before trying the TDX guest module.
- SNP guests skip TDX-only `mr_config_id` and app-info RTMR decoding while still preserving non-SNP behavior.
- Configfs TSM report collection falls back to the SEV-SNP extended-report ioctl when configfs does not carry certificate collateral.
- If verifier-side evidence still lacks ASK/VCEK collateral, the verifier can fetch AMD KDS ARK/ASK/VCEK using the report `chip_id` and reported TCB, then verify the signed report fail-closed.
- KMS measurement recomputation now uses the image's original kernel cmdline as the measurement base before appending `docker_compose_hash`, `rootfs_hash`, and `app_id`, matching the VMM QEMU `-append` path.

Latest sanitized remote smoke result with PR head `38b02d7c`:

```text
remote_host=chris@173.234.27.162
host_kernel=Linux 6.11.0-rc3-snp-host-85ef1ac03941
qemu_version=10.0.2
ovmf_sha256=67e7a7027437823e9c166a60d00666d5d5391e13050488cad5cc2acd913fab4a
image=dstack-dev-0.5.11-snp-dnsfix
platform=amd-sev-snp
kms_guest=booted SNP Linux/userspace and started dstack-kms
kms_marker=SNP_KMS_CONTAINER_STARTED / KMS runtime ready
kms_metrics=dstack_kms_attestation_requests_total 2, dstack_kms_attestation_failures_total 0
app_guest=booted SNP Linux/userspace and reached dstack-prepare.sh
app_marker=SNP_APP_CONTAINER_STARTED not reached
failure_boundary=app guest GetTempCaCert/GetAppKey attestation validation
failure_error=amd sev-snp cert_chain must contain either ASK and VCEK certificates or one kernel certificate table auxblob
no_secret_material_logged=true
```

This means the PR has live SNP report proof, live golden-vector measurement proof, release-gate unit/integration coverage, and hardware smoke proof through dstack-managed SNP KMS boot plus app guest key-request boundary. The remaining full `GetAppKey` smoke blocker is a guest image/tooling skew: the app VM uses the `dstack-util`/`dstack-attest` embedded inside the released `meta-dstack` v0.5.11 guest image, while the host/KMS binaries are built from PR #703. Rebuilding only `dstack-vmm`, `supervisor`, and `dstack-kms` is not enough for a fresh tester to exercise the PR's guest-side cert-chain/KDS fallback.

### Fresh SNP host / image requirements

The checked-in smoke is enough to reproduce the current boundary on a compatible SNP host, but reviewers should treat the guest image/kernel/userspace as part of the test matrix:

- Known-good host for reaching KMS and app `dstack-prepare.sh`: `chris@173.234.27.162` with AMDSEV QEMU 10.0.2, the SNP-capable OVMF above, and `dstack-dev-0.5.11-snp-dnsfix`.
- That released image is **not** a coherent PR #703 image: its guest-side `dstack-util`/`dstack-attest` may reject SNP evidence before the newer PR fallback paths can help.
- A separate local SNP host can run SNP Linux guests, but the stock `meta-dstack` v0.5.11 `6.9.0-dstack` kernel stops after OVMF/EFI loads kernel+initrd and QEMU reports `cpus are not resettable, terminating`, even when using QEMU 10.0.2.
- On that same local host, a newer Lit SNP guest kernel (`6.13.0-snp-guest-ffd294d346d1`) reaches Linux/SNP markers, which isolates that local failure to the dstack guest image/kernel compatibility layer rather than Chipotle/KMS/auth policy or basic host SNP enablement.

Practical implication for reviewers/testers on a fresh box:

1. Install/use an AMDSEV QEMU 10.x build and the matching SNP-capable OVMF.
2. Build the PR binaries with `cargo build --release -p dstack-vmm -p supervisor -p dstack-kms`.
3. Run `test-scripts/snp-e2e-smoke.sh` unchanged and first confirm it reaches `SNP_KMS_CONTAINER_STARTED` and the app guest key-request boundary.
4. For full `SNP_APP_CONTAINER_STARTED` / `GetAppKey` success, use or publish a coherent `meta-dstack` guest image whose kernel, modules, initramfs, rootfs, verity metadata, and guest userspace include the same PR #703 `dstack-util`/`dstack-attest` SNP cert-chain/KDS fallback code. Do not try to inject only a replacement `dstack-util` into the stock image; that experiment changed the initramfs/measurement enough to regress boot.
5. Only after the baseline smoke reaches the app success marker should testers swap the simple app workload for Chipotle.

If the smoke stops after `EFI stub: Loaded initrd ...` with `cpus are not resettable`, use a host/image/kernel that is known to boot dstack under SNP before debugging app-level behavior. If it reaches `Requesting app keys from KMS` and fails with the cert-chain error above, rebuild/use a coherent PR guest image rather than changing KMS release policy.

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
