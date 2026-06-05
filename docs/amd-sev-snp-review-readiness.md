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

Latest sanitized remote smoke result with PR-built host binaries and a coherent `MACHINE = "sev-snp"` guest image:

```text
remote_host=chris@173.234.27.162
host_kernel=Linux 6.11.0-rc3-snp-host-85ef1ac03941
qemu_version=10.0.2
ovmf_sha256=67e7a7027437823e9c166a60d00666d5d5391e13050488cad5cc2acd913fab4a
image=dstack-dev-0.6.0
platform=amd-sev-snp
image_kernel=Linux 6.18.24-dstack with CONFIG_AMD_MEM_ENCRYPT=y, CONFIG_SEV_GUEST=y, CONFIG_TSM_REPORTS=y
kms_guest=booted SNP Linux/userspace and started dstack-kms
kms_marker=SNP_KMS_CONTAINER_STARTED / KMS runtime ready
kds_proxy=enabled for smoke via DSTACK_SNP_SMOKE_KDS_PROXY_URL=https://cors.litgateway.com/
strict_tcb_probe=denied_as_expected with tcb_status is not allowed
success_probe=GetTempCaCert HTTP 200; GetAppKey HTTP 200; SignCert HTTP 200; app container started
smoke_result=SNP E2E smoke success
no_secret_material_logged=true
```

This means the PR has live SNP report proof, live golden-vector measurement proof, release-gate unit/integration coverage, and hardware smoke proof through dstack-managed SNP KMS boot, strict TCB denial, app guest key release, and app container startup. The fresh-box smoke now reaches Linux/userspace, `SNP_KMS_CONTAINER_STARTED`, `GetTempCaCert`, `GetAppKey`, `SignCert`, and app container startup when using a coherent **SNP** `meta-dstack` image. During the smoke, AMD KDS throttling was worked around by explicitly routing AMD KDS collateral fetches through the smoke-level `DSTACK_SNP_SMOKE_KDS_PROXY_URL=https://cors.litgateway.com/`; the runtime code exports that as `DSTACK_AMD_KDS_PROXY_URL` for verifier processes. The proxy is a path-prefix passthrough (`https://cors.litgateway.com/https://kdsintf.amd.com/...`), not a `?url=` wrapper. The proxy value is carried in the measured guest cmdline for smoke runs and mirrored in KMS measurement recomputation to avoid measurement drift. Host/KMS binaries must match PR #703, guest-side `dstack-util`/`dstack-attest` must include the PR cert-chain/KDS fallback, and the Yocto image must be built with `MACHINE = "sev-snp"` so the guest kernel includes AMD memory-encryption/SNP support. A coherent PR image built with the default `tdx` machine produced a `6.18.24-dstack` kernel with `# CONFIG_AMD_MEM_ENCRYPT is not set`; controlled QEMU tests showed that kernel resets immediately after OVMF loads kernel/initrd, while SNP-capable kernels boot the same QEMU/OVMF path to Linux/SNP markers.

### Fresh SNP host / image requirements

The checked-in smoke is enough to reproduce the current boundary on a compatible SNP host, but reviewers should treat the guest image/kernel/userspace as part of the test matrix:

- Known-good host for reaching KMS and app `dstack-prepare.sh`: `chris@173.234.27.162` with QEMU 10.0.2, the SNP-capable OVMF above, and a coherent `dstack-dev-0.6.0` guest image built with `MACHINE = "sev-snp"`.
- Released images that do not carry PR #703 guest-side `dstack-util`/`dstack-attest` may reject SNP evidence before the newer PR fallback paths can help.
- A coherent PR #703 image must be built as an SNP image, not with `meta-dstack`'s default `tdx` machine. The default TDX build can emit a kernel without `CONFIG_AMD_MEM_ENCRYPT`, which fails before Linux serial output under SNP.
- On the same remote host/QEMU/OVMF, a minimal SNP initramfs booted SNP-capable kernels (`6.11.0-rc3-snp-host`, `6.9.0-rc7-snp-host`, and the `MACHINE = "sev-snp"` `6.18.24-dstack` kernel) to Linux/SNP markers, while the default-TDX `6.18.24-dstack` kernel reset immediately after OVMF loaded kernel/initrd. This isolates that failure to the guest kernel config, not PSP firmware, KMS/auth policy, author-key, command line, virtio wiring, or basic host SNP enablement.

Practical implication for reviewers/testers on a fresh box:

1. Install/use an AMDSEV QEMU 10.x build and the matching SNP-capable OVMF.
2. Build the PR binaries with `cargo build --release -p dstack-vmm -p supervisor -p dstack-kms`.
3. Run `test-scripts/snp-e2e-smoke.sh` unchanged and first confirm it reaches `SNP_KMS_CONTAINER_STARTED`; if AMD KDS throttles the lab host, set `DSTACK_SNP_SMOKE_KDS_PROXY_URL` to a trusted path-prefix AMD-KDS passthrough/cache endpoint such as `https://cors.litgateway.com/` and rerun. The lab success above also used `DSTACK_SNP_SMOKE_ALLOW_OUT_OF_DATE_TCB=1` because the current SNP lab host reports `OutOfDate`; production defaults remain `allowed_tcb_statuses = ["UpToDate"]` with an empty advisory allowlist.
4. For full `SNP_APP_CONTAINER_STARTED` / `GetAppKey` success, use or publish a coherent `meta-dstack` guest image whose kernel, modules, initramfs, rootfs, verity metadata, and guest userspace include the same PR #703 `dstack-util`/`dstack-attest` SNP cert-chain/KDS fallback code. The reproducible path is to build `meta-dstack` with its `dstack` submodule checked out to this PR branch, for example:

   ```bash
   git clone https://github.com/Dstack-TEE/meta-dstack.git
   cd meta-dstack
   git submodule update --init --recursive --depth 1
   cd dstack
   git fetch https://github.com/clawdbot-glitch003/dstack.git feat/amd-sev-snp-conversion
   git checkout -B feat/amd-sev-snp-conversion FETCH_HEAD
   cd ..
   source dev-setup ./bb-build
   sed -i 's/^MACHINE ??= .*/MACHINE = "sev-snp"/' ./bb-build/conf/local.conf
   FLAVORS=dev make dist DIST_DIR=$PWD/images BB_BUILD_DIR=$PWD/bb-build
   # Use the resulting dstack-dev image directory with:
   #   DSTACK_SNP_SMOKE_IMAGE_NAME=<coherent-dstack-dev-image-dir>
   ```

   Do not try to inject only a replacement `dstack-util` into the stock image; that experiment changed the initramfs/measurement enough to regress boot.
5. Only after the baseline smoke reaches the app success marker should testers swap the simple app workload for Chipotle.

If the smoke stops after `EFI stub: Loaded initrd ...` with `cpus are not resettable`, use a host/image/kernel that is known to boot dstack under SNP before debugging app-level behavior. If it reaches `Requesting app keys from KMS` and fails with AMD KDS `HTTP 429`, use the smoke proxy hook above; if it fails with missing cert-chain/collateral without KDS proxy evidence, rebuild/use a coherent PR guest image rather than changing KMS release policy.

## Validation commands

Run locally for this review-ready staging branch:

```bash
bash -n test-scripts/snp-e2e-smoke.sh
cargo fmt --all
cargo test -p dstack-kms --all-features
cargo test -p dstack-attest --all-features
cargo test -p dstack-vmm --all-features
cargo test -p ra-rpc --all-features
cargo check --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings --allow unused_variables
git diff --check
cd kms/auth-simple && npx oxlint . && npx vitest run
```

## Remaining production follow-up

The release gate is controlled and production-oriented, but AMD advisory/revocation collateral is still limited by the evidence source available here: SNP reports/VCEKs do not directly carry an advisory list, so `advisory_ids` currently propagates as an explicit empty list. Future collateral fetchers can populate this field and will be denied by both auth-simple and the local KMS release gate unless each advisory is explicitly allowlisted.
