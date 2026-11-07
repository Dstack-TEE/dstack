# AMD SEV-SNP Support

This document describes how dstack uses AMD SEV-SNP on self-hosted bare-metal
systems. AMD SEV-SNP support is currently **experimental**; Intel TDX remains
the production bare-metal path.

For platform firmware, kernel, QEMU, and OVMF preparation, start with
[Hardware Enablement](./hardware-enablement.md). This document covers the
dstack-specific image, installation, attestation, and key-release requirements.

## Supported image line

dstack OS 0.6.0 and later use one `dstack-<version>` guest image for both Intel
TDX and AMD SEV-SNP. The unified Yocto machine includes both platform kernel
feature sets and detects the active TEE at runtime. Do not change the Yocto
`MACHINE` to a platform-specific value.

Guest OS releases are split at the monorepo boundary:

- versions below 0.6.0 are archived in
  [`Dstack-TEE/meta-dstack`](https://github.com/Dstack-TEE/meta-dstack/releases)
  under tags such as `v0.5.11`;
- versions 0.6.0 and later are in
  [`Dstack-TEE/dstack`](https://github.com/Dstack-TEE/dstack/releases?q=guest-os-v)
  under tags such as `guest-os-v0.6.0`.

The 0.5.x images are legacy TDX images, not the current unified SEV-SNP image
line. Use a 0.6.0-or-later image for SEV-SNP. The image must include
`digest.txt`, `sha256sum.txt`, and the SNP measurement material.

## Host requirements

The host must provide:

- an SEV-SNP-capable AMD processor and current platform firmware;
- SEV-SNP and the Reverse Map Table (RMP) enabled by the host kernel;
- `/dev/sev`;
- a QEMU and OVMF build with SEV-SNP support.

After following the host platform's enablement procedure, check:

```bash
test -e /dev/sev
sudo dmesg | grep -e SEV-SNP -e RMP
cat /sys/module/kvm_amd/parameters/sev_snp
```

The last command should print `Y`. `dstackup` checks `/dev/sev`, but that
preflight does not replace firmware, kernel, QEMU, or OVMF validation.

## Install dstack on an SNP host

For a self-contained KMS installation, use matching guest, KMS container, and
host-tool builds containing the native `snp` provider and updated shared types.
Older images that only support SNP attestation cannot use this provider. Set
`SNP_OS_IMAGE` to the guest image's name in the VMM image store and
`SNP_KMS_IMAGE` to the rebuilt KMS container image, then select the platform
explicitly:

```bash
sudo dstackup install --platform amd-sev-snp \
  --image "$SNP_OS_IMAGE" --kms-image "$SNP_KMS_IMAGE"
sudo dstackup status
```

The default `--platform auto` mode also selects SEV-SNP when the host CPU flags
advertise `sev_snp`. Explicit selection is preferable while commissioning a
host because it fails immediately when the required SNP device is absent.

Unlike the TDX path, SEV-SNP does not use the local SGX key provider.

## Persistent local keys

Select `key_provider: snp` in the KMS CVM's app-compose document, or deploy with
`dstack deploy --key-provider snp`. The VMM UI calls this provider **SEV-SNP
hardware**. `dstackup` selects it for an AMD KMS installation. Application CVMs
continue using `key_provider: kms`.

Components that parse shared provider metadata, including the KMS and client
attestation verifiers, must recognize the new `snp` enum value. Rebuild those
components with the updated shared types; older strict verifiers reject it.
The KMS RPC protocol and application configuration are unchanged.

The provider requires a real SNP guest at VMPL0, debugging disabled, encrypted
storage, and firmware supporting explicit VCEK selection through
`SNP_GET_DERIVED_KEY`. It derives a seed using legacy VCEK (`KEY_SEL=1`), launch
measurement, guest policy, and a pinned TCB. HOST_DATA and launch identity also
bind the key. Derivation failures stop startup.

Before initializing a new disk, the guest saves public versioned
`snp_sealing` parameters in the existing `.instance_info` record through the
host API. The TCB is stored as a decimal string to preserve all 64 bits. Later
boots reuse it. Missing parameters for an existing LUKS disk, unknown parameter
versions, or failure to save metadata stop startup before disk unlock.

Preserve `.instance_info`, the original MrConfig document, launch identity,
and launch inputs with the encrypted disk. Recovery requires the same hardware
and bound configuration. OS or compose changes need a new sealing context;
preserve KMS roots through the existing onboarding/replication flow. A firmware
update must still support the saved derivation TCB and satisfy attestation
policy. Hardware replacement requires KMS onboarding/replication too.

Keep the KMS CVM under the existing operator isolation and authorization
policy. The hardware seed and KMS root keys stay inside that CVM; authorized
applications retain access to their own application keys.

## Attestation and image identity

The guest collects an SNP attestation report through Linux configfs-tsm when
available, with `/dev/sev-guest` extended-report collection as the fallback.
See [Native TEE Interfaces](./native-tee-interfaces.md) before exposing either
kernel interface directly to an application container.

Verification is fail-closed and includes:

1. the AMD ARK/ASK/VCEK certificate chain and report signature;
2. the requested `REPORT_DATA` challenge binding and SNP policy fields;
3. the launch `MEASUREMENT` recomputed from the VMM's firmware, kernel,
   initramfs, command line, and launch inputs;
4. the MrConfigV3 `HOST_DATA` application-identity binding;
5. the unified OS image identity, `sha256(sha256sum.txt)`, which must match
   `digest.txt` and the SNP measurement document.

For a GPU VM, the optional `MrConfigV3.gpu_policy_hash` field contains
`SHA-256(JCS(requirements.gpu_policy))`. The signed SNP report binds the exact
MrConfigV3 document through `HOST_DATA`, so a verifier can validate the report
and document binding and then compare this field with the expected GPU policy
digest. If the field is absent, this optional check is not asserted. This binds
the GPU policy, but not the later `gpu-attestation` runtime event or the
boot-time GPU evidence returned by `/v1/Attest`: the current SEV-SNP path has
no quote-bound runtime measurement register.

The verifier supports the AMD Milan, Genoa, and Turin KDS product families.
Bergamo and Siena are handled through AMD's canonical Genoa KDS product path.

`BootInfo.tcb_status` is `UpToDate` only when the current, reported, committed,
and launch TCB versions agree; otherwise it is `OutOfDate`. Authorization
policy should remain strict for non-up-to-date TCB values. The verifier
currently reports an explicit empty advisory-ID list because the SNP report
and VCEK evidence do not directly carry an advisory list.

## KMS key-release policy

SEV-SNP key and certificate release has two independent gates:

1. the external KMS authorization policy must accept the verified `BootInfo`;
2. the local KMS operator must explicitly enable SNP release.

The local gate is disabled by default:

```toml
[core]
sev_snp_key_release = false
```

After the host, image, attestation, and external authorization policy have been
validated, enable it deliberately in the KMS configuration:

```toml
[core]
sev_snp_key_release = true
```

This gate covers application keys, KMS key transfer, application certificate
signing, and self-authorized temporary CA material. Enabling it does not bypass
the external authorization decision. Keep `enforce_self_authorization = true`
for production TEE deployments.

## AMD KDS collateral

The verifier obtains AMD certificate collateral from the built-in AMD KDS URL
when the attestation evidence does not already contain the required chain. An
operator can set an AMD-KDS-compatible mirror or cache:

```toml
[core]
amd_kds_base_url = "https://mirror.example.com/vcek/v1"
```

Leave the value empty to use the built-in default. A custom endpoint is part of
the verification trust and availability boundary: use a controlled mirror,
preserve TLS validation, and do not make verification succeed without valid
AMD signatures.

## Troubleshooting

- **`/dev/sev` is missing:** finish host firmware/kernel enablement before
  running `dstackup install`.
- **The guest resets before Linux starts:** verify that the selected QEMU,
  OVMF, and unified dstack OS image all support SNP. Do not debug KMS policy
  until the guest boots reliably.
- **Image identity files are missing:** use a 0.6.0-or-later unified image.
  `dstackup install` rejects an SNP image without `digest.txt`.
- **KDS requests fail:** check host time, DNS, outbound HTTPS, and KDS or mirror
  availability. Do not disable certificate or signature verification.
- **Attestation succeeds but key release fails:** check both the external auth
  response and `core.sev_snp_key_release`; either gate can deny the request.
- **TCB is `OutOfDate`:** update platform firmware and re-evaluate the reported,
  committed, current, and launch TCB versions before changing auth policy.
