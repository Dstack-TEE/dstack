# AMD SEV-SNP Support

This document describes how dstack uses AMD SEV-SNP on self-hosted bare-metal
systems. SEV-SNP instances in public clouds are not supported yet: dstack
recomputes the launch measurement itself, which needs control of the launch,
and AWS signs its reports with a VLEK, which the verifier rejects.

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

Use a release containing the `sev-snp` key provider in the guest OS and VMM. The
KMS container and client attestation verifiers must recognize the new provider
metadata. Set `VERSION` to the OS release version and `KMS_IMAGE` to the KMS
container reference, then install:

```bash
sudo dstackup image pull --version "$VERSION"
sudo dstackup install --platform amd-sev-snp \
  --image "dstack-$VERSION" --kms-image "$KMS_IMAGE"
sudo dstackup status
```

Confirm that installation reports `booted` for the KMS CVM. `dstackup` selects
the `sev-snp` provider for the KMS CVM on AMD hosts. The default
`--platform auto` also detects SEV-SNP from the host CPU flags. Explicit
selection checks for the required SNP device before installation. Review the
[KMS key-release policy](#kms-key-release-policy) before serving applications.

## Run KMS with persistent local keys

The `sev-snp` provider lets a KMS CVM recover its encrypted disk and stored KMS
roots after restart on the same AMD hardware. For a manually managed KMS CVM,
set this field in its app-compose document:

```json
{"key_provider": "sev-snp"}
```

The deployment CLI also accepts `dstack deploy --key-provider sev-snp`. Application
CVMs continue using `key_provider: kms` and the existing KMS API.

The guest derives a seed through `SNP_GET_DERIVED_KEY` using legacy VCEK at
VMPL0. The seed binds to launch measurement, guest policy, HOST_DATA, launch
identity, and a pinned TCB. The guest requires debugging disabled and encrypted
storage, and verifies the configuration binding before deriving the seed.

Before initializing a new disk, the guest persists public derivation parameters
in `.instance_info` through the host API. Preserve this file, the encrypted
disk, and the original launch configuration together. Missing parameters for
an existing disk, unknown versions, or derivation/unlock failures stop startup.

Recovery requires the original hardware and bound launch inputs. For OS or
compose changes, or hardware replacement, preserve KMS roots through the
existing onboarding/replication flow. Firmware updates must support the stored
derivation TCB and satisfy attestation policy.

The entire KMS CVM, including its OS, is trusted. Protect KMS root and sealing
keys by keeping the KMS OS and workload under operator control. Application
key release continues to follow the existing KMS authorization policy.

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

GPU workloads get the same boot-time guarantee as on TDX. Before key
provisioning, the guest attests every attached NVIDIA GPU, applies the app's
`requirements.gpu_policy`, and stops boot if either fails. The SNP report proves
this gate ran under that policy: the launch `MEASUREMENT` covers the OS that
runs it, and `HOST_DATA` binds the MrConfigV3 `compose_hash` that fixes the
policy. GPU launches also carry the policy digest,
`SHA-256(JCS(requirements.gpu_policy))`, as `MrConfigV3.gpu_policy_hash`.

SEV-SNP has no quote-bound runtime register, so the per-boot `gpu-attestation`
event and the boot-time GPU evidence returned by `/v1/Attest` are not bound to
the report. A verifier that needs a GPU present, or a specific GPU count, must
find that requirement in the measured policy rather than in the event. See
[GPU Threat Model and Lifetime](./security/security-model.md#gpu-threat-model-and-lifetime).

The verifier supports the AMD Milan, Genoa, and Turin KDS product families.
Bergamo and Siena are handled through AMD's canonical Genoa KDS product path.

The verifier also fetches the product family's CRL from KDS
(`<amd_kds>/<product>/crl`). It requires the CRL to be signed by the pinned ARK
and current, and rejects a revoked ASK. This applies whether the evidence
carries its certificates or the verifier fetches them, so a KDS mirror must
serve the CRL too. The verifier does not yet check the validity periods of the
ASK and VCEK certificates
([#1140](https://github.com/Dstack-TEE/dstack/issues/1140)).

AMD publishes no TCB status for SNP, so a report is judged against a list of
minimum TCBs, one per CPU. An entry names the CPU by CPUID Fn0000_0001 EAX, as
AMD's security bulletins print it, and gives the highest SVNs those bulletins
require of it; family 1Ah (Turin) entries also set `fmc`. This one is Milan
after AMD-SB-3020 and AMD-SB-3027:

```json
[{"cpuid":"00a00f11","bootloader":0,"tee":0,"snp":27,"microcode":222}]
```

A product family is too coarse a key: Milan (`00a00f11`) and Milan-X
(`00a00f12`) differ only in stepping and carry different microcode SVNs, as do
Genoa (`00a10f11`), Genoa-X (`00a10f12`) and Bergamo/Siena (`00aa0f02`). A
bulletin that lists only a microcode patch level implies the SVN: it is the
level's low byte, as the bulletins that state both show.

`BootInfo.tcb_status` is `UpToDate` when the reported, committed and launch
TCBs all meet the entry for the report's CPU, and `OutOfDate` when one does
not. The reported TCB is the one the VCEK certifies, and the committed TCB
bounds a firmware rollback. SEV-SNP reports no advisory IDs. `DstackKms`
accepts only `UpToDate` from a KMS instance, as does `DstackApp` with
`requireTcbUpToDate`.

The KMS reads the list from its auth API when it authorizes an SEV-SNP
attestation, reusing it for a second. Its verdict on its own attestation is
reused for an hour, like the rest of its boot info. Publish the list where the
auth API reads it:

- With on-chain governance, publish it in `DstackKms` with
  `setSevSnpTcbRequirements` (see [On-chain governance](./onchain-governance.md)).
- With `dstack-auth`, list the entries under `sevSnpTcbRequirements` (see
  [dstack-auth operations](./dstack-auth-operations.md)).

A KMS can cover CPUs governance does not list: `sev_snp_tcb_requirements_file`
under `[core.attestation]` names a file with the same JSON, read at startup.
The published list takes precedence: the file decides only for a CPU the
published list has no entry for, and cannot raise or lower a published minimum.
Governance does not see the file, so a KMS that carries one vouches by itself
for the CPUs governance leaves out, its own included. Write the file in the
KMS's compose file, like `kms.toml`, so that it is part of the measurement
governance allows.

The KMS refuses a request it cannot judge, with the reason, instead of calling
the TCB out of date: when the auth API does not serve the list, when the list
does not parse, when neither list has an entry for the report's CPU, and when
the report predates the CPUID fields (version 2). The dev backend publishes
none, which leaves the KMS's own list.

`dstack-verifier` does not read the auth API: give it the same JSON in the file
`attestation.sev_snp_tcb_requirements_file` names, which a compose file can
carry inline (see the [verifier README](../dstack/verifier/README.md)). It
reads the file at startup, and reports an empty status without one and for a
CPU without an entry.

No report field shows firmware that was downgraded and upgraded again
while the guest ran, as long as the committed TCB stayed at the minimum.

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

The verifier obtains the ASK and VCEK from the built-in AMD KDS URL when the
attestation evidence does not already contain them, and always fetches the
product family's CRL from it. An operator can set an AMD-KDS-compatible mirror
or cache, which must also serve `<product>/crl`:

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
- **TCB is `OutOfDate`:** the TCB is below the minimum published for its CPU.
  Update the platform firmware before changing the auth policy.
- **`no minimum TCB is listed for CPUID ...`:** publish an entry for that CPU.
  The error names the `cpuid` the entry needs.
- **`failed to read the SEV-SNP TCB requirements from the auth API`:** the auth
  API predates the route, or the contract predates `sevSnpTcbRequirements`.
