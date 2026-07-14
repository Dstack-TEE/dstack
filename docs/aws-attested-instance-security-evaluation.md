# AWS EC2 Instance Attestation Security Evaluation

> **Current model (post-simplify, PR #753):** App/config is **not** embedded
> in UKI cmdline. Shared-disk `MrConfigV3` is measured into **PCR8**. All dstack
> events extend **SHA384 PCR14** only (TDX RTMR3 analogue; no PCR23 runtime
> split). `os_image_hash` prefers unified `sha256(sha256sum.txt)` via
> `VmConfig.aws_measurement`. GetAppKey is RA-TLS v1 only (no recipient v2).
> KMS auth pins early **`mrAggregated`** only. The local `mr_config` check runs
> once after key receipt (`verify_app`); there is no separate pre-key-release
> gate. Historical sections below that describe cmdline `dstack.mr_config_id`,
> PCR23 runtime, recipient encryption, pre-key-release `mr_config` gating, or
> `kms.composeHashes` are superseded by this model.

Date: 2026-07-03

This note compares dstack attestation with AWS EC2 instance
attestation. The target threat model is:

- Trusted root: AWS Nitro system and NitroTPM attestation signing
  infrastructure.
- Verified, not blindly trusted: dstack OS images, dstack KMS instances,
  dstack verifier code, and governance policy. The relying party accepts these
  only after checking reproducible build outputs, attested measurements, event
  logs, and policy state. A published AMI ID or a running KMS endpoint is not
  sufficient evidence by itself.
- Untrusted: the workload AWS account administrator/operator. They may launch,
  stop, replace, snapshot, reconfigure, and network-interpose EC2 resources in
  their account. AWS KMS keys controlled by that account are also untrusted for
  secret authority because the account administrator may be able to change key
  policy, create grants, or route secret-bearing calls through policies they
  control.
- Out of scope: availability. The operator can always deny service.

## Baseline: dstack Chain of Trust

dstack's trust chain is layered:

1. Hardware quote verification proves the workload runs on genuine TEE hardware.
   In the Intel TDX path, DCAP quote verification checks Intel signature chain,
   debug status, TCB/collateral, and `report_data`.
2. OS verification compares `MRTD` and `RTMR0-2` against values independently
   computed from the meta-dstack image, VM config, kernel, initrd, firmware, and
   boot parameters.
3. Application verification replays RTMR3 runtime events and checks the
   `compose-hash`, `app-id`, `instance-id`, and `key-provider` events.
4. KMS binding records the KMS identity in RTMR3. The KMS is not a trusted
   service by name or network location. It is a dstack app with its own
   attestation, reproducible image measurement, and governed identity. KMS key
   release builds `BootInfo` from verified attestation, asks the auth
   API/contracts whether that boot is allowed, then derives app-scoped
   disk/env/signing keys.
5. Governance pins allowed OS images, KMS aggregate measurements, and allowed
   app compose hashes.

The important property is not just "there is a signed measurement." The
measurement must bind hardware, base OS, app identity, key provider, freshness,
and authorization policy in a way the infrastructure operator cannot silently
change.

## AWS EC2 Instance Attestation Summary

AWS EC2 instance attestation is the new whole-instance attestation feature based
on NitroTPM and Attestable AMIs. It is distinct from the existing Nitro Enclave
NSM path already implemented in `dstack-attest`/`nsm-qvl`.

From AWS documentation:

- NitroTPM is a virtual TPM 2.0 device provided by the AWS Nitro System. It
  supports measured boot, signed PCR values, remote attestation, and TPM
  sealing.
- An Attestable AMI is built so that reference PCR measurements represent the
  AMI contents, including boot process, applications, code, and configuration.
- The current AWS sample path uses UEFI + a UKI, with `erofs` and `dm-verity`
  to keep root filesystem state immutable.
- `nitro-tpm-pcr-compute` computes reference `PCR4`, `PCR7`, and `PCR12`.
- `nitro-tpm-attest` retrieves a COSE/CBOR NitroTPM Attestation Document with
  `nitrotpm_pcrs`, timestamp, optional `public_key`, optional `user_data`, and
  optional `nonce`.
- AWS KMS supports attested `Recipient` calls for `Decrypt`,
  `DeriveSharedSecret`, `GenerateDataKey`, `GenerateDataKeyPair`, and
  `GenerateRandom`. KMS returns `CiphertextForRecipient`, encrypted to the
  public key in the attestation document, instead of plaintext.
- KMS supports `kms:RecipientAttestation:NitroTPMPCR<PCR_ID>` condition keys.
  AWS EC2 docs specifically recommend `PCR4` plus `PCR12` for standard boot, or
  `PCR7` for Secure Boot. The KMS service authorization reference exposes
  NitroTPM PCR condition keys for PCR0 through PCR23.

In this evaluation, AWS KMS is treated as an optional convenience service, not a
trusted secret authority. The baseline replacement for dstack should use dstack
KMS or another verifier-controlled KMS that validates NitroTPM attestations
itself and encrypts key material to the public key bound in the attestation
document. That KMS remains subject to the same verification rule as any other
dstack workload: the relying party must verify its attestation, image
measurement, app identity, and governance authorization.

## dstack-os AMI Status

Yes. We are already booting a Yocto-built dstack OS image as an AWS EC2 AMI
with NitroTPM enabled. The production target is a reproducible dstack OS variant
packaged as an AWS Attestable AMI:

1. Build dstack OS as a UEFI-bootable image with NitroTPM enabled. AWS requires a
   TPM 2.0 CRB driver in the OS, `--boot-mode uefi`, and `--tpm-support v2.0`
   when the AMI is registered.
2. Put the hardened kernel, initrd, boot arguments, and early dstack launcher
   into a Unified Kernel Image (UKI). AWS' reference PCR tooling computes
   `PCR4`, `PCR7`, and `PCR12` from the UKI.
3. Use an immutable root design (`dm-verity`, read-only rootfs, or equivalent)
   so the instance cannot drift after the measured boot state.
4. Keep operator mutation channels out of the measured base image. The July 1,
   2026 prod Yocto rootfs manifest did not include `openssh`, `dropbear`,
   `cloud-init`, `amazon-ssm-agent`, or EC2 Instance Connect packages. Continue
   treating SSH, SSM, EC2 Instance Connect, cloud-init/user-data scripts, serial
   console login, mutable package updates, and writable executable paths before
   attestation-gated key release as production blockers.
5. Preserve reproducibility: publish the image manifest, kernel config, UKI
   inputs, rootfs hash, and PCR reference measurements from the same build. The
   relying party must recompute or independently verify these values before
   accepting an AMI.

The build target should remain one reproducible Yocto pipeline, not a separate
OS fork per cloud. The monorepo's `os/yocto` backend follows that shape:
`MACHINE=dstack` builds a unified confidential-guest machine, the prod/dev
multiconfigs build flavor-specific rootfs and UKI artifacts, and kernel feature
fragments add TDX, SEV-SNP, TPM2, and AWS NitroTPM support to the same guest
kernel where possible. The preferred release shape is:

1. One shared dstack OS rootfs and userspace content.
2. One shared kernel configuration unless a platform has a hard boot-time
   incompatibility.
3. Platform-specific packaging only where required by the launcher. For example,
   EC2 needs an imported UEFI raw disk registered with `--tpm-support v2.0`,
   while the existing dstack VMM consumes the standard guest-image directory or
   tarball.
4. One manifest that links all package formats back to the same reproducible
   Yocto build inputs and per-platform reference measurements.

The ideal end state is one dstack OS content set accepted on TDX, SEV-SNP, GCP,
and AWS. If a single byte-identical boot artifact is not possible because a
platform requires different firmware, boot media layout, or measurement carrier,
the verifier should still see one build graph with explicit per-platform
packaging and PCR/MR outputs.

Remote meta-dstack commit `9b8ccdd` makes the packaging direction explicit:
`build.sh guest` still emits the standard dstack guest-image tarball, and the
UKI/AWS EC2 package includes `disk.raw`, `dstack-uki.efi`, and
`auth_hash.txt`. Including the UKI lets a verifier recompute AWS reference PCRs
directly from the release package. The clean AMI manifest below still pins the
artifacts from the earlier P2 build.

Latest source-integrated prod build evidence from `phala-onprem`:

- Source: meta-dstack `a3057cdc86f452a26f628c50f4a237a542fe9a6f`,
  dstack `3da3b8a6b70b73c93a0a4a32bf94207c09317016`.
- Deterministic source archive SHA256 values:
  - `meta-dstack-a3057cdc86f452a26f628c50f4a237a542fe9a6f.tar`:
    `176e94fee5e508c4b15e57a0fa41c5937674ae548dd0762202b45ecb5f3cf3ae`
  - `dstack-3da3b8a6b70b73c93a0a4a32bf94207c09317016.tar`:
    `288a8183ec0e0f11870b1d4f42708eea00388100c679354c7c639f7953fef505`
- Yocto downloads evidence from the hardened build contains 5,328 cached input
  paths with sorted path-list SHA256
  `17df580db33fb9186eaa7e7b9b6e9514423595cd81101eed2cf06605a1c25d48`
  and content-manifest SHA256
  `3f94d1b0f77579f63faa8688ec318f4e63fc921d7dc3f970e1d96c0e1281912b`.
  This is evidence for the current build environment, not a substitute for a
  production input-content mirror.
- `os/yocto/tools/aws/generate-aws-ec2-release-manifest.sh` now generates the
  machine-readable AWS release manifest from the source repositories and release
  artifacts. It records source commits, deterministic source archive hashes,
  artifact hashes, optional Yocto download evidence, optional AWS
  `nitro-tpm-pcr-compute` output, UKI AuthentiCode hash, hardening audit
  output, and verifier instructions.
- The July 5, 2026 hardened release-candidate build on `phala-onprem` was
  captured by running `os/yocto/tools/aws/generate-aws-ec2-release-manifest.sh`, which
  produces a reproducibility manifest with the clean source archive hashes,
  release artifact hashes, optional Yocto download content manifest, AWS
  PCR4/7/12 values, dstack `os_image_hash`, UKI AuthentiCode hash, and the
  hardening-audit result. That run reported `hardening_audit.failures = 0` and
  `hardening_audit.warnings = 0`. Regenerate the manifest for the exact release
  candidate you promote instead of relying on a committed evidence copy.
- Hardened release-candidate packages:
  - `aws-hardening-release/images/dstack-0.6.0-uki.tar.gz`, SHA256
    `935af1e4d07908826c1c7b0067bd7e453900fc31f576a2708b33e742f663c993`.
  - `aws-hardening-release/images/dstack-0.6.0.tar.gz`, SHA256
    `e974f17bcdfc3f7015d1c290995e5188c183be37b147f208c5f2d84240a314d9`.
  - `aws-hardening-release/images/dstack-0.6.0/disk.raw`, SHA256
    `2261a2e28ae4b0ca5da1f675319d1d6c1c35623ae76370d77b6e2255ec46baee`.
  - `aws-hardening-release/images/dstack-0.6.0/dstack-uki.efi`, SHA256
    `9ff9fa711f6659b1855e7cc4337b22c0a1d9356ef05a926e446bcefd871ecb7d`.
- AWS `nitro-tpm-pcr-compute` for the hardened UKI returns SHA384 `PCR4`
  `22eaa1efe29a10c161bc91dc6474089b881f5d23b6c403916957a1e6ff0bb18d5b2f0eb82a66476cefdf08cd0633ea6a`,
  `PCR7`
  `98441c7f7625d10058c47683aec486ce311c633235eb555593a7ee791121e3578ae72d04ecef661f272d59058b77af35`,
  and zero `PCR12`.
- A hardened app-specific P4/API-smoke package was built from the same
  meta-dstack and dstack commits with
  `DSTACK_MR_CONFIG_FILE=aws-test-disks/api-smoke-20260702040745/dstack-mr-config.json`.
  Running `os/yocto/tools/aws/generate-aws-ec2-release-manifest.sh` against that build
  produces a deployment-specific manifest with its own optional Yocto download
  content manifest. The package embeds
  `dstack.mr_config_id=039c25534ef2dd61b12de4bfbe377fa20dd3e234c5a77185f5255bb251aef5764a000000000000000000000000000000`
  in the UKI `.cmdline`, includes `dstack-mr-config.json`,
  `dstack-mr-config-id.txt`, and the API-smoke `shared.raw` as manifest
  artifacts, and reports `hardening_audit.failures = 0`,
  `hardening_audit.warnings = 0`.
- The P4/API-smoke package was promoted to an Attestable AMI and live-smoked on
  EC2. `os/yocto/tools/aws/aws-ec2-attach-promotion-evidence.sh` attaches the validated
  promotion and live-smoke records to that manifest:

  ```text
  AWS account: 481766170915
  AWS region: us-west-2
  AMI: ami-015b720d2e3e9dd9c
  AMI name: dstack-aws-hardened-p4-api-smoke-20260705164908
  root snapshot: snap-022c271b9790aebf3
  shared snapshot: snap-0efa19b7528e14142
  data snapshot: snap-032e134d0bb685cc6
  live smoke instance: i-00ad5b777c394914d
  live smoke status: passed
  console sha256: 123fb8f67c0394417ef29c696811e5f08f804e5eaa483f6af4746254cc24ebc2
  observed os_image_hash: b02b91586ae21ab5a255f743603ef4465afcf718a692e9ee52ab59e71eeb0006
  observed mr_aggregated: 88b6bc30f3f0769c2948b38df39f9e79b7ab50c5b208f8226d7160355a72d175
  observed compose_hash: f3fe256d2531bd60b27e16848db66c084abead49678458448b2d7d4a49bd6922
  ```
- AWS `nitro-tpm-pcr-compute` for the hardened P4/API-smoke UKI returns
  SHA384 `PCR4`
  `19688151478d1f37e1a1ba17346fdd4f28962005f15a38a7f3587b3bd42124d603bcd5a861a6ff072308697bcaa45d21`,
  the same `PCR7` as the generic hardened UKI, zero `PCR12`, dstack
  `os_image_hash`
  `b02b91586ae21ab5a255f743603ef4465afcf718a692e9ee52ab59e71eeb0006`,
  and UKI AuthentiCode hash
  `e4dfb1475e6f7957f75497db113e8277800528960ec94e659cb443eb4784b10c`.
- Historical generic prod UKI package:
  `repro-build/dist/dstack-0.6.0-uki.tar.gz`, SHA256
  `1a34d155df60d363910490b0acb7bd94ffd74c5c4c8ccbd344bfa8e38b72abaf`,
  UKI Authenticode hash
  `dc7c0dd4142673fbbbd411aff7d023bdbb61f233f394df128c04ef3babfdc0d0`.
- P4 validation UKI package:
  `repro-build/build-a/images-p4-final/dstack-0.6.0-uki.tar.gz`, SHA256
  `9eacc9ed9539e94812a892db01232ef37f03074ef16311f0a5d8e7e4fec44daa`,
  UKI Authenticode hash
  `e8c1fb45e3c033a46e9cee8357467685e4bd4f01173145b297af8455a451b191`.
- The P4 package includes `dstack-mr-config.json` and
  `dstack-mr-config-id.txt`. The config ID is
  `03b3c65016fdc392d8497f72bfa697d06743fecc15601fa140c319dec56a3acd6a000000000000000000000000000000`.
- Extracting the `.cmdline` section from the P4 `dstack-uki.efi` shows the same
  `dstack.mr_config_id=03b3c650...000000` embedded in the measured UKI.
- AWS `nitro-tpm-pcr-compute` for the P4 UKI returns SHA384 `PCR4`
  `d33295e86f2cd21e376fadbf591ff09575a46c2f228673f8995c8967467b5c80595b1658444e46e5c53412dedae2acba`,
  `PCR7`
  `98441c7f7625d10058c47683aec486ce311c633235eb555593a7ee791121e3578ae72d04ecef661f272d59058b77af35`,
  and zero `PCR12`. For the current UKI packaging, the target config ID is
  therefore carried by the UKI/PCR4 measurement, not by PCR12. If a future AWS
  boot path accepts an external kernel command line, verifier policy must also
  require the expected PCR12.
- P4 boot-validation AMI `ami-0d228faa2192ce552`
  (`dstack-aws-p4-final-20260702040745`) booted on EC2 with NitroTPM enabled,
  reached dstack guest preparation, used `key_provider = "tpm"`, enforced the
  measured `mr_config_id`, and emitted the expected app identity and PCR-derived
  measurements.
- API-smoke validation UKI package:
  `repro-build/build-a/images-api-smoke/dstack-0.6.0-uki.tar.gz`, SHA256
  `84cb4fc9a20cfdaa0e6dce017c6a88d426bf7800b94dad45aad78a9b46fca165`,
  UKI Authenticode hash
  `b5498fa8c57a9d1ffd8fde6d4a5eb293a80341d4c9329c38766a21c36dbbd585`.
  Its measured config ID is
  `039c25534ef2dd61b12de4bfbe377fa20dd3e234c5a77185f5255bb251aef5764a000000000000000000000000000000`.
- API-smoke AMI `ami-01612ca905fdda978`
  (`dstack-aws-api-smoke-20260702040745`) booted a measured bash app whose
  compose hash was
  `f3fe256d2531bd60b27e16848db66c084abead49678458448b2d7d4a49bd6922`.
  The app called the dstack API through `/var/run/dstack.sock`, received
  platform info for `Amazon EC2` on `m6i.large`, retrieved a NitroTPM
  attestation payload through `/Attest`, and printed `DSTACK_AWS_API_TEST_OK`.
  The `/GetQuote` raw quote fields are not the AWS production attestation path;
  `/Attest` is the platform-adaptive API for NitroTPM evidence.

Kernel/rootfs hardening audit evidence:

- `os/yocto/tools/aws/audit-aws-ec2-image-hardening.sh` was run against the hardened
  release-candidate Yocto artifacts on `phala-onprem` on July 5, 2026. It
  reported `failures=0 warnings=0`.
- The release-blocking checks passed: required UEFI/NitroTPM/dm-verity/rootfs
  kernel features are present; `kexec`, hibernation, and debugfs are disabled;
  SSH, Dropbear, cloud-init, SSM, and EC2 Instance Connect packages are absent;
  root is locked; no SSH/getty/cloud/SSM/EC2 units are enabled; and no `sshd` or
  `dropbear` server binary is present.
- The defense-in-depth kernel items are set in meta-dstack commit
  `a3057cdc86f452a26f628c50f4a237a542fe9a6f`: dmesg restriction, strict I/O
  devmem, init-on-alloc/free, slab freelist randomization/hardening, hardened
  usercopy, and fortify source are enabled; magic SysRq and legacy TIOCSTI are
  disabled.

The clean P2 AMI for this track is `ami-058f0124934d7a144`
(`dstack-aws-clean-p2-20260701221139`) in `us-west-2`. Its reproducibility and
reference PCR evidence is recorded in
`docs/aws-ec2-ami-reproducibility-manifest.md`. It booted on EC2 with NitroTPM
enabled and the dstack API reported platform `aws-ec2`, attestation
`dstack-aws-nitro-tpm`, and the expected PCR-derived `os_image_hash`.

The hardened kernel is not a problem as long as it is part of the measured UKI.
Changing kernel hardening options changes the reference PCRs, which is exactly
what we want.

For dynamic container deployments, the AMI should not bake every app into the OS.
AWS should reuse dstack's existing RTMR3-style app-measurement model, not invent
a second app identity scheme. Today dstack measures runtime app identity through
events such as `compose-hash`, `app-id`, `instance-id`, `key-provider`, and
`os-image-hash`; GCP verification already combines TDX RTMR3 replay with a TPM
quote. AMD SEV-SNP binds the same logical app/config document through
`MrConfigV3` and `HOST_DATA`.

The AWS carrier should map that existing model onto NitroTPM:

1. Precompute the target application/config measurement off-instance.
2. Pass that target measurement in a kernel command line field that is itself
   measured by the selected AWS boot path. In the current UKI package this means
   embedding it in the UKI, which changes `PCR4` under AWS
   `nitro-tpm-pcr-compute`; if the platform uses an external kernel command line,
   require the corresponding `PCR12` value as well.
3. Early measured dstack init reads the operator-provided app config, computes
   the actual measurement, and refuses to continue unless it equals the measured
   target.
4. Early dstack init extends SHA384 `PCR14` with dstack-compatible launch
   events: `compose-hash`, `app-id`, `instance-id`, `key-provider`,
   `os-image-hash`, and related launch state. The measured boot carrier commits
   the target `mr_config_id`; `PCR14` is the RTMR3-style launch app-event
   carrier. The verifier treats `system-ready` as the launch boundary when it is
   present. Events after that boundary are not part of launch authorization.
5. The dstack KMS and external verifier replay those events and compare the
   final PCR value, just like dstack replays RTMR3 today.

TPM PCRs support extend-style measurement (`PCR_new = hash(PCR_old ||
digest)`), so a non-resettable PCR can model RTMR3's append-only event chain.
Use SHA384 `PCR14` for AWS launch authorization.

`PCR14` is the best current fit because AWS defines `PCR8` through `PCR15` for
static operating-system use, while `PCR4`, `PCR7`, and `PCR12` are already part
of the AWS boot path. The current dstack AWS image boots a direct UKI without
GRUB, shim/MOK, IMA, systemd-boot PCR helpers, or systemd-pcrphase. That leaves
`PCR14` available for dstack-owned launch measurement. Avoid `PCR10` because it
is the normal IMA PCR, avoid `PCR11` through `PCR13` because systemd-stub and
systemd-boot use them for UKI, boot phase, command line, credentials, and
sysext measurements, and avoid `PCR15` because systemd uses it for machine and
filesystem identity. Avoid `PCR8` and `PCR9` as first choice because GRUB-style
boot paths commonly use them. If the AWS image later adds shim/MOK, GRUB, IMA,
or systemd PCR tooling, revisit this PCR assignment before release.

`PCR23` remains useful for app-owned runtime telemetry, but it is not a
pre-secret launch gate. The Ubuntu PoC below confirmed that `PCR23` can be
extended and appears in the NitroTPM Attestation Document when the SHA384 bank
is extended. It also confirmed that `PCR23` is resettable by a privileged local
process. A compromised guest kernel could therefore reset and replay `PCR23`.
The hardened OS must still restrict direct TPM access, but launch authorization
must depend on non-resettable `PCR14`.

The July 4, 2026 reset negative test confirms the critical PCR14 assumption on
live NitroTPM. A temporary Ubuntu 24.04 NitroTPM AMI attempted `PCR_Reset` for
SHA384 PCR14 and PCR23 from local root. PCR23 reset succeeded and returned to
zero, as expected for the app/runtime PCR. PCR14 reset failed with TPM error
`0x907` (`bad locality`), and the PCR14 SHA384 value was unchanged before and
after the reset attempt. This means a compromised guest can still append to
PCR14, causing verifier/KMS mismatch or denial of service, but cannot reset and
replay PCR14 to a chosen authorized launch value through the normal guest TPM
interface.

The same day, a live dstack-os EC2 negative test confirmed that malformed PCR14
launch history is rejected even when the measured `mr_config_id` carrier is
valid. An instrumented, feature-gated image used UKI cmdline
`dstack.aws_pcr14_fault=mutate-compose-pcr`: the event log recorded the normal
`compose-hash` event, but early init extended PCR14 with a different digest.
The guest reached `dstack-prepare`, logged the expected `mr_config_id`, then
failed during app-info decoding:

```text
Injected AWS PCR14 fault: MutateComposePcr
aws mr_config_id: 0353d1503b71e1c87d3797b986e83051967d26180ed59e0139bcbe307d0fc312bb000000000000000000000000000000
Error: Failed to decode app info
    1: PCR14 mismatch, quoted: 078d42e5aecdc397d3710eb7115b5b3a699a1e795a864bb5051713b7a2b3cf5e43c0d2ff1bf536e4788ba6f6cb6c2011, replayed: 92766d667a289e24df485aebeef6cba76a053661f3002557e78f1b0d2ef7dddeee5480356b719241bab7c42bab2b0522
Failed to start dstack Guest Preparation Service
reboot: Restarting system
```

Evidence from that run:

```text
AMI: ami-014de51f12775d69a
AMI name: dstack-pcr14-mutated-compose-20260704
root snapshot: snap-099d53fa37a1a2d9f
import task: import-snap-78205abf39273631t
instance: i-00bcc271a6779f129
shared snapshot: snap-076523551b85461f6
data snapshot: snap-032e134d0bb685cc6
UKI package sha256: c8d8f1c77fafaab58345a3f38f176344d880d2c281e4cc80e2123dda52775c33
bare-metal package sha256: d04b8a8ee6ecf8708e1fe6363e770226396f0427b68887a373d76fe147676830
root disk raw sha256: c6fa93419aa8a772e4b38fb7f37c51cb1e4bc44b07c549ab08a88946f0ea6189
UKI Authenticode sha256: 5098c2e20e98cacb483784895536dfa9d945cf40219637d3617635543f04e3da
mr_config_id: 0353d1503b71e1c87d3797b986e83051967d26180ed59e0139bcbe307d0fc312bb000000000000000000000000000000
final console sha256: 3f45d22c107e1335c7f36bcf10134bdccb50aee3ac0efb25cf9eb0a3ac83bf27
combined console capture sha256: 0854d7306a93439d014b4567e2bc01845a1651eb852ad9daef0b360dd55b641c
```

This closes the changed-PCR14 live negative case. Missing, reordered, and
duplicated PCR14 launch histories are covered by source replay tests; live EC2
variants remain useful as additional coverage but are no longer needed to prove
the PCR14-as-RTMR3 design.

With that result, SHA384 PCR14 is a practical AWS substitute for the RTMR3
launch-measurement role:

- It is extend-only from the guest's reachable locality, so launch events form
  the same hash-chain shape as RTMR3.
- The NitroTPM Attestation Document reports SHA384 PCR14, so remote verifiers
  can bind policy to the final value.
- dstack records canonical launch events and replays them through
  `system-ready`, giving the same app identity inputs as RTMR3:
  `compose_hash`, `app_id`, `instance_id`, key-provider identity, and OS image.
- The measured UKI carries the expected `mr_config_id`, so early init has a
  precommitted target and rejects mismatched app/config input before secret
  release.

It is not literally TDX RTMR3. The root of trust is AWS NitroTPM rather than a
CPU TEE measurement register, AWS does not expose a TDX/SNP-style TCB status
field, and the platform must preserve and verify dstack's launch event log
rather than relying on a hardware-provided event log format. Those differences
are acceptable only if the verifier detects the AWS attestation mode and its
policy explicitly requires the boot PCRs, PCR14 replay, `mr_config_id`, and
dstack KMS/auth policy.

## NitroTPM as Local Key Provider

AWS NitroTPM can play the same two logical roles as the vTPM in the dstack GCP
integration, with a different attestation shape:

1. Measurement and attestation provider.
   - GCP path: TDX quote plus TPM quote, with
     `tpm_quote.qualifying_data = sha256(tdx_quote)`.
   - AWS path: NitroTPM Attestation Document is the primary whole-instance
     attestation evidence. It carries the NitroTPM PCR values, timestamp, nonce,
     and optional public key, signed by AWS Nitro attestation infrastructure.
2. Local key provider.
   - dstack already has `key_provider = "tpm"` support. It detects `/dev/tpmrm0`
     or `/dev/tpm0`, reads or creates a 32-byte seed, seals that seed into TPM NV
     storage under a PCR policy, and derives dstack app keys from the seed.
   - On AWS, the same TPM 2.0 sealing/unsealing model should work with
     NitroTPM. AWS documents NitroTPM as supporting key storage, crypto
     operations, measured boot, PCR-based sealing/unsealing, and states that
     NitroTPM state is not included in EBS snapshots.

This is sufficient to bootstrap a dstack KMS on EC2 in local TPM mode:

1. Launch the KMS as a dstack-os Attestable AMI with `key_provider = "tpm"`.
2. Early boot measures OS and KMS app identity into the NitroTPM PCR set.
3. KMS first boot generates root key material or a root seed and seals it with
   NitroTPM under the accepted PCR policy.
4. Later reboot/stop-start of the same EC2 instance can unseal only if the same
   measured state is reached.
5. EBS snapshots or cloned volumes do not carry the NitroTPM state, so the
   account admin cannot clone the KMS disk and recover the sealed root material
   elsewhere.

This is also the recommended AWS practice for dstack KMS: run the KMS as a
verifiable dstack workload on dstack-os EC2, use NitroTPM as its local key
provider, and require verifiers or peer KMS instances to check the KMS
attestation before accepting any key release. NitroTPM protects the KMS local
root material from account-admin disk cloning. It does not make an unverified
KMS endpoint trustworthy by itself.

The local-provider scope is per EC2 instance. If a KMS instance is terminated,
or if we intentionally move to a new KMS instance, root material must be
replicated through dstack's attested KMS replication flow to another authorized
KMS instance before the original local TPM state is lost.

Current implementation state:

- The AWS launch policy is SHA384 `PCR4`, `PCR7`, `PCR12`, and `PCR14`. Remote
  attestation uses SHA384 values from the NitroTPM Attestation Document.
  `PCR23` is reserved for post-launch app runtime telemetry and is not a
  pre-secret gate.
- AWS NitroTPM app measurement reuses the existing dstack event model, but now
  separates dstack-controlled launch measurement from app runtime events.
  Remote dstack commit `591b5625` adds `emit_launch_event`, maps AWS launch
  events to SHA384 `PCR14`, keeps app `EmitEvent` on SHA384 `PCR23`, and makes
  `dstack-attest` compute AWS `mr_aggregated` from `PCR4`, `PCR7`, `PCR12`,
  and verified `PCR14`. The verifier replays launch events through
  `system-ready` when that boundary exists, so post-launch app events do not
  change the launch identity. Parent meta-dstack commit `7d1ec56` points at
  this dstack state.
- dstack KMS has focused AWS NitroTPM `BootInfo` binding regression tests. The
  current tests construct a signature-verified AWS NitroTPM report model with
  `PCR4`, `PCR7`, `PCR12`, `PCR14`, and dstack launch events. They check that
  KMS `BootInfo` carries `app_id`, `compose_hash`, `instance_id`,
  `key_provider_info`, and `os_image_hash`; computes `mr_system` from verified
  boot PCRs plus key-provider identity; computes `mr_aggregated` from verified
  boot PCRs plus replayed `PCR14` launch events; changes `mr_aggregated` when
  `compose-hash` changes; changes both `mr_system` and `mr_aggregated` when
  verified boot PCRs change; rejects missing/mismatched `PCR14`; rejects
  reordered or duplicated pre-boundary launch events; and accepts post-boundary
  app runtime events without changing launch identity.
- AWS measured-target binding is implemented and has been exercised on EC2.
  Remote dstack commit `8c9a257d` keeps AWS fail-closed on
  `dstack.mr_config_id=<96 hex chars>` while allowing NitroTPM-derived
  per-instance fields to be dynamic. Parent meta-dstack commit `731bb32`
  teaches the UKI recipe to emit that command-line value and package the exact
  `MrConfigV3` document plus config ID for relying-party recomputation. The
  latest P4 validation package embeds that value in the UKI `.cmdline` section
  and AWS reference computation reflects the change in `PCR4`; `PCR12` remains
  zero for this UKI packaging path. Live AMI `ami-0d228faa2192ce552` booted the
  final P4 package with NitroTPM enabled and reached dstack guest preparation.
  Live AMI `ami-01612ca905fdda978` booted a measured API-smoke app and proved
  `/Info` and `/Attest` access from the measured runtime.
- AWS PCR14/PCR12/replay negative coverage has been expanded in source and with
  one live malformed-PCR14 EC2 run. Re-run on `phala-onprem` at remote dstack
  commit `3da3b8a6`:

  ```text
  cargo test -p dstack-attest aws_nitro_tpm_ -- --nocapture
  result: 4 passed

  cargo test -p dstack-kms aws_nitro_tpm -- --nocapture
  result: 7 passed

  cargo check -p dstack-util
  result: passed

  cargo check -p dstack-guest-agent -p dstack-util --features dstack-util/aws-pcr14-fault-injection
  result: passed
  ```

  The live EC2 negative used `ami-014de51f12775d69a` with
  `dstack.aws_pcr14_fault=mutate-compose-pcr`. The guest logged the expected
  `mr_config_id`, then rejected its own app info with `PCR14 mismatch` before
  the app could start. The test instance was terminated after evidence
  collection.
- AWS NitroTPM sealed-state behavior has live dstack-os evidence. AMI
  `ami-01612ca905fdda978` was launched with `key_provider = "tpm"`. On the
  primary instance, first boot generated a TPM-sealed seed. A later EC2
  force-stop/start of the same instance unsealed the same seed under
  `PCR policy: sha384:4,7,12,23`, kept the same TPM key-provider public id, kept
  the same dstack `instance_id`, and the measured API-smoke app passed again.
  A separate clone instance launched from the same AMI, shared disk, and a data
  snapshot of the primary did not recover the primary TPM state. The captured
  clone boot used a different TPM key-provider public id and failed to open the
  primary encrypted data disk with `No key available with this passphrase`.
  This is the expected result when EBS state is cloned but NitroTPM NV state is
  not. Temporary instances and snapshots from this test were deleted after
  evidence capture.
- App TPM-access is governed by measurement, not by a container sandbox. An
  earlier iteration of this branch added a structural Docker Compose/app-compose
  security validator, rejected app `init_script`, and ran `app-compose.service`
  with `PrivateDevices=yes`/`DevicePolicy=closed`. That filter and those unit
  settings were removed for parity with TDX and SEV-SNP, which carry no such
  filter, because they were not a real trust boundary under dstack's model. App
  code — `init_script`, `pre_launch_script`, and the docker-compose — is measured
  into the app-compose hash, hence into the on-chain-whitelisted app identity, and
  replayed into non-resettable `PCR14`, so an operator cannot alter app inputs
  without changing the measured identity and being denied key release.
  `init_script` is now allowed and treated as measured, app-owned code. The app
  is trusted after launch: through `dstack.sock`, the decrypted disk, and
  decrypted env it already holds everything the TPM-sealed seed protects, and
  measured guest-root scripts could reach the TPM regardless, so blocking app
  containers from `/dev/tpm*` was never the boundary. The load-bearing P8
  controls are measurement plus non-resettable `PCR14`, the same as on TDX and
  SEV-SNP.
- KMS self-authorization and image verification are already fail-closed in the
  dstack KMS production defaults. `kms.toml` sets
  `enforce_self_authorization = true` and `[core.image] verify = true`.
  Trusted key/cert RPCs call `ensure_self_allowed()` before releasing material,
  and app/KMS attestation paths call the auth API with verified `BootInfo`
  before image verification and key derivation. AWS NitroTPM reuses the standard
  authorization path: because a verified NitroTPM attestation has no TDX/SNP-style
  TCB advisory surface, dstack normalizes it to `tcbStatus = "UpToDate"` (the same
  way AMD SEV-SNP normalizes its own status), so it passes the standard
  `allowedTcbStatuses` gate (default `["UpToDate"]`) with no AWS-specific enum or
  empty-`tcbStatus` rule. Nitro Enclave stays empty and fail-closed. `auth-simple`
  still allowlists OS image hash, KMS identity (including the `kms.composeHashes`
  option), app compose hash, and device ID. AWS NitroTPM key release
  additionally requires the opt-in `aws_nitro_tpm_key_release` flag in `kms.toml`
  (disabled by default, like `sev_snp_key_release`), so an upgraded KMS never
  releases keys to the new AWS mode until an operator explicitly enables it.
  Verification on the current source:

  ```text
  npx vitest run
  result: 18 passed

  npx oxlint .
  result: 0 warnings, 0 errors

  cargo test -p dstack-kms aws_nitro_tpm -- --nocapture
  result: 8 passed
  ```
- AWS `PCR14` positive launch measurement has live EC2 evidence from the same
  source line. The July 4, 2026 run built a Yocto prod UKI package on
  `phala-onprem` from parent meta-dstack commit `7d1ec56` and dstack commit
  `591b5625`, using a measured app `MrConfigV3` fixture:

  ```text
  AMI: ami-08f1eaaf091830a12
  AMI name: dstack-pcr14-positive-20260704
  root snapshot: snap-0b0c222e0e3a444ef
  import task: import-snap-82428df512ed7362t
  instance: i-0a55b16622b698094
  instance type: m6i.large
  launch time: 2026-07-04T07:44:15+00:00
  shared snapshot: snap-076523551b85461f6
  data snapshot: snap-032e134d0bb685cc6
  UKI package sha256: 0ed93c8245c21ccdbff30b9ed7fb054b18e469e232a7881c5e159b22d8967c01
  bare-metal package sha256: f740c052b304e07ffb18d051cdd9c0aef263669c02770d92209d2e3538da408b
  root disk raw sha256: 8f98a39ef307546172abc67aeb9b18fb1b54272c024c716a17665da24a041afc
  UKI Authenticode sha256: d1937841dd86546aee4c66edc0f2d210583da32b980f754085a88620029d0a78
  mr_config_id: 0353d1503b71e1c87d3797b986e83051967d26180ed59e0139bcbe307d0fc312bb000000000000000000000000000000
  compose_hash: 670a6e2b4581d36d9e775fbd2aca4eaecc99f8cb79153e5ce1154c18e5014e26
  observed os_image_hash: 4f207833420110d4c4dea2dba7cab027c9d9028d0598095bb6f097814475d8e2
  observed mr_aggregated: 2c4734084fa644014a3f5cd3d165d196423719553622cefa78e5b005acd917b1
  console sha256: 94c057609f6ac839dd77649fbe51dc96cebc47e4de87e575fc298c6b288e4c40
  ```

  The measured app observed `cloud_vendor = "Amazon EC2"`,
  `cloud_product = "m6i.large"`, and `DSTACK_ATTEST_RESPONSE_BYTES=10970`. (This
  run reused a fixture from the later-removed TPM-hardening iteration; its
  `/dev/tpm*`-visibility and hardening markers no longer describe current
  behavior, but the PCR14-positive launch measurement is unaffected.) The test
  instance was terminated after collecting console evidence; the AMI, root
  snapshot, and imported raw-disk S3 object were kept for follow-up verifier
  work.
- AWS NitroTPM recipient-key evidence is now preserved after verification.
  Remote dstack commit `3427a379` carries NitroTPM `public_key` and `nonce`
  from the signature-verified document into `AwsNitroTpmVerifiedReport`, with
  accessors for KMS and verifier code. Parent meta-dstack commit `e214775`
  points at that dstack commit.
- AWS app-key release is now recipient-key bound in source. Remote dstack commit
  `373bd99f` adds `GetAppKey` API v2: on AWS NitroTPM, the guest generates an
  X25519 recipient key, embeds the public key in the NitroTPM-backed RA-TLS
  client certificate, and KMS returns only an `X25519-AES-256-GCM` encrypted
  serialized `AppKeyResponse`. KMS rejects v2 key release unless the verified
  NitroTPM document contains the recipient public key. Parent meta-dstack commit
  `7ff27e6` points at that dstack commit. The live EC2 smoke test below proved
  this path end to end from a measured dstack-os client app to a measured
  dstack KMS app.
- AWS local `mr_config` enforcement now runs before any app-key request. Live
  negative testing with the previous AMI showed that a changed shared
  `app-compose.json` failed locally with `Invalid mr_config compose_hash`, but
  only after the dev KMS had already returned `GetAppKey` successfully. Remote
  dstack commit `cb4e0fbe` moves the AWS static `mr_config` check before the
  `requesting app keys` step; parent meta-dstack commit `96df85f` points at
  that dstack commit. A rebuilt fixed-client AMI later proved the mismatch is
  rejected before any KMS key-release request.
- The first dstack-os EC2 AMI PoC extended the dstack runtime app identity into
  SHA384 `PCR23`, used NitroTPM as the local key provider, and retrieved the
  NitroTPM Attestation Document through raw TPM commands. This proved raw
  NitroTPM access and SHA384 PCR reporting. The production source plan now uses
  non-resettable `PCR14` for launch authorization and reserves `PCR23` for
  post-launch runtime telemetry.
- AWS `platform_instance_binding()` now mixes the NitroTPM endorsement primary
  public area into `instance_id`. The value is derived from per-instance TPM
  state rather than from the cloneable data disk, matching the GCP AK
  public-area binding model.
- The clone-style instance-binding test passed: two EC2 instances launched from
  the same AMI, shared config, data snapshot, app ID, and instance seed produced
  different `instance_id` values because the NitroTPM-derived binding differed.
- The raw NitroTPM request path must compute the vendor-command cpHash with the
  NV index name after writing the request. The write sets the NV `WRITTEN`
  attribute, which changes the TPM name. Using the pre-write name causes
  `TPM_RC_AUTH_FAIL`.

Remaining productionization work:

- Keep the hardened release manifest current for the exact source-integrated
  release candidate that will be promoted. Regenerate it with
  `os/yocto/tools/aws/generate-aws-ec2-release-manifest.sh` for any new source or AMI
  change and ship it with the Yocto input mirror, AMI registration data,
  app/KMS allowlists, freshness policy, and endpoint identity policy.
- Promote the exact hardened P4 artifact with
  `dstack-cloud deploy` (`platform: aws`) to import the Attestable AMI and run
  a live instance against that AMI before release. The
  smoke evidence must include the promoted AMI ID, root/shared/data snapshots,
  explicit workload success markers, and serial-console hash. This is a
  release-candidate gate, not a per-CI job. Attach the promotion and smoke
  records to the final manifest with
  release evidence packaging (AMI id / shared snapshot / console logs), which validates the disk hash,
  Attestable AMI settings, AMI identity, region, and passed smoke status before
  updating the manifest.
- Deploy the external AWS verifier workflow and production auth/governance
  policy with real allowlists for every dynamic app and KMS deployment.
  `docs/aws-ec2-production-verifier-runbook.md` now packages the
  relying-party workflow. The config-file `auth-simple` path and on-chain
  `DstackKms` path can both express the AWS NitroTPM policy shape; rollout
  still needs deployment-specific allowlists and policy endpoints.
- Enforce the production endpoint identity mode in deployment. AWS EC2
  attestation verifies the instance state, not DNS, load balancers, or
  admin-controlled proxies. `ra-tls::attestation::verify_der` /
  `verify_pem` and `dstack-verifier --verify-cert` now verify a TLS
  certificate's embedded dstack attestation and bind it to the certificate
  SubjectPublicKeyInfo. Public services must require this RA-TLS path, signed
  responses, or an attested gateway so endpoint identity is bound to verified
  NitroTPM evidence.
- Keep live EC2 fault injection as a release-candidate test suite rather than
  per-CI work. Source tests cover omitted/reordered/duplicated PCR14 replay and
  freshness failures; live EC2 has already covered changed PCR14 replay, PCR14
  non-reset, production KMS policy denial, same-instance sealed-state recovery,
  and EBS clone failure. Optional extra live
  evidence includes omitted/reordered/duplicated PCR14 AMIs, live auth-eth
  deployment, PCR23 runtime telemetry policy, terminate/recreate sealed-state
  behavior, non-attested KMS calls, and admin-controlled network proxy tests.

## Ubuntu NitroTPM Fast-Track PoC

To test the AWS mechanics before building a custom dstack OS image, I registered
a temporary Ubuntu 24.04 AMI with `--boot-mode uefi` and `--tpm-support v2.0`,
launched an `m6i.large` NitroTPM-enabled instance, and installed only the tools
needed for TPM and attestation testing.

Confirmed results:

- NitroTPM device exists as `/dev/tpm0` and `/dev/tpmrm0`.
- `tpm2_getcap properties-fixed` reports manufacturer `AMZN`, vendor strings
  `Nitr`/`oTPM`/`v1.0`, and 24 PCRs.
- PCR extend works. Extending `PCR23` in the SHA256 bank with two deterministic
  app events produced:
  `0x97C31F439314CCD11ECB51E8BE972D779B2B2F166B6F2D99FE4E05511D6E620F`.
- Local TPM sealing works. A secret sealed under SHA256 `PCR4`, `PCR12`, and
  `PCR23` unsealed in the matching measured state and failed after `PCR23` was
  mutated.
- Reboot continuity works for local TPM sealing. After reboot, `PCR23` returned
  to zero; unseal failed before event replay; replaying the same two app events
  recovered the same PCR value and unseal succeeded.
- `PCR23` reset is supported. This is not fatal, but it is a hard design
  requirement: untrusted app/runtime code must not get TPM access that can reset
  or rewrite the app measurement after secrets are released.
- `PCR14` reset is rejected by NitroTPM from local root. In a July 4, 2026
  run, `tpm2_pcrreset 14` returned `Esys_PCR_Reset(0x907) - bad locality`.
  PCR14 stayed
  `0x937437D07298010015F4598395C9F8DC202EF36E0BE3897BBA89874BF612B5DA092BEADFE37F79714A60193819E384AD`
  before and after the reset attempt. As a control, PCR23 extended to
  `0xDABD351D7E252376AA1A8E6787ABCBE6DA54CCE97653D48E8B1A6C10C556504A2A24CDFA621E9819B98695D22851B87D`
  and reset back to zero.
  Evidence used Canonical source AMI `ami-0bd515973f5bcf6a0`, copied snapshot
  `snap-0979b10198935d925`, temporary TPM-enabled AMI
  `ami-0b38f2ab34cbb37d4`, and instance `i-0c20350cd6369ea44`; the copied
  snapshot and temporary AMI were deleted after the test. Console SHA256:
  `a5eaf40e7fe2f206daeb11a7cbd0e4c77edd630e96c4e1f8882ec705db7c2c66`.
- `nitro-tpm-attest` builds and runs on Ubuntu from the AWS
  `NitroTPM-Tools` crate with current Rust and TSS headers.
- NitroTPM Attestation Documents were retrieved with an RSA public key,
  `user_data`, and nonce. I decoded the CBOR/COSE document, verified the ES384
  COSE signature, verified the AWS Nitro certificate chain to the documented
  AWS Nitro root fingerprint, and confirmed that `public_key`, `user_data`, and
  `nonce` are signed fields.
- NitroTPM Attestation Documents use `digest = SHA384` and report the SHA384 PCR
  bank. Extending only SHA256 `PCR23` leaves attested `PCR23` as zero. Extending
  the same logical app events into SHA384 `PCR23` produced:
  `2EDF9FF51D1457C97BCC0167C2D70F17B966201E05A7D08FF4ED0B7C4E668E4644EFA6E127A997F3B2575007BA5C507E`,
  and the signed Attestation Document carried that exact value.

This confirms the user's proposed split is feasible: use a stock Ubuntu AMI to
validate NitroTPM attestation and local-key behavior now, then build dstack-os
for AWS EC2 as the next track.

## dstack-os EC2 AMI PoC

The dstack-os track now boots on EC2 with NitroTPM enabled.

Confirmed on July 1, 2026:

- Built a dstack guest image with AWS kernel support for UEFI, NVMe, ENA, serial
  console, and TPM 2.0 CRB.
- Imported the raw disk into EC2 and registered it with `--boot-mode uefi` and
  `--tpm-support v2.0`.
- Booted AMI `ami-09bab4df72390a4d8` on `m6i.large` with a persistent data disk
  and a FAT `DSTACKSHR` shared disk.
- The guest reached `/dev/tpm0`, mounted the data disk and shared disk, used
  `key_provider = "tpm"`, generated TPM-backed app keys, created an encrypted
  persistent data filesystem, emitted dstack measurements, and finished
  `dstack Guest Preparation Service`.
- The guest mixed the NitroTPM endorsement primary public area into
  `instance_id`, giving AWS EC2 the same clone-resistant instance binding shape
  as the GCP vTPM AK public-area binding.
- The NitroTPM Attestation Document path works without `tss-esapi`. The guest
  uses the in-tree raw TPM stack for EK creation, auth NV buffer setup, salted
  HMAC sessions, and AWS vendor command `0x20000001`.

Boot evidence from the successful run:

```json
{
  "app_id": "2222222222222222222222222222222222222222",
  "compose_hash": "bddbfa46bf9aec748426c8c0082a07f5f1ededc63f6b03ce9e22f51ec7b8d014",
  "instance_id": "fcf33079e02bef01fb11cc56df254948200f2a7f",
  "device_id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "mr_system": "802d79651518d7563c2adaec5947dc7312115882febab64ac1a510b5a6241a8b",
  "mr_aggregated": "2acef63154c750f71a5bb5371c78a823c95870780af7dece290d105f530b482f",
  "os_image_hash": "4949b39e5cefef09290a9a29b807034a17306a44a58a0c8b96e569d7f45470fe"
}
```

Clone-style binding check from a second EC2 instance launched with the same AMI,
same shared config, same data snapshot, same app ID, and same
`instance_id_seed`:

```json
{
  "instance_id": "27b3eea65c95e90dac487dc96dc0792beca745bd",
  "mr_system": "2ebaabc14ab0892d3f1f8422591d807a904092c5c0e7e05a1d7ca6f3056d01eb",
  "mr_aggregated": "60494c081d2b789a79a0bf174fd2d18704183381ea8cc23564e36210e36d2beb",
  "os_image_hash": "4949b39e5cefef09290a9a29b807034a17306a44a58a0c8b96e569d7f45470fe"
}
```

The `os_image_hash` stayed the same while `instance_id`, `mr_system`, and
`mr_aggregated` changed, as expected when only the per-instance NitroTPM binding
and TPM key-provider identity differ.

Build artifacts for that AMI:

- Raw disk SHA256:
  `21a616427bf81c87e71932b7ebbd69b00d539cde7edc3d4318b6142a00aac2e9`
- UKI Authenticode hash:
  `bc1e10926d00a0a68fca71a71e41bd51645ef8cc07996af7e528d5cec7aeb188`

This proves the OS image can boot as an AWS attested EC2 instance and can use
NitroTPM for both local key provider and attestation-document generation. It
does not yet prove production readiness because the dstack KMS policy path,
external verifier workflow, automated sealed-state coverage, and broader
negative tests are not complete.

The clean P2 AMI has a verifier-facing reproducibility manifest in
`docs/aws-ec2-ami-reproducibility-manifest.md`. That manifest records AMI
metadata, clean source pins, raw disk/UKI/rootfs hashes, AWS reference PCRs, and
the dstack `os_image_hash` derivation for `ami-058f0124934d7a144`.

Clean P2 smoke-test evidence from `2026-07-01T22:43:54+00:00`:

```text
DSTACK_PLATFORM_JSON={"platform":"aws-ec2","attestation":"dstack-aws-nitro-tpm"}
DSTACK_GETQUOTE_ATTEST_LEN=11092
DSTACK_ATTEST_LEN=11092
DSTACK_AWS_API_TEST_OK
"os_image_hash": "c2d6f2d20b1f0ec3a73661a63bfe2edc091ff1d555241de48742245a02754a91"
```

This satisfies the P2 base-image evidence gate for this AMI, subject to release
process work: reproducible source/input publication, mirrored Yocto inputs, and
a kernel config audit for the hardening symbols that configcheck reported as not
present in the active kernel config.

Final P4/API-smoke evidence from July 2, 2026:

```text
P4 boot-validation AMI: ami-0d228faa2192ce552
API-smoke AMI: ami-01612ca905fdda978
DSTACK_PLATFORM_JSON={"cloud_vendor":"Amazon EC2","cloud_product":"m6i.large","compose_hash":"f3fe256d2531bd60b27e16848db66c084abead49678458448b2d7d4a49bd6922","os_image_hash":"c5b4b08bcbee6c315ad3b9a8bba58bbc8f1164d44ebbda8e72f78e9ddb841d5a","mr_aggregated":"092a303a342353c020c5c627a930e66744f33c8546478430bdc214a651bfdfa0"}
DSTACK_ATTEST_LEN=10949
DSTACK_AWS_API_TEST_OK
```

The measured API-smoke app confirms that the final AWS dstack-os path can boot
with NitroTPM, enforce the measured app config, expose platform-specific
parameters through the dstack API, and return NitroTPM attestation evidence from
inside the measured runtime. This is positive P4 evidence. By itself, it is not
a full production key-release proof because it does not exercise dstack KMS
authorization or recipient-bound key release. The next smoke covers the positive
`GetAppKey` API v2 path; production still needs external verifier/auth policy.

Final `GetAppKey` API v2 smoke evidence from July 2, 2026:

```text
KMS AMI: ami-06a48f10cca0701bf
KMS instance: i-05a5d09e4071c3372
KMS app_id: 3333333333333333333333333333333333333333
KMS compose_hash: 588727a8dc3bd9fd22375de83e2d90ab66f527e53b6278757ac9da94fcd05807
KMS mr_config_id: 031b16f5c37fa825ce2e853e5faf05e92a2e1e05905de45cc8a866b41b82efd2a1000000000000000000000000000000
KMS binary SHA256: 61b3b55531d97859d41871167078768f658f196264023c3be5bdd4c0e6cda465

Client AMI: ami-0863e9a672f7c0804
Client instance: i-071fdb8f12d8b739b
Client app_id: 4444444444444444444444444444444444444444
Client compose_hash: f3519b7b94f72d5d25c7f25b1e3bebd1223ce53c7fbbb6ea0c27e3a18cd6354f
Client mr_config_id: 036c3e640594b2561e888ba02030fb64eae69be4ee23343ba8ec8ac7cc869d8165000000000000000000000000000000

DSTACK_PLATFORM_JSON={"cloud_vendor":"Amazon EC2","cloud_product":"m6i.large","compose_hash":"f3519b7b94f72d5d25c7f25b1e3bebd1223ce53c7fbbb6ea0c27e3a18cd6354f","os_image_hash":"909827b3e71e8a46771d9286c45ec77d06c954706aa076798c6c843d85516f3d","mr_aggregated":"c4d64f43ea17b1e073102b6399b0624873bd8d9768c823e6c2d34a542433cca8"}
DSTACK_APPKEYS_PATH=/dstack/.host-shared/.appkeys.json
DSTACK_AWS_GETAPPKEY_V2_TEST_OK
```

The KMS server logged a successful `/prpc/GetAppKey` request after verifying
the client's NitroTPM-backed RA-TLS evidence. The client setup wrote
`.appkeys.json`, which means the guest decrypted the `X25519-AES-256-GCM`
response encrypted to the public key carried in its verified NitroTPM
Attestation Document. This proves the positive recipient-bound app-key path on
EC2.

This smoke used development KMS settings: KMS self-authorization was disabled,
the auth API was a local development backend, and image verification was
disabled. The test proves the cryptographic AWS recipient binding and dstack-os
guest/KMS integration. It does not prove production governance authorization.
The KMS payload was embedded in the measured app compose document and the
measured script verified the KMS binary hash before running it, so the smoke did
not depend on an unmeasured S3 download. A client-side diagnostic command had a
`jq` quoting bug when printing `/Attest` length, and the demo certificate
signing path was not configured; neither path is part of the successful
`GetAppKey` API v2 key release.

Negative compose-mismatch evidence from July 2, 2026:

```text
KMS AMI: ami-06a48f10cca0701bf
KMS instance: i-0fabf272c7743096c
Client AMI: ami-0863e9a672f7c0804
Client instance: i-05160165c2055d5f7
Bad shared snapshot: snap-076dc06f99543915c
Expected compose_hash in measured mr_config: f3519b7b94f72d5d25c7f25b1e3bebd1223ce53c7fbbb6ea0c27e3a18cd6354f
Actual mutated app-compose hash: 0fa2d98cd4ca44c1db09a967b65b63b5815e932ffa0793552a0b8b9e2456d339
Bad shared raw SHA256: 54568a7f9f456742be295cf5cbbf0ebb439937808c2948b5f19cde41efa53ebf

dstack-prepare.sh:   "compose_hash": "0fa2d98cd4ca44c1db09a967b65b63b5815e932ffa0793552a0b8b9e2456d339",
dstack-prepare.sh: Error: Failed to verify app
dstack-prepare.sh:     Invalid mr_config compose_hash
```

This negative test proves the measured dstack-os guest rejects runtime app
content that does not match the boot-measured AWS `dstack.mr_config_id`. It also
found a release-ordering bug in the tested AMI: because `verify_app` ran after
`request_app_keys`, the dev KMS logs show successful `GetAppKey` responses
before the local failure. Source commit `cb4e0fbe` fixes that ordering by
checking AWS `mr_config` before key release. The rebuilt fixed-client rerun
below confirms the guest now rejects the mismatch before any KMS key-release
request.

Rebuilt fixed-client negative evidence from July 2, 2026:

```text
Fixed client meta-dstack commit: 96df85fe65439db9d0e016f0b3541189101c5e5f
Fixed client dstack commit: cb4e0fbe
Fixed client AMI: ami-0abff2f0d04966602
Fixed client root snapshot: snap-0836d13f87406b844
Fixed client root disk raw SHA256: 5376a1c6ca52c1a452b6626caf6bc8b725eca08088ea2adb9fe290fdac636342
Fixed client dstack-0.6.0.tar.gz SHA256: 2298d1facb377ec6f18cda89ab48280538e590eccde1e3a8f759ba87d506e153
Fixed client dstack-0.6.0-uki.tar.gz SHA256: 173f7e60e58de332911ade3b42811244f5058c3a21655c87784a0d5f4966d2e2
Fixed client dstack-uki.efi SHA256: 56335e704119ef7e43eced668f3f78feee89d55900378519faa7f2ec0a63bf75
Fixed client UKI Authenticode hash: 5f3075dfca7e3f7e3705077e00bb05c888017a1782ea41dedc09d02d59c3e7c8
Fixed client mr_config_id: 036c3e640594b2561e888ba02030fb64eae69be4ee23343ba8ec8ac7cc869d8165000000000000000000000000000000
Fixed client observed os_image_hash: c0d9285e1d8fc3baf6d1b45fd9890bbdb71ab16a7c4c920a7065fc793c8011b1
Fixed client observed mr_aggregated: 75ee8db10e454d52b0fbcacae17739cd7e192241061bb424d9d290363df78593

KMS AMI: ami-06a48f10cca0701bf
KMS instance: i-02e190d949f9cc88b
Fixed client instance: i-06ea578bc04964b93
Bad shared snapshot: snap-02a191ca3c018bb32
Expected compose_hash in measured mr_config: f3519b7b94f72d5d25c7f25b1e3bebd1223ce53c7fbbb6ea0c27e3a18cd6354f
Actual mutated app-compose hash: 0fa2d98cd4ca44c1db09a967b65b63b5815e932ffa0793552a0b8b9e2456d339
Bad shared raw SHA256: 896204414e94056928beec03a7764b14ffa71846a5d9542712d39e7d0e72739f

dstack-prepare.sh:   "compose_hash": "0fa2d98cd4ca44c1db09a967b65b63b5815e932ffa0793552a0b8b9e2456d339",
dstack-prepare.sh: Error: Failed to verify app before key release
dstack-prepare.sh:     Invalid mr_config compose_hash

KMS console after client launch: no POST /prpc, no GET /prpc, no Matched request
entries, and no request-path GetAppKey/GetTempCaCert entries. The only
GetAppKey/GetTempCaCert strings were the KMS startup supported-method route list.
```

This rerun closes the release-ordering bug for the rebuilt client AMI. The guest
failed before app-key release, and the KMS console showed no request from the
mismatched client. The test still used development KMS settings, so it proves the
negative local guard ordering and AWS guest/KMS integration. It does not prove
production governance authorization.

NitroTPM sealed-state evidence from July 2-3, 2026:

```text
API-smoke AMI: ami-01612ca905fdda978
Shared snapshot recreated from shared.raw: snap-071887373768d13cc (temporary, deleted after test)
Blank data snapshot source: snap-032e134d0bb685cc6

Primary instance: i-0d6cab189d7cf246a
Primary first boot:
  no sealed seed found, generating new seed...
  key_provider_id: 3059301306072a8648ce3d020106082a8648ce3d030107034200040c0cc69aac8795f3f29d46099b53f6875f0c19ea72b09d9b4729c2c2ad3dabf0a642e320edc5ff2cdaac42c4f1921569dc364fb6879a2394710b0ba97fcb0fad
  instance_id: ed1c6fa204027c42fe31e4f8ba25dd197390485b
  DSTACK_AWS_API_TEST_OK

Primary second boot after EC2 force-stop/start:
  unsealed root key seed from TPM (PCR policy: sha384:4,7,12,23)
  key_provider_id: 3059301306072a8648ce3d020106082a8648ce3d030107034200040c0cc69aac8795f3f29d46099b53f6875f0c19ea72b09d9b4729c2c2ad3dabf0a642e320edc5ff2cdaac42c4f1921569dc364fb6879a2394710b0ba97fcb0fad
  instance_id: ed1c6fa204027c42fe31e4f8ba25dd197390485b
  DSTACK_AWS_API_TEST_OK

Clone instance: i-01d38337d87e9f91c
Clone data snapshot from primary data volume: snap-0053b9f6705d81bf8 (temporary, deleted after test)
Clone boot:
  unsealed root key seed from TPM (PCR policy: sha384:4,7,12,23)
  key_provider_id: 3059301306072a8648ce3d020106082a8648ce3d03010703420004c3c3c3e592b862c86788a7d0e28964fe7ae96e5e8eafa6cfde5555f34f98533ab2b48f7923e63cf73aaa0eefb1186bc81e804cd359180dbdfaf9c6c5654b0677
  No key available with this passphrase.
  Error: Failed to open encrypted data disk
  DSTACK_AWS_API_TEST_OK count: 0
```

The primary stop/start path proves that NitroTPM local sealed state survives the
same EC2 instance lifecycle when the measured PCR policy is reached again. The
clone path proves that cloning the EBS disks is not enough to recover the
primary app/data key: the clone used a different TPM key-provider public id and
could not decrypt the data disk sealed to the primary TPM-derived key. The EC2
force-stop was used because this minimal image did not complete graceful stop in
time; force-stop does not change the same-instance TPM-state property being
tested.

Production-mode KMS self-authorization and image-verification evidence from
July 3, 2026:

```text
Auth policy implementation:
  auth-simple accepts kms.composeHashes as a stable KMS identity allowlist and
  preserves exact kms.mrAggregated allowlists for pinned-MR tests.
  If both identity allowlists are set, both must match.
  Focused tests:
    npx vitest run index.test.ts in kms/auth-simple: 18 passed
    cargo test -p dstack-auth: 6 passed

Auth service:
  instance: i-05d2bb48a4703efac
  private IP: 172.31.37.195
  policy:
    allowedTcbStatuses: [""]
    osImages:
      - fe7c1c6eb46a5ededcdba2adbc31d83c6a1b346761796bf630c9c91215d2a4ae
      - 909827b3e71e8a46771d9286c45ec77d06c954706aa076798c6c843d85516f3d
    kms.composeHashes:
      - a5fe7fea1957e946683c5e8c7fc79555957d11017f652f6440b80fd15db1a8d3
    app 4444444444444444444444444444444444444444 composeHashes:
      - f3519b7b94f72d5d25c7f25b1e3bebd1223ce53c7fbbb6ea0c27e3a18cd6354f

KMS:
  AMI: ami-0a8c8ab8bb81ab5c4
  root snapshot: snap-0d2e4f80428b03e6b
  shared snapshot: snap-0cea8c981b6190925
  instance: i-0b13a71568b44a62f
  private IP: 172.31.34.4
  app_id: 3333333333333333333333333333333333333333
  compose_hash: a5fe7fea1957e946683c5e8c7fc79555957d11017f652f6440b80fd15db1a8d3
  os_image_hash: fe7c1c6eb46a5ededcdba2adbc31d83c6a1b346761796bf630c9c91215d2a4ae
  observed mr_aggregated: b8d883e593778526b5c86719999d5e8cbf11d17bab4cc113c091c8cdff62df28
  dstack-kms sha256: 5ecaf1d0912eae2ef6c6634f68a303cdb4687afc0b8f01e0b4f71be5e7dd6fdc
  config:
    enforce_self_authorization = true
    core.image.verify = true

Client:
  AMI: ami-0863e9a672f7c0804
  corrected shared snapshot: snap-03982636ae64f2f89
  instance: i-037e6ad6ca9d8dabf
  private IP: 172.31.41.215
  app_id: 4444444444444444444444444444444444444444
  compose_hash: f3519b7b94f72d5d25c7f25b1e3bebd1223ce53c7fbbb6ea0c27e3a18cd6354f
  os_image_hash: 909827b3e71e8a46771d9286c45ec77d06c954706aa076798c6c843d85516f3d
  observed mr_aggregated: 0fd85003e25b80a7d8c25b390fcf61c6f75cb145c1a71962f72728f71b14515e
  sys_config.vm_config: {"os_image_hash":"909827b3e71e8a46771d9286c45ec77d06c954706aa076798c6c843d85516f3d"}
  success markers:
    DSTACK_APPKEYS_PATH=/dstack/.host-shared/.appkeys.json
    DSTACK_AWS_GETAPPKEY_V2_TEST_OK
  KMS console:
    /prpc/GetTempCaCert status=200
    /prpc/GetAppKey status=200
```

Two negative observations from the same run are important for production
configuration:

- Reusing a previous KMS `mr_aggregated` is not a valid allow-any-device AWS
  policy. A fresh KMS instance produced a different `mr_aggregated` because the
  AWS NitroTPM key-provider binding is instance-specific. For AWS KMS
  self-authorization, use stable KMS `compose_hash` plus OS image when the
  policy intentionally allows any device, or pin an exact `mr_aggregated` only
  for a specific instance.
- The first client shared disk sent `vm_config = "{}"` to KMS. The client could
  compute its own `os_image_hash`, but KMS policy saw an empty `osImageHash` and
  denied `GetAppKey` with `OS image is not allowed`. The corrected shared disk
  included `vm_config.os_image_hash`; KMS then accepted policy and performed
  image verification before returning keys.

Production-policy negative evidence from July 3, 2026:

```text
Setup:
  Reused the positive-path auth/KMS/client AMIs and shared disks.
  Auth was relaunched at private IP 172.31.37.195.
  KMS was relaunched at private IP 172.31.34.4 with:
    AMI: ami-0a8c8ab8bb81ab5c4
    data snapshot: snap-032e134d0bb685cc6
    shared snapshot: snap-0cea8c981b6190925
    enforce_self_authorization = true
    core.image.verify = true
  Client was relaunched with:
    AMI: ami-0863e9a672f7c0804
    data snapshot: snap-032e134d0bb685cc6
    shared snapshot: snap-03982636ae64f2f89

Policy mutation:
  KMS compose hash remained allowlisted:
    a5fe7fea1957e946683c5e8c7fc79555957d11017f652f6440b80fd15db1a8d3
  Client app 4444444444444444444444444444444444444444 was changed from:
    f3519b7b94f72d5d25c7f25b1e3bebd1223ce53c7fbbb6ea0c27e3a18cd6354f
  to an all-zero compose-hash allowlist entry.

Observed result:
  KMS instance: i-0ed161f54b8952cee
  KMS observed mr_aggregated:
    dfb1f41bfe605fd34dedadc27b4c4ef3c4fa875d474e744da52fe42ddfb33663
  Client instance: i-0f846a957bec506c4
  Client private IP: 172.31.43.72
  Client did not print DSTACK_AWS_GETAPPKEY_V2_TEST_OK.
  Client dstack-prepare failed before app start:
    Failed to get app keys from KMS https://172.31.34.4:8000/prpc
    Request failed with status=400 Bad Request
    "error": "App not allowed: Boot denied: compose hash not allowed"
  KMS console showed:
    /prpc/GetTempCaCert status=200
    /prpc/GetAppKey status=400
    rpc error: App not allowed
    Boot denied: compose hash not allowed

Evidence files:
  /tmp/dstack-prod-kms-test/negative-client-wrong-compose-policy-console.log
    sha256 d2038c9d4709bc8dcb13a7c10d1f33c48171bff21c7f2db136c423e596b5e8fa
  /tmp/dstack-prod-kms-test/negative-kms-after-wrong-compose-policy-console.log
    sha256 c92c5cca700774fdab2c43757b6f1fb07ef954e34bc9df7202f9a8c6b195b191
  /tmp/dstack-prod-kms-test/negative-auth-console.log
    sha256 6e1b5483041a3ab8e5bc8202fff82a5d6328c8bcf62734f2556527d4e5665a1b
```

TPM access hardening live EC2 evidence from July 3, 2026 (superseded hardening
iteration):

An earlier iteration of this branch added a structural compose-security
validator, rejected app `init_script`, and ran `app-compose.service` with
`PrivateDevices=yes`/`DevicePolicy=closed`. A July 3, 2026 live EC2 run
(meta-dstack commit `30c6fed`, dstack commit `b3b28196`, common app_id
`5555555555555555555555555555555555555555`, `key_provider=tpm`,
`kms_enabled=false`, region `us-west-2`) booted a positive AMI plus negative
AMIs that rejected `init_script`, `privileged: true`, direct `/dev/tpmrm0`
exposure, and `/var/run/docker.sock` bind mounting before app execution. That
compose filter and the `PrivateDevices`/`DevicePolicy` unit settings were later
removed for parity with TDX and SEV-SNP, so those negative cases no longer
describe current controls; see the measurement-based P8 argument above
(`init_script` is now allowed as measured, app-owned code). Instances were
terminated after evidence capture.

One result from that run is independent of the removed filter and remains valid:

```text
AWS KMS non-use check:
  The live app configs used key_provider=tpm and kms_enabled=false.
  CloudTrail lookup for EventSource=kms.amazonaws.com from
  2026-07-03T11:00:00Z through 2026-07-03T12:00:00Z in us-west-2 returned [].
```

## External Verifier and Auth Policy

The external verifier is the component, service, or relying-party library that
checks AWS NitroTPM evidence outside the untrusted workload account before it
accepts a workload, KMS, or key-release result. It must verify the AWS NitroTPM
signature chain, freshness (`nonce` or timestamp policy), measured boot PCRs,
`PCR14` launch event replay, `mr_config_id`, recipient public key binding, and
the expected dstack `BootInfo` fields. The repository `dstack-verifier` now
emits this auth-policy object as `details.boot_info` after quote verification,
OS image binding, and event/PCR replay have all succeeded. A relying party can
feed that object directly to the same policy logic used by `/bootAuth/app` or
`/bootAuth/kms`.

Production AWS NitroTPM verification should also pass a non-empty
`freshness` policy to `dstack-verifier`. The policy can bind the verified
`report_data` challenge, NitroTPM `nonce`, NitroTPM `public_key`, and maximum
attestation-document age. `details.freshness_verified` is true only after those
requested checks pass; an empty freshness policy is rejected. The lower-level
AWS/Nitro verifier already rejects stale or far-future attestation document
timestamps, but explicit nonce/report-data binding is still required for
challenge-response replay protection. If the relying party consumes app-owned
runtime telemetry, it should verify the separate `PCR23` runtime chain as a
post-launch property.

The auth/governance policy is the allowlist that says which verified states may
receive secrets or serve as KMS. For AWS this policy should include at least:

- a verified AWS NitroTPM attestation, normalized to `tcbStatus = "UpToDate"` so
  it passes the standard authorization gate (and gated by the opt-in
  `aws_nitro_tpm_key_release` KMS flag),
- accepted dstack OS image measurements and build inputs,
- accepted AWS boot PCRs for the exact AMI/UKI path,
- accepted app `compose_hash`, `app_id`, and `mr_config_id`,
- required `PCR14` launch event chain and derived `mr_aggregated`,
- optional `PCR23` app runtime telemetry policy when the workload exposes
  post-launch events,
- accepted dstack KMS app identity. Prefer KMS `compose_hash` plus OS image for
  AWS allow-any-device policy; use exact KMS `mr_aggregated` only for a pinned
  instance or a platform path where that value is stable across deployments,
- freshness and recipient-key requirements for key release.

For AWS NitroTPM, a verified attestation has no TDX/SNP-style `tcbStatus`
advisory surface, so dstack normalizes it to `tcbStatus = "UpToDate"` (the same
way AMD SEV-SNP normalizes its own status) and it passes the standard
`tcbStatus == "UpToDate"` gate through the unchanged authorization contract and
`allowedTcbStatuses` policy. The policy should still require the PCR, image,
launch-event, device, freshness, and recipient-key fields above, and the KMS
gates AWS key release behind the opt-in `aws_nitro_tpm_key_release` flag. Both the
config-file `auth-simple` path and the on-chain auth-eth `DstackKms` path express
this shape without any AWS-specific on-chain field.

This policy must not be mutable by the untrusted workload AWS account admin. It
can live in dstack governance contracts, a trusted control plane account, or an
external verifier/KMS service, but the account admin running the workload must
not be able to weaken it.

## Platform Security Property Spec

The following properties are the readiness gates for any new platform claiming
the same security level as dstack under this threat model.

| ID | Required property | dstack mechanism | AWS attested-instance status |
| --- | --- | --- | --- |
| P1 | Verifiable platform root of trust | TDX/SNP/Nitro quote verification against vendor root; debug rejected; TCB surfaced | Satisfiable. NitroTPM Attestation Documents are signed by AWS Nitro Attestation PKI. Treat accepted NitroTPM state as production-only policy; reject unexpected debug/config PCR states. Remaining gap: there is no dstack-equivalent TCB status/advisory field in the EC2 docs. |
| P2 | Reproducible or independently computable base image measurement | meta-dstack rebuild plus `dstack-mr` computes `MRTD`/`RTMR0-2` | Satisfied for the current hardened release candidate. `os/yocto/tools/aws/generate-aws-ec2-release-manifest.sh` produces a reproducibility manifest with clean source archive hashes, release artifact hashes, Yocto download content-manifest hash, AWS PCRs, dstack `os_image_hash`, UKI AuthentiCode hash, and a zero-failure, zero-warning hardening audit for meta-dstack `a3057cdc86f452a26f628c50f4a237a542fe9a6f` plus dstack `3da3b8a6b70b73c93a0a4a32bf94207c09317016`; run it against the app-specific build to produce the P4 package manifest from the same source state. Earlier live base-image evidence remains `ami-058f0124934d7a144`. Production still needs an actual mirrored Yocto input-content store or archive. The desired build shape is one Yocto pipeline that emits the AWS AMI package and the non-AWS guest-image packages from shared OS inputs. |
| P3 | Boot command line and root filesystem integrity are measured | `RTMR1/2`, rootfs hash, dm-verity, measured initrd/cmdline | Satisfiable if dstack KMS/verifier policy checks the AWS reference PCRs for the exact boot path. For the current UKI package, embedded cmdline and rootfs metadata are committed by the UKI/PCR4 measurement and rootfs dm-verity hash. For a standard boot path with external command line, policy must also check `PCR12`; missing `PCR12` is a known account-operator bypass for that boot mode. |
| P4 | Runtime application identity is cryptographically bound | RTMR3 `compose-hash`, `app-id`, `instance-id`, `key-provider`; event log replay | Positive path implemented and smoke-tested by reusing dstack's RTMR3-style event model. GCP already verifies TDX RTMR3 plus a TPM quote, and SEV-SNP uses `MrConfigV3` through `HOST_DATA`. AWS computes `mr_aggregated` from `PCR4`, `PCR7`, `PCR12`, and verified SHA384 `PCR14` launch events; `dstack-attest`, dstack KMS, and `dstack-verifier` now reject missing/mismatched `PCR14`, missing `PCR12`, and reordered or duplicated pre-boundary launch-event replay in source tests before they emit policy `BootInfo`. AWS source requires `dstack.mr_config_id` in the measured cmdline and checks it against `MrConfigV3`. The hardened P4/API-smoke manifest embeds that target in the UKI, includes the expected `MrConfigV3` document and shared app disk as artifacts, and changes AWS reference `PCR4`; `PCR12` remains zero for this UKI path. AMI `ami-01612ca905fdda978` booted a measured app, exposed AWS platform parameters, returned NitroTPM evidence through `/Attest`, and printed `DSTACK_AWS_API_TEST_OK`. AMI `ami-08f1eaaf091830a12` booted the PCR14-positive launch path and produced the expected `mr_aggregated`. AMI `ami-014de51f12775d69a` proved a changed PCR14 launch history fails with `PCR14 mismatch` while retaining the valid `mr_config_id`. The July 4 Ubuntu NitroTPM negative test proved local root can reset PCR23 but cannot reset PCR14 (`PCR_Reset` fails with `bad locality` and PCR14 remains unchanged). The rebuilt fixed client AMI `ami-0abff2f0d04966602` rejected changed app content with `Invalid mr_config compose_hash` before key release, and the KMS console showed no request-path `GetAppKey` entry. Optional live EC2 coverage can still be added for omitted, reordered, and duplicated PCR14 histories. |
| P5 | Freshness and caller key binding | `report_data` challenge or RA-TLS public key hash in quote | Positive path satisfied by source and live EC2 smoke for AWS app-key release. NitroTPM supports `nonce`, `user_data`, and `public_key`. dstack preserves verified NitroTPM `nonce` and `public_key` in `AwsNitroTpmVerifiedReport`, RA-TLS binds `report_data` to the TLS certificate public key, and `GetAppKey` v2 encrypts the response to the X25519 public key embedded in the verified NitroTPM document. `dstack-verifier` now accepts an explicit `freshness` policy that checks expected `report_data`, NitroTPM `nonce`, NitroTPM `public_key`, and max document age before emitting `details.freshness_verified = true`; source tests cover matching policy, mismatched nonce/public key, stale timestamp, future timestamp, and empty-policy rejection. Live client `ami-0863e9a672f7c0804` retrieved app keys from measured KMS `ami-06a48f10cca0701bf` through this path. |
| P6 | Secret release only to attested code | dstack KMS verifies attestation, checks auth policy, derives per-app keys | Positive path satisfied by source and live EC2 production-mode smoke for AWS app-key release without AWS KMS. dstack KMS builds policy-relevant AWS `BootInfo` from verified NitroTPM boot PCRs plus `PCR14` launch events and encrypts `GetAppKey` v2 output only to the attested NitroTPM recipient key. The July 3 run used KMS self-authorization, auth-simple policy, and image verification. A live negative rerun removed the client app compose hash from auth-simple and KMS denied `GetAppKey` with `Boot denied: compose hash not allowed`. AMI `ami-014de51f12775d69a` proved changed PCR14 launch replay is rejected before app start. auth-simple supports AWS NitroTPM dstack KMS authorization by stable KMS `compose_hash` plus OS image, while preserving exact `mrAggregated` allowlists for pinned-MR tests. AWS reuses the unchanged on-chain `DstackKms`/`DstackApp` contract: a verified NitroTPM attestation is normalized to `tcbStatus = "UpToDate"` and passes the standard `tcbStatus == "UpToDate"` gate, exactly as AMD SEV-SNP does; AWS NitroTPM key release additionally requires the opt-in `aws_nitro_tpm_key_release` KMS flag (disabled by default), and a live auth-eth deployment test remains optional deployment evidence. |
| P7 | Key-release policy is not controlled by the untrusted account admin | KMS runs inside TEE; policy from auth API/contracts; KMS identity measured | Satisfiable with dstack KMS or another verifiable secret authority outside the untrusted AWS account admin's control. A NitroTPM-backed dstack KMS can keep root material out of account-admin snapshots and clones. The policy backend must be outside the untrusted workload account admin's control, whether it is auth-simple in a trusted control plane, dstack governance contracts, or another verifier-controlled service. Same-account AWS KMS fails this property if the admin can change key policy, create grants, or call secret-bearing operations through a policy they control. |
| P8 | Operator cannot inject boot-time or runtime inputs that affect secrets without detection | Host-shared files are either measured or independently authenticated; KMS URLs not trusted, KMS key identity measured | Satisfied for the tested dstack-os AWS path. AWS dstack-os images exclude SSH, cloud-init, SSM, EC2 Instance Connect, and serial login from the production rootfs evidence, and the hardened release audit reports `failures=0 warnings=0`. App TPM-access is enforced by measurement, not by a container sandbox: `init_script`, `pre_launch_script`, and the docker-compose are measured into the app-compose hash, hence into the on-chain-whitelisted app identity, and replayed into non-resettable `PCR14`, so an operator cannot alter app inputs without changing the measured identity and being denied key release. `init_script` is allowed as measured, app-owned code, and the app is trusted after launch because it already holds — via `dstack.sock`, the decrypted disk, and decrypted env — everything the TPM-sealed seed protects. An earlier compose-validator/`PrivateDevices` iteration was removed for parity with TDX and SEV-SNP, which carry no such filter. The platform must still avoid IMDS/operator-provided config as secret-affecting input unless that config is measured or authenticated. |
| P9 | Persistent state confidentiality from account admin | dstack disk key derived after attestation; encrypted env vars decrypted only inside CVM | Partially satisfied for the dstack-os local TPM path. Live EC2 evidence shows same-instance stop/start can unseal the same NitroTPM-backed seed under `sha384:4,7,12,23`, while a cloned EBS data disk on a different EC2 instance used a different TPM key-provider id and failed to decrypt the primary data disk. EBS snapshots and volumes remain account-admin visible at the AWS control plane level, so persisted confidential state must stay encrypted inside the instance and root AMIs must contain no secrets. Production still needs automated sealed-state tests and terminate/recreate coverage. |
| P10 | Network and TLS endpoint identity is attestation-bound | RA-TLS / Zero Trust HTTPS / gateway attestation; TLS keys generated in TEE | Source-satisfied for RA-TLS certificate verification. AWS EC2 attestation does not protect DNS, load balancers, or admin-controlled proxies by itself. The Rust RA-TLS verifier now exposes `verify_der`/`verify_pem`, which extract the dstack RA-TLS certificate attestation, verify it with the platform verifier including AWS NitroTPM, and require `report_data = QuoteContentType::RaTlsCert(SubjectPublicKeyInfo)`. `dstack-verifier --verify-cert` provides an operator/relying-party certificate evidence path. Production clients or gateways must require this RA-TLS check, signed responses, or an attested gateway before accepting a public endpoint. |
| P11 | Upgrade governance is explicit and non-bypassable | DstackApp/DstackKms whitelists compose hashes, OS images, KMS aggregate MRs | Source-satisfied for policy expression. auth-simple can pin the OS image hash, KMS aggregate MR, app compose hash, and device ID; AWS passes the standard `UpToDate` gate through `tcbStatus` normalization, and AWS NitroTPM key release is gated behind the opt-in `aws_nitro_tpm_key_release` KMS flag (disabled by default). The on-chain `DstackKms`/`DstackApp` contract is unchanged and carries no `attestationMode` field — AWS reuses it via the normalized `UpToDate` `tcbStatus`, exactly as AMD SEV-SNP does. Upgrades still require a trusted policy update or a Secure Boot certificate policy. AWS warns a PCR7 certificate policy can continue to allow old AMIs unless certificate/key rotation and revocation policy are handled. |
| P12 | Verifier is independent and complete | `dstack-verifier`, DCAP/QVL, RTMR replay, KMS/app/governance checks | Partially implemented. The repo can represent AWS NitroTPM evidence, verify the NitroTPM document with AWS Nitro PKI, check PCR-derived OS image hash, require PCR14 launch-event replay during AWS MR decoding, emit canonical auth-policy `details.boot_info`, build dstack KMS `BootInfo` from verified AWS boot PCRs plus launch events, enforce AWS `dstack.mr_config_id` against `MrConfigV3` in source, express the AWS policy in auth-simple and on-chain auth-eth, run live production-mode KMS self-authorization/image-verification tests, reject a live changed-PCR14 launch replay, publish hardened release evidence, and provide a production verifier runbook in `docs/aws-ec2-production-verifier-runbook.md`. Remaining work: instantiate the runbook with real deployment allowlists, optionally add live omitted/reordered/duplicated PCR14 fault-injection cases, and define optional PCR23 runtime-telemetry policy. |

## Readiness Decision

AWS EC2 instance attestation is not ready as a drop-in dstack replacement today,
but the custom dstack-os AMI path is now proven feasible. The P2 base-image gate
is satisfied for `ami-058f0124934d7a144` as a clean release-candidate evidence
set. The P4/API-smoke AMIs and the July 4 PCR14-positive AMI prove the positive
measured-app path on EC2, the
`GetAppKey` API v2 smoke proves positive recipient-bound key release from a
measured dstack-os client app to a measured dstack KMS app, the rebuilt fixed
client AMI proves a compose mismatch is rejected before key release, and the
sealed-state test proves the NitroTPM local key-provider state survives
same-instance stop/start but does not transfer with EBS clones. App TPM-access
is governed by measurement rather than a container sandbox: app inputs are
measured into the app-compose hash and non-resettable `PCR14`, so an operator
cannot change them without changing the on-chain app identity and being denied
key release, the same as on TDX and SEV-SNP. The platform becomes a credible
AWS-Nitro-rooted, account-admin-untrusted foundation only if every non-AWS
component remains verifier-checked: the OS image, the app measurement, the
dstack KMS instance, and governance policy.

The minimum viable AWS design is:

1. Build one reproducible dstack OS through Yocto and emit the platform packages
   from that build. The AWS output is an Attestable AMI package; the existing
   TDX/SEV/GCP output can remain the standard dstack guest-image package. Keep
   the rootfs, userspace, and kernel as common as platform boot constraints
   allow. Keep SSH, SSM, EC2 Instance Connect, serial login, cloud-init/user-data,
   and mutable operator hooks out of the production image and verification
   policy.
2. Use UKI + read-only rootfs + `dm-verity` (the current Yocto AMI uses
   squashfs). For the current UKI path, require the exact reference `PCR4` for
   the measured UKI and `PCR7` if Secure Boot policy is used. For a standard
   boot path that accepts an external command line, also require `PCR12`.
   Define certificate rotation/revocation so old AMIs do not remain authorized.
3. For dynamic apps, reuse the existing dstack RTMR3/MrConfigV3 app identity
   model. Pass the target app/config measurement through
   `dstack.mr_config_id=<MrConfigV3 hash>` in the measured kernel command line,
   enforce it in early measured init, and extend SHA384 `PCR14` with
   dstack-compatible launch events. Production policy must require both parts:
   the boot PCR that commits the target config ID (`PCR4` for the current UKI
   path, and `PCR12` as well for an external-cmdline standard boot path) and
   `PCR14` for the replayed launch event chain. Keep SHA384 `PCR23` available
   for app-owned runtime telemetry after `system-ready`, but do not use it as a
   pre-secret launch gate.
4. Put secret-release authority in dstack KMS or another verifiable KMS outside
   the untrusted AWS account admin's control. Prefer running dstack KMS on
   dstack-os EC2 with NitroTPM local sealing, then verify the KMS attestation and
   governed identity before trusting any key release. For the config-file path,
   use auth-simple with allowlists for OS image hash, KMS `compose_hash`, app
   compose hash, and device ID; a verified AWS NitroTPM attestation is normalized
   to `tcbStatus = "UpToDate"` and passes the standard gate, and AWS NitroTPM key
   release is gated behind the opt-in `aws_nitro_tpm_key_release` `kms.toml` flag.
   Use exact KMS `mr_aggregated` only when the policy pins a specific measured
   instance. Do not rely on same-account AWS KMS for the security baseline.
5. Generate an ephemeral public key inside the instance, include the public key
   in the NitroTPM Attestation Document, call dstack KMS, and decrypt the
   returned key material only inside the measured code.
6. Add third-party verification with a non-empty `dstack-verifier` freshness
   policy (`report_data` challenge, NitroTPM `nonce`, NitroTPM `public_key`,
   and max age as appropriate). Do not rely on a static attestation document
   for liveness.
7. Add attestation-bound TLS or response signing. KMS attestation alone does not
   prove the network endpoint a user is talking to is the measured workload.

## AWS CLI and Live PoC Observations

The local AWS CLI is current enough for this feature, and a temporary Ubuntu
NitroTPM instance was used for live validation:

- `aws-cli/2.35.6`
- Region: `us-west-2`
- `aws ec2 get-instance-tpm-ek-pub` is available and supports `rsa-2048` and
  `ecc-sec-p384`, with `der` and `tpmt` output formats.
- `aws kms decrypt --generate-cli-skeleton input` and
  `aws kms generate-data-key --generate-cli-skeleton input` both include
  `Recipient.KeyEncryptionAlgorithm=RSAES_OAEP_SHA_256` and
  `Recipient.AttestationDocument`.
- A live NitroTPM Attestation Document was generated and verified offline
  against the AWS Nitro PKI root.
- AWS KMS `Recipient` was not tested because AWS KMS is not part of the trusted
  baseline under the account-admin-untrusted threat model.

## Open Work Before Calling AWS Ready

The implementation is close enough to cut a production release candidate, but it
should not be called generally production ready until these release gates are
closed:

1. Keep the hardened release manifest current for the exact final AMI that will
   be promoted. Regenerate it with `os/yocto/tools/aws/generate-aws-ec2-release-manifest.sh`
   for any new AMI or source change. Binary signatures are optional for this
   stage; the relying party should trust reproducible rebuilds and measurements.
2. Mirror the Yocto input content. The current docs include a 5,328-file
   download content manifest and its SHA256, but production should publish the
   actual input mirror/archive so rebuilds do not depend on live upstream fetch
   availability.
3. Deploy the external verifier/auth workflow. Source now emits canonical AWS
   `BootInfo`, verifies freshness, rejects bad PCR14 replay, and both
   auth-simple and auth-eth can express the AWS NitroTPM policy shape.
   `docs/aws-ec2-production-verifier-runbook.md` defines the relying-party
   workflow; production still needs real allowlists for each app and KMS.
4. Bind public network endpoint identity to attestation in deployment. The repo
   now has RA-TLS certificate verification support and a `dstack-verifier
   --verify-cert` evidence path; production clients/gateways must require it, or
   an equivalent signed-response/attested-gateway design, so DNS/LB/proxy
   control in the untrusted AWS account cannot impersonate a verified workload.
5. Treat extra EC2 fault injection as release-candidate validation, not per-CI
   work. Useful remaining live evidence includes omitted/reordered/duplicated
   PCR14 AMIs, live auth-eth deployment, PCR23 runtime telemetry policy,
   terminate/recreate sealed-state behavior, non-attested KMS calls, and an
   admin-controlled network proxy test.

## Sources

- AWS EC2 instance attestation:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation.html
- AWS Attestable AMIs:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html
- AWS custom AMI PCR computation:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-pcr-compute.html
- AWS Linux AMI NitroTPM enablement:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-support-on-ami.html
- AWS NitroTPM Attestation Document:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestation-get-doc.html
- AWS NitroTPM Attestation Document validation:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-validate.html
- AWS NitroTPM Attestation Document contents:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-content.html
- AWS KMS condition keys for NitroTPM:
  https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-tpm.html
- AWS KMS attested calls:
  https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html
- AWS KMS key policies:
  https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
- AWS KMS default key policy:
  https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html
- AWS NitroTPM prerequisites:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html
- AWS NitroTPM samples:
  https://github.com/aws/nitrotpm-attestation-samples
- TPM PCR extend behavior:
  https://manpages.ubuntu.com/manpages/focal/man1/tpm2_pcrextend.1.html
- AWS advisory on PCR12:
  https://github.com/aws/nitrotpm-attestation-samples/security/advisories/GHSA-xrv8-2pf5-f3q7
- dstack security model:
  `docs/security/security-model.md`
- dstack attestation guide:
  `attestation.md`
- dstack KMS protocol:
  `kms/README.md`
- dstack Nitro Enclave flow:
  `docs/attestation-nitro-enclave.md`
- dstack GCP TDX + TPM flow:
  `docs/attestation-gcp.md`
