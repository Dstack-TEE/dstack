# AWS EC2 dstack-os AMI Reproducibility Manifest

Date: 2026-07-01

This manifest records the reproducibility and reference-measurement evidence for
the current dstack OS AWS EC2 NitroTPM AMI. It is written for relying parties
and verifier implementers.

Do not trust the AMI ID by itself. A verifier should accept this AMI only after
checking the source pins, rebuilding or independently verifying the artifacts,
recomputing the AWS NitroTPM PCR reference values, and comparing those values
with a live NitroTPM Attestation Document.

## Status

This is a clean-source release-candidate manifest for the AWS EC2 P2 base-image
gate. It is no longer the dirty development AMI used for early API testing.

Current status:

1. This manifest remains the clean P2 base-image evidence set. It should be used
   to verify the AMI, UKI, rootfs, and boot-PCR mechanics, not as the final P4
   dynamic-app production manifest.
2. Later P4, API-smoke, PCR14, sealed-state, TPM-hardening, and
   recipient-bound `GetAppKey` evidence is recorded in
   `docs/aws-attested-instance-security-evaluation.md`.
3. The production trust model does not require signed release binaries. A
   relying party should trust a matching reproducible rebuild and the verified
   NitroTPM measurements, not the publisher's binary artifact by itself.
4. A hardened source-integrated release candidate is produced by
   `os/yocto/tools/aws/generate-aws-ec2-release-manifest.sh`. The manifest includes source
   archive hashes, Yocto input-cache evidence, release artifact hashes, AWS PCR
   references, dstack verifier instructions, and a zero-warning hardening audit.
5. The July 5, 2026 hardened release-candidate manifest was generated from
   meta-dstack commit `a3057cdc86f452a26f628c50f4a237a542fe9a6f` and dstack
   commit `3da3b8a6b70b73c93a0a4a32bf94207c09317016`, with a matching Yocto
   download-cache content manifest. Running the generator against the
   app-specific build produces a P4/API-smoke package manifest from the same
   source state, with `dstack.mr_config_id` embedded in the measured UKI command
   line.
6. `os/yocto/tools/aws/generate-aws-ec2-release-manifest.sh` now generates the
   machine-readable release manifest from the dstack monorepo and build
   artifacts. It records deterministic source archive hashes, artifact hashes,
   optional Yocto download evidence, optional AWS PCR/AuthentiCode measurements,
   the dstack PCR-derived `os_image_hash`, optional AMI promotion/live-smoke
   records, verifier instructions, and optional hardening audit output.
   `dstack-cloud` (`platform: aws`) performs AMI import and live deploy; validated
   promotion/live-smoke records to an existing manifest after AMI registration.
7. `os/yocto/tools/aws/audit-aws-ec2-image-hardening.sh` provides the repeatable
   kernel/rootfs hardening audit. The hardened release candidate reports
   `failures=0 warnings=0`.

## AMI

| Field | Value |
| --- | --- |
| AWS account | `481766170915` |
| Region | `us-west-2` |
| AMI ID | `ami-058f0124934d7a144` |
| AMI name | `dstack-aws-clean-p2-20260701221139` |
| AMI creation time | `2026-07-01T22:35:13.000Z` |
| Root snapshot | `snap-004fac31b93866bf1` |
| Root device | `/dev/sda1` |
| Boot mode | `uefi` |
| TPM support | `v2.0` |
| Root volume type | `gp3` |
| Root volume size | `1 GiB` |
| Root volume encryption | `false` |

Verify the AMI metadata with:

```bash
aws ec2 describe-images \
  --region us-west-2 \
  --image-ids ami-058f0124934d7a144 \
  --query 'Images[0].{ImageId:ImageId,Name:Name,CreationDate:CreationDate,BootMode:BootMode,TpmSupport:TpmSupport,RootDeviceName:RootDeviceName,BlockDeviceMappings:BlockDeviceMappings}' \
  --output json
```

Expected identifying fields:

```json
{
  "ImageId": "ami-058f0124934d7a144",
  "Name": "dstack-aws-clean-p2-20260701221139",
  "CreationDate": "2026-07-01T22:35:13.000Z",
  "BootMode": "uefi",
  "TpmSupport": "v2.0",
  "RootDeviceName": "/dev/sda1"
}
```

## Source State

The clean build came from:

| Repository | Branch | Commit | Source state |
| --- | --- | --- | --- |
| `meta-dstack` | `aws-ec2-attested-boot` | `7f9ade543f9eee8219c37dd9a6b860aa477a3867` | Clean |
| `dstack` | `aws-ec2-nitrotpm-production-p2` | `3d0e858f3b192d60933bc535d9b8b843dc497c5a` | Clean |

The build tree reported no tracked modifications:

```bash
git status --short --untracked-files=no
git -C dstack status --short --untracked-files=no
```

Both commands produced empty output.

The build was run on:

```text
phala-onprem:~/workspace/meta-dstack-aws-ec2-attested-boot/repro-build/build-clean-p2
```

No Yocto or BitBake build was run locally for this manifest.

## Build Artifacts

Artifacts were inspected from:

```text
phala-onprem:~/workspace/meta-dstack-aws-ec2-attested-boot/repro-build/build-clean-p2
```

| Artifact | Size | SHA256 |
| --- | ---: | --- |
| `images/dstack-0.6.0/disk.raw` | `779091968` | `2bd9df697276a78c6b96731b928a93a0c7322d7dafe9fe255ea53fa3b9d9e59d` |
| `images/dstack-0.6.0.tar.gz` | `525722760` | `06fb458ed0e721c97f85a0cc23f04aad6add0e3b1591661926c2c3c17b431ca7` |
| `images/dstack-0.6.0-uki.tar.gz` | `524608440` | `3ea573bd59dba651b21bc0abf3fc88a0d526a595022857b8e1c459a7ec499fbe` |
| `bb-build/tmp-mc-prod/deploy/images/dstack/dstack-uki.efi` | `21054464` | `d5f6021f38b60a6942dd1062f31e7e9b8a3d0a6947bc8e025543ee064941ae66` |
| `bb-build/tmp-mc-prod/deploy/images/dstack/systemd-bootx64.efi` | `134656` | `98f4003505b5b62dd3649eb7b78714d5df2d1c932468036e9d072fa661b137d0` |
| `bb-build/tmp-mc-prod/deploy/images/dstack/dstack-rootfs-dstack-20260701221139.squashfs` | `492298240` | `b78791e14081ebb8b0a7a495be6b6d93ed18b6ba7b8ac7139947745c72ce9209` |
| `bb-build/tmp-mc-prod/deploy/images/dstack/dstack-rootfs-dstack-20260701221139.manifest` | `18457` | `4c449e0ca014ed7ee46819b1e833fee8349ff389afca0e82fb353808a7691659` |
| `bb-build/tmp-mc-prod/deploy/images/dstack/dstack-rootfs-dstack-20260701221139.spdx.json` | `8263595` | `58b9c59847a3067d4d0ba4b19e2bc91c3455614d62d4b97760b946a06884d636` |

The UKI Authenticode SHA256 is:

```text
172e2fe430468d2f40951cf3b87db0869160fc07c375806ee51d5fcadc22bb68
```

Recompute artifact hashes with:

```bash
sha256sum \
  disk.raw \
  dstack-uki.efi \
  systemd-bootx64.efi \
  dstack-rootfs-dstack-20260701221139.squashfs \
  dstack-rootfs-dstack-20260701221139.manifest \
  dstack-rootfs-dstack-20260701221139.spdx.json
```

Recompute the Authenticode hash with:

```bash
docker run --rm --platform linux/amd64 \
  -v "$PWD":/artifacts \
  amazonlinux:2023 \
  bash -lc 'dnf install -y pesign >/tmp/dnf.log && pesign -h -P -i /artifacts/dstack-uki.efi'
```

Expected output:

```text
172e2fe430468d2f40951cf3b87db0869160fc07c375806ee51d5fcadc22bb68 /artifacts/dstack-uki.efi
```

## UKI Measurements

The UKI contains these measured sections:

| Section | SHA256 |
| --- | --- |
| `.cmdline` | `19e8b5d3c7bdb654f4a399f725f50bf9e762aa3f7f76749d0c4396dc379b61db` |
| `.linux` | `a3d14ab0583a30767704dc75fcfbe99a20b7d4e3f2313d61f575d8b0ca4c5040` |
| `.initrd` | `a0ac2cd8b73cf5e0dbc5e7a97b2138a465ea6158866fdabee57c5ff62017a573` |
| `.osrel` | `bb2b5ec7a2c36a131b8b7cde2f7983f0a4d3ea24b24d3e775b4c8ad5a673d74c` |
| `.uname` | `8a7a82d90da7c7d9daba285bef81ad8f399549c4b79cf64b4c1d016066e00d4c` |

Extract the sections with:

```bash
for sec in .cmdline .linux .initrd .osrel .uname; do
  objcopy -O binary --only-section="$sec" dstack-uki.efi "section-${sec#.}.bin"
  sha256sum "section-${sec#.}.bin"
done
```

The `.cmdline` section is:

```text
console=ttyS0 init=/init panic=1 net.ifnames=0 biosdevname=0 mce=off oops=panic pci=noearly pci=nommconf random.trust_cpu=y random.trust_bootloader=n tsc=reliable no-kvmclock dstack.rootfs_hash=ce48b13be4c8f34eaa5d9c77611781c7ee4a8885ec5101b5b038f0428dd8951d dstack.rootfs_size=492298240
```

The embedded `dstack.rootfs_hash` is the rootfs dm-verity root hash. The
`dstack.rootfs_size` value matches the squashfs artifact size.

## AWS PCR Reference Measurements

Reference PCRs were computed with AWS `nitro-tpm-pcr-compute` from
`aws-nitro-tpm-tools-1.1.1-1.amzn2023.x86_64` inside Amazon Linux 2023.

Command:

```bash
docker run --rm --platform linux/amd64 \
  -v "$PWD":/artifacts \
  amazonlinux:2023 \
  bash -lc 'dnf install -y aws-nitro-tpm-tools >/tmp/dnf.log && nitro-tpm-pcr-compute --image /artifacts/dstack-uki.efi'
```

Expected output:

```json
{
  "Measurements": {
    "HashAlgorithm": "SHA384",
    "PCR4": "c4b56f291c0923f99dc915dbe97c2cfebf71554766b74cdd65c882f5d6559f65d11ebc11c541c10313b51f25f4c59bcd",
    "PCR7": "98441c7f7625d10058c47683aec486ce311c633235eb555593a7ee791121e3578ae72d04ecef661f272d59058b77af35",
    "PCR12": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

dstack derives its AWS EC2 `os_image_hash` from the boot PCR set:

```text
sha256(PCR4 || PCR7 || PCR12)
```

For this AMI:

```text
c2d6f2d20b1f0ec3a73661a63bfe2edc091ff1d555241de48742245a02754a91
```

`PCR12` is zero for this P2 AMI. This is acceptable for base-image
verification. It is not enough for dynamic app verification. The AWS P4 path
must bind dstack's existing app-measurement model to NitroTPM by carrying the
target app/config value in the measured boot artifact and extending the dstack
launch event chain into SHA384 `PCR14`. In the current UKI package shape, the
embedded `dstack.mr_config_id` changes `PCR4`; `PCR12` remains zero. A standard
boot path that accepts an external kernel command line must additionally produce
and require the expected `PCR12`. `PCR23` is reserved for post-launch app runtime
telemetry and is not the pre-secret launch gate.

## Live Smoke Test

The clean AMI booted on EC2 with NitroTPM enabled:

| Field | Value |
| --- | --- |
| Test instance | `i-02bf363998a6f88c6` |
| Instance type | `m6i.large` |
| Launch time | `2026-07-01T22:43:54+00:00` |
| Shared config snapshot | `snap-07952aabfbd635b18` (temporary, deleted after test) |
| Data disk snapshot | `snap-09706806b33a527ce` (temporary, deleted after test) |

The app exercised the dstack API through `/run/dstack.sock`:

```text
DSTACK_PLATFORM_JSON={"platform":"aws-ec2","attestation":"dstack-aws-nitro-tpm"}
DSTACK_GETQUOTE_ATTEST_LEN=11092
DSTACK_GETQUOTE_RAW_QUOTE_LEN=0
DSTACK_ATTEST_LEN=11092
DSTACK_AWS_API_TEST_OK
```

The live instance printed the same PCR-derived OS image hash:

```text
"os_image_hash": "c2d6f2d20b1f0ec3a73661a63bfe2edc091ff1d555241de48742245a02754a91"
```

The smoke instance, helper instances, helper volumes, temporary helper
snapshots, and imported raw-disk S3 object were deleted after the test. The AMI
and root snapshot were kept.

## Release Manifest Generator

Generate the production release manifest from the monorepo and immutable
build artifacts:

```bash
  os/yocto/tools/aws/generate-aws-ec2-release-manifest.sh \
  --output aws-ec2-release-manifest.json \
  --repo /path/to/dstack \
  --uki /path/to/dstack-0.6.0/dstack-uki.efi \
  --artifact /path/to/dstack-0.6.0-uki.tar.gz \
  --artifact /path/to/dstack-0.6.0.tar.gz \
  --artifact /path/to/dstack-0.6.0/disk.raw \
  --artifact /path/to/dstack-0.6.0/dstack-uki.efi \
  --artifact /path/to/dstack-0.6.0/dstack-mr-config.json \
  --artifact /path/to/dstack-0.6.0/dstack-mr-config-id.txt \
  --downloads-dir /path/to/bb-build/downloads \
  --downloads-manifest-output aws-ec2-downloads.sha256 \
  --kernel-config /path/to/deploy/images/dstack/kernel-config \
  --rootfs-manifest /path/to/deploy/images/dstack/dstack-rootfs-dstack.manifest \
  --rootfs-squashfs /path/to/deploy/images/dstack/dstack-rootfs-dstack.squashfs \
  --compute-aws-pcr \
  --ami-id ami-... \
  --ami-name dstack-aws-... \
  --region us-west-2 \
  --aws-account 123456789012 \
  --root-snapshot snap-... \
  --promotion-record aws-ec2-ami-promotion.json \
  --live-smoke-record aws-ec2-live-smoke.json
```

`--compute-aws-pcr` uses Docker with Amazon Linux 2023 to run
`nitro-tpm-pcr-compute` and `pesign` against the UKI. If this flag is present,
missing Docker or failed AWS measurement tooling is a release failure.

After AMI import and live EC2 smoke, attach the promotion evidence to an
already-generated manifest:

```bash
os/yocto/tools/aws/aws-ec2-attach-promotion-evidence.sh \
  --manifest aws-ec2-release-manifest.json \
  --promotion-record aws-ec2-ami-promotion.json \
  --live-smoke-record aws-ec2-live-smoke.json \
  --aws-account 123456789012 \
  --output aws-ec2-release-manifest.json
```

The helper fails if the promoted disk hash does not match the manifest's
`disk.raw` artifact, if the AMI is not UEFI/NitroTPM v2.0, or if the live smoke
record is not a passed run for the promoted AMI in the same region.

When run against the July 5, 2026 hardened release candidate, the generator
emits a `dstack-aws-ec2-release-manifest/v1` manifest. The historical evidence
records the separate meta-dstack and dstack commits used for that build. New
runs record the unified monorepo commit and deterministic source archive hash,
along with the Yocto download
content-manifest hash, the release artifact hashes (UKI package, bare-image
package, `disk.raw`, `dstack-uki.efi`, verity rootfs), the UKI AuthentiCode hash,
the dstack `os_image_hash`, the AWS PCR4/7/12 reference values, and
`hardening audit: failures=0 warnings=0`. The source entry must carry
`dirty_tracked_files = false`. Production deployment still needs an actual
mirrored object store or archive for the Yocto inputs so relying parties are not
dependent on live upstream availability.

Running the generator against the app-specific build produces a hardened
P4/API-smoke package manifest from the same source state. It uses the API-smoke
`MrConfigV3` document and shared app disk, embeds the app `dstack.mr_config_id`
in the measured UKI command line, and carries its own boot PCR set and
`os_image_hash`. After that package is promoted to an EC2 Attestable AMI and
live-smoked, `os/yocto/tools/aws/aws-ec2-attach-promotion-evidence.sh` attaches the
validated promotion and live-smoke records — AMI ID, root/shared/data snapshots,
console hash, and the observed `os_image_hash`, `mr_aggregated`, and
`compose_hash` — to the manifest.

## Rootfs Package Check

The prod rootfs manifest has 436 packages. The manifest did not include these
operator-access packages:

- `openssh`
- `dropbear`
- `cloud-init`
- `amazon-ssm-agent`
- `ssm-agent`
- EC2 Instance Connect packages

Check this with:

```bash
grep -Ei '^(openssh|openssh-|dropbear|cloud-init|amazon-ssm-agent|ssm-agent|ec2-instance-connect)' \
  dstack-rootfs-dstack-20260701221139.manifest
```

Expected output is empty.

Key packages present:

```text
bash x86_64_v3 5.3
containerd x86_64_v3 2.2.2+git0+5957d3334b
cryptsetup x86_64_v3 2.8.6
curl x86_64_v3 8.19.0
docker-moby x86_64_v3 v29.3.0+git1da6517e1a4381297e56862f6f373f265c28d1020+1da6517e1a
dstack-guest x86_64_v3 1.0
dstack-sysbox x86_64_v3 0.6.7+git0+3a69811f54
jq x86_64_v3 1.8.1
systemd x86_64_v3 259.5
```

## Kernel and Rootfs Hardening Audit

Run the repeatable audit from the repository root:

```bash
os/yocto/tools/aws/audit-aws-ec2-image-hardening.sh \
  --kernel-config bb-build/tmp-mc-prod/deploy/images/dstack/kernel-config \
  --rootfs-manifest bb-build/tmp-mc-prod/deploy/images/dstack/dstack-rootfs-dstack-20260701221139.manifest \
  --rootfs-squashfs bb-build/tmp-mc-prod/deploy/images/dstack/dstack-rootfs-dstack-20260701221139.squashfs
```

The hardened July 5, 2026 audit was run against the final release-candidate
Yocto artifacts on `phala-onprem`; no Yocto build was run locally. Result:

```text
failures=0 warnings=0
```

The audit confirmed required EC2/NitroTPM and measured-root kernel features:
UEFI boot, EFI stub, TPM CRB, dm-verity, squashfs, KASLR, stack protector,
seccomp, strict devmem, no kexec, no hibernation, and no debugfs. It also
confirmed the rootfs manifest excludes SSH, Dropbear, cloud-init, SSM, and EC2
Instance Connect packages. When checking the squashfs contents directly, root is
locked, no SSH/getty/cloud/SSM/EC2 units are enabled, and no `sshd` or
`dropbear` server binary is present. The defense-in-depth kernel items are
enabled or disabled as required in meta-dstack commit
`a3057cdc86f452a26f628c50f4a237a542fe9a6f`.

## Verifier Acceptance Rule

For this AMI, a verifier should require:

1. The AMI metadata matches this manifest.
2. The source commits are the accepted clean commits, or a published source
   archive hash expands to the same source.
3. The raw disk, UKI, rootfs squashfs, package manifest, SPDX artifact, and
   release tarball hashes match this manifest.
4. `nitro-tpm-pcr-compute --image dstack-uki.efi` returns the `PCR4`, `PCR7`,
   and `PCR12` values in this manifest.
5. A live NitroTPM Attestation Document verifies to the AWS NitroTPM attestation
   root and reports the same `PCR4`, `PCR7`, and `PCR12` values.
6. dstack's decoded `os_image_hash` equals
   `c2d6f2d20b1f0ec3a73661a63bfe2edc091ff1d555241de48742245a02754a91`.
7. The rootfs package manifest excludes operator mutation channels such as SSH,
   cloud-init, SSM, and EC2 Instance Connect.

Full production acceptance additionally requires a P4 release manifest whose UKI
command line carries `dstack.mr_config_id=<MrConfigV3 hash>` in the measured boot
artifact, an external P4 application PCR policy workflow, production dstack KMS
NitroTPM key-release policy, and source/input mirroring. The hardened release
manifest provides the current zero-warning hardening audit. For the current UKI
package shape, AWS reference computation reflects the embedded cmdline through
`PCR4` while `PCR12` remains zero; a non-UKI or external-cmdline boot path must
additionally produce and require the expected `PCR12`. Positive P4/API-smoke,
PCR14, production KMS, and hardening evidence for later AMIs is tracked in
`docs/aws-attested-instance-security-evaluation.md`.

Later GetAppKey API v2 smoke evidence from July 2, 2026 is also tracked there.
The positive path used a measured dstack KMS AMI
`ami-06a48f10cca0701bf` and a measured dstack-os client AMI
`ami-0863e9a672f7c0804`. The client retrieved app keys through v2 recipient
binding and printed `DSTACK_AWS_GETAPPKEY_V2_TEST_OK`. This is not evidence for
the P2 AMI above; it is downstream evidence that the AWS NitroTPM attestation
carrier can support recipient-bound dstack KMS key release.

The same AMI pair was used for a compose-mismatch negative test with bad shared
snapshot `snap-076dc06f99543915c`. The live guest rejected the mutated
`app-compose.json` with `Invalid mr_config compose_hash`. That run also showed
the tested AMI requested keys before the local rejection, so the source fix in
dstack `cb4e0fbe` must be included in the next reproducible AMI before this
gate can be closed.

Key artifact identifiers from that smoke:

| Artifact | Value |
| --- | --- |
| KMS dstack commit | `373bd99f018b856ece6f95b655aa1334db9f87a9` |
| KMS binary SHA256 | `61b3b55531d97859d41871167078768f658f196264023c3be5bdd4c0e6cda465` |
| KMS compose hash | `588727a8dc3bd9fd22375de83e2d90ab66f527e53b6278757ac9da94fcd05807` |
| KMS `mr_config_id` | `031b16f5c37fa825ce2e853e5faf05e92a2e1e05905de45cc8a866b41b82efd2a1000000000000000000000000000000` |
| KMS root raw SHA256 | `cfec53c442b1855523aa5405ea483c59181976f88361ac4da7dc8b89f85f4ac1` |
| KMS shared raw SHA256 | `4511cb3cb679a9519b2c8d603eb092806787ea71f6c0086ea28f1608055863fb` |
| Client compose hash | `f3519b7b94f72d5d25c7f25b1e3bebd1223ce53c7fbbb6ea0c27e3a18cd6354f` |
| Client `mr_config_id` | `036c3e640594b2561e888ba02030fb64eae69be4ee23343ba8ec8ac7cc869d8165000000000000000000000000000000` |
| Client root raw SHA256 | `5e64158286af55b471ee822377fc5f865a10ad12cb8efb0cc0de889194de207b` |
| Client shared raw SHA256 | `92c442943f8a9a07c81a1f3a30959b9b6fb451f5dd9995126e8296a82c6433a6` |

## Sources

- AWS EC2 reference PCR computation:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-pcr-compute.html
- AWS NitroTPM PCR contents:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-content.html
