# AWS EC2 Production Verifier Runbook

This runbook describes the verifier-side workflow for AWS EC2 NitroTPM dstack
deployments under the account-admin-untrusted threat model.

The relying party must not trust an AMI ID, DNS name, load balancer, AWS KMS
key, or dstack KMS endpoint by itself. It should accept a workload only after
checking the release evidence, NitroTPM challenge binding, policy `BootInfo`,
and endpoint identity.

## Inputs

- The release image package for the exact release candidate, produced by the
  unified build entrypoint `os/build.sh` (the `<name>-<version>-uki.tar.gz`
  dist archive). It contains `disk.raw`, `sha256sum.txt`, `digest.txt`, and
  `measurement.{gcp,aws}.cbor`. The build output also contains an
  `aws-pcrs.json` side-car, but that file is not part of the archive.
- The dstack monorepo sources pinned at the exact release revision, for the
  reproducible rebuild.
- A dstack verifier built from this repository.
- The production auth policy backend: `auth-simple`, auth-eth contracts, or an
  equivalent verifier-controlled service.
- For public services, the endpoint's RA-TLS certificate.

## 1. Verify Release Evidence

The release evidence is the image package itself: every measured file is
listed in `sha256sum.txt`, and the unified image identity is
`os_image_hash = sha256(sha256sum.txt)` (also recorded as `digest.txt`).
There is no separately generated release manifest; the same `os/build.sh`
flow produces both the image and its evidence.

Rebuild from clean, pinned sources and require a byte-identical result:

```bash
git status --porcelain   # must be empty at the pinned release revision
./os/build.sh            # reproducible Yocto backend; emits images/<name>-<version>-uki.tar.gz
```

Compare the rebuilt package against the published one. `sha256sum.txt` lists
the full build inputs, not only the files in the UKI archive, so do not run
`sha256sum -c` inside the extracted UKI package:

```bash
mkdir published rebuilt
tar -xzf published-<name>-<version>-uki.tar.gz -C published --strip-components=1
tar -xzf rebuilt-<name>-<version>-uki.tar.gz -C rebuilt --strip-components=1

cmp published/sha256sum.txt rebuilt/sha256sum.txt
cmp published/measurement.aws.cbor rebuilt/measurement.aws.cbor
cmp published/disk.raw rebuilt/disk.raw

expected=$(sha256sum published/sha256sum.txt | awk '{print $1}')
test "$expected" = "$(cat published/digest.txt)"
```

BitBake enforces per-recipe input checksums during the rebuild; for full
supply-chain independence, mirror the Yocto `downloads/` input cache by
content hash.

Run the hardening audit against the release kernel config and rootfs; it must
exit zero with `failures=0`:

```bash
os/yocto/tools/aws/audit-aws-ec2-image-hardening.sh \
  --kernel-config <kernel .config> \
  --rootfs-manifest <rootfs package manifest> \
  --rootfs-squashfs <rootfs squashfs>
```

## 2. Register the AMI and deploy with `dstack-cloud`

Apply the EC2 and EBS Direct IAM policy in the AWS prerequisites of
[`quickstart.md`](quickstart.md). `iam:PassRole` is needed only when
`aws_config.iam_instance_profile` is configured.

After the release artifact hashes and AWS PCR references match the published
release evidence, deploy with **`dstack-cloud`** (`platform: aws`). The CLI
uploads the local UKI `disk.raw` directly to an EBS snapshot and registers an
Attestable AMI (UEFI + NitroTPM v2.0) when `aws_config.ami_id` is empty, builds
the shared config disk with
`aws_measurement` from `measurement.aws.cbor`, writes a minimal GPT data-disk
template whose partition is labeled `dstack-data`, and launches the instance.

```bash
# one-time: install CLI
export PATH="$PATH:$(pwd)/dstack/scripts/bin"

# project for AWS
dstack-cloud new my-aws-app --platform aws --region us-west-2
cd my-aws-app
# configure subnet/security groups; no S3 bucket or vmimport role is required
# pull or place the UKI package (must include measurement.aws.cbor) under image_search_paths

dstack-cloud pull dstack-0.6.0   # UKI package must include assemble-time measurement.aws.cbor
dstack-cloud prepare             # embeds fixed os_image_hash + aws_measurement (no PCR recompute)
dstack-cloud deploy              # create EBS snapshots directly, register AMI, run-instances

dstack-cloud status
dstack-cloud logs --follow
```

Record the resulting AMI id, shared/data snapshots, and instance id from
`state.json` / `dstack-cloud status` in the release review package.

Recompute AWS reference PCRs and the UKI AuthentiCode hash from the release
UKI with version-pinned host tools (do not rely on an unpinned container
toolchain for reference measurements):

```bash
cargo install --git https://github.com/aws/NitroTPM-Tools \
  --rev d76d6eeebd4169b00a3c3af9858852d48f40e748 \
  --locked nitro-tpm-pcr-compute   # aws/NitroTPM-Tools v1.1.2
# The UKI is EFI/BOOT/BOOTX64.EFI in the 256 MiB EFI partition at 1 MiB.
dd if=published/disk.raw of=efi.img bs=1M skip=1 count=256 status=none
mcopy -i efi.img ::EFI/BOOT/BOOTX64.EFI dstack-uki.efi
nitro-tpm-pcr-compute --image dstack-uki.efi
pesign -h -P -i dstack-uki.efi   # UKI AuthentiCode SHA256
```

The PCRs must match the build-output `aws-pcrs.json` side-car when it is
published with the release, and their digest
`sha256(PCR4 || PCR7 || PCR12)` must equal the `boot_pcr_digest` committed in
`measurement.aws.cbor`. For the generic hardened UKI this is the boot PCR set
plus the UKI hash:

```text
dstack_os_image_hash: <os-image-hash>
PCR4: <pcr4>
PCR7: <pcr7>
PCR12: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
UKI AuthentiCode SHA256: <uki-authenticode-sha256>
```

For a dynamic app package, the **UKI/AMI stays generic**. App/config identity
is not embedded in the UKI cmdline; the guest computes the `MrConfig` **V2**
config id from its measured app identity (compose hash, app id, key-provider
kind, deploy-time key-provider pin from `app-compose.json`) and extends the
raw config id into **PCR8** at guest setup. Record the expected config id in
the deployment-specific release package:

```text
dstack_os_image_hash: <os-image-hash>   # prefer sha256(sha256sum.txt) + aws_measurement
PCR4/PCR7/PCR12: <boot PCRs for the AMI UKI>
PCR8: sha384(0^48 || <MrConfig V2 config id>)
PCR14: <event-log replay; early pin uses boot-mr-done cutoff>
expected MrConfig V2 config id: <mr-config-id>
```

## 3. Verify the Attestation

Challenge binding uses **report_data → NitroTPM user_data** (same role as
TDX/GCP): the relying party embeds its own challenge in `report_data` and
checks it against `details.report_data` in the verifier result.

Example verifier request shape:

```json
{
  "attestation": "hex-encoded-dstack-attestation"
}
```

Run:

```bash
cargo run --bin dstack-verifier -- --verify request.json
```

Require:

```bash
# from the release package: os_image_hash = sha256(sha256sum.txt)
expected_os_image_hash=$(sha256sum published/sha256sum.txt | awk '{print $1}')
# exact 64-byte challenge used when collecting this attestation, as hex
expected_report_data="<128-hex-characters>"

jq -e \
  --arg expected_os_image_hash "$expected_os_image_hash" \
  --arg expected_report_data "$expected_report_data" '
  .is_valid == true and
  .details.quote_verified == true and
  .details.report_data == $expected_report_data and
  .details.boot_info.teeVariant == "dstack-aws-nitro-tpm" and
  .details.boot_info.tcbStatus == "UpToDate" and
  .details.boot_info.osImageHash == $expected_os_image_hash
' request.json.verification.json
```

NitroTPM has no TDX/SNP-style TCB surface, so the verifier and KMS normalize a
verified NitroTPM attestation to `tcbStatus = "UpToDate"`. This lets AWS reuse
the standard authorization contract and auth policy unchanged, with no
AWS-specific on-chain fields.

The relying party should then check `details.boot_info` against its auth policy.

## 4. Configure Auth Policy

For AWS NitroTPM, the policy must require:

- accepted `tcbStatus` (`UpToDate` by default, matching the normalized value);
- accepted `osImageHash` (unified `sha256(sha256sum.txt)`; `aws_measurement`
  is required and must bind the attested boot PCRs);
- accepted app `composeHash` and `appId`;
- accepted KMS identity via **early `mrAggregated`** (boot-mr-done), same as
  bare TDX;
- verified PCR14 event-log replay (single event lane; no PCR23 runtime split) —
  this is the authoritative app-identity binding (`composeHash`, `appId`,
  `instance-id`, `key-provider`);
- a `report_data` challenge for external verifier flows that need liveness.

For GPU workloads, PCR14 also contains `gpu-policy-hash` immediately after
`compose-hash`. Its 32-byte payload must equal
`SHA-256(JCS(requirements.gpu_policy))`, using `{}` when the policy is omitted.
Because the verifier replays the event chain against the signed NitroTPM
Attestation Document, this validates `gpu_policy_hash` on AWS. A successful GPU
launch also adds `gpu-attestation`; after PCR14 replay, its `evidence_sha256`
can be compared with `SHA-256(hex_decode(bundle.evidence))`, where `bundle` is
the `AttestResponse.boottime_gpu_evidence` entry whose `format` is
`nvidia-nvattest-boottime-json-v1`, returned by `/v1/Attest` when the request
sets `include_boottime_gpu_evidence`. Hash the decoded bytes exactly as
returned, not a re-serialized form.

The guest also extends a `MrConfig` V2 **config commitment** into **PCR8**
(`PCR8 = sha384(0^48 || config_id)`). This is **optional** and exists only to
let a lightweight third-party verifier confirm `composeHash` + key-provider
*without* implementing PCR14 event-log replay: recompute
`expected_aws_config_pcr(MrConfig::V2 { compose_hash, app_id, key_provider,
key_provider_id })` and compare it to PCR8. dstack's own verifier and KMS do
**not** check PCR8 — they rely on PCR14 replay — so it is not part of the
required policy above.

The `teeVariant` field is carried in the verified boot info for
observability; a relying party may additionally assert
`teeVariant == "dstack-aws-nitro-tpm"` against the verifier output, but the
authorization contract itself keys on the standard fields above.

Same-account AWS KMS is not a trusted secret authority in this threat model if
the untrusted account admin can alter key policy, grants, or secret-bearing
operations. Use dstack KMS or another verifier-controlled KMS.

## 5. Verify Endpoint Identity

AWS EC2 attestation does not authenticate DNS, load balancers, or
admin-controlled proxies. Public clients must verify an attestation-bound
endpoint.

For RA-TLS endpoints, capture the server certificate:

```bash
openssl s_client -connect HOST:PORT -servername HOST -showcerts </dev/null \
  2>/dev/null |
  awk '/BEGIN CERTIFICATE/{p=1} p{print} /END CERTIFICATE/{exit}' \
  > endpoint-cert.pem
```

Verify it:

```bash
cargo run --bin dstack-verifier -- --verify-cert endpoint-cert.pem
```

Require the generated `endpoint-cert.pem.ratls-verification.json` to contain:

```bash
jq -e '
  .is_valid == true and
  .details.tee_variant == "dstack-aws-nitro-tpm" and
  .details.app_info.os_image_hash_verified == true
' endpoint-cert.pem.ratls-verification.json
```

On AWS NitroTPM the `os_image_hash` binding is self-contained, so
`os_image_hash_verified` is `true` here; only then should you trust
`.details.app_info.os_image_hash`. Then apply the same allowlist policy to the
verified app identity (including `os_image_hash`). If the
deployment uses signed responses or an attested gateway instead of direct
RA-TLS, the response-signing key or gateway certificate must be bound to
verified NitroTPM evidence with equivalent policy checks.

## 6. Release Decision

An AWS EC2 NitroTPM deployment can be promoted only when:

1. a reproducible rebuild from the clean, pinned release sources yields a
   byte-identical `sha256sum.txt` (and therefore the same `os_image_hash`);
2. Yocto input content is mirrored or otherwise available by content hash;
3. independently recomputed AWS PCRs and the UKI AuthentiCode hash match the
   published build-output `aws-pcrs.json` side-car (when provided) and the
   `boot_pcr_digest` in `measurement.aws.cbor`;
4. the hardening audit has zero failures and zero warnings, or every warning has
   a documented release exception;
5. the registered AMI has a live EC2 smoke record for the exact AMI ID and
   root snapshot in the release review package;
6. `/verify` returns a valid AWS `BootInfo`;
7. auth policy accepts only the intended OS, app, and KMS state;
8. endpoint identity is RA-TLS, signed-response, or attested-gateway bound.
