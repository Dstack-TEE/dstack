# AWS EC2 Instance Attestation Security Evaluation

This document evaluates dstack attestation on AWS EC2 with NitroTPM
(Attestable AMIs) under the account-admin-untrusted threat model. It states
the security properties dstack requires from a platform and how the AWS
NitroTPM path satisfies them in the current implementation. For the
operational relying-party workflow (verifier deployment, allowlists, key
release), see `docs/aws-ec2-production-verifier-runbook.md`.

The threat model is:

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

## Platform Security Property Spec

The following properties are the readiness gates for any platform claiming the
same security level as dstack under this threat model, and how the AWS
NitroTPM path meets them today.

| ID | Required property | dstack mechanism | AWS NitroTPM status |
| --- | --- | --- | --- |
| P1 | Verifiable platform root of trust | TDX/SNP/Nitro quote verification against vendor root; debug rejected; TCB surfaced | NitroTPM Attestation Documents are verified against the AWS Nitro Attestation PKI, including document timestamp sanity. AWS exposes no TDX/SNP-style TCB advisory field, so a verified attestation is normalized to `tcbStatus = "UpToDate"` and passes the standard authorization gate unchanged. |
| P2 | Reproducible or independently computable base image measurement | meta-dstack rebuild plus `dstack-mr` computes `MRTD`/`RTMR0-2` | The unified `os/build.sh` flow emits the AWS image archive with `sha256sum.txt`, `digest.txt`, and `measurement.aws.cbor`; its output directory also contains the reference-PCR side-car `aws-pcrs.json`. `os_image_hash = sha256(sha256sum.txt)` is the same identity used on all platforms; the verifier recomputes it from the downloaded image directory (`dstack/verifier/src/verification.rs`). The hardening audit script `os/yocto/tools/aws/audit-aws-ec2-image-hardening.sh` checks the image for operator mutation channels. |
| P3 | Boot command line and root filesystem integrity are measured | `RTMR1/2`, rootfs hash, dm-verity, measured initrd/cmdline | The UKI commits kernel, initrd, and embedded cmdline into `PCR4`; the rootfs is dm-verity-protected. `VmConfig.aws_measurement` is required and must bind `boot_pcr_digest = sha256(PCR4||PCR7||PCR12)` to the attested PCRs, so `PCR12` (external cmdline) is always part of the bound digest — a missing-PCR12 bypass is not expressible. Enforced in guest quote generation (`dstack/dstack-attest/src/attestation.rs`), `verify_os_image_hash_for_aws_nitro_tpm` (`dstack/verifier/src/verification.rs`), and the KMS pipeline via the same verifier check. |
| P4 | Runtime application identity is cryptographically bound | RTMR3 `compose-hash`, `app-id`, `instance-id`, `key-provider`; event log replay | SHA384 `PCR14` event-log replay is the authoritative binding (RTMR3 analogue; non-resettable). Launch events: `system-preparing`, `app-id`, `compose-hash`, zero or more ordered `init-script-hash` events, `instance-id`, `boot-mr-done`, `key-provider`, `storage-fs`, `system-ready` (`dstack/dstack-util/src/system_setup.rs`). GPU launches also include `gpu-policy-hash` and `gpu-attestation` before `instance-id`. `dstack-attest`, `dstack-verifier`, and KMS reject missing/mismatched PCR14 and bad replay. Optionally, the guest extends the raw `MrConfig` V2 `config_id` into `PCR8` once (`PCR8 = sha384(0^48 || config_id)`) so a lightweight third-party verifier can check compose hash + key provider without event-log replay; dstack's own verifier and KMS do not check PCR8. |
| P5 | Challenge/liveness and caller key binding | `report_data` challenge or RA-TLS public key hash in quote | RA-TLS binds `report_data` to the TLS certificate public key. KMS key release is bound to the live RA-TLS handshake; external `/verify` callers supply and check their own `report_data` challenge. The low-level NitroTPM document verifier also rejects stale or far-future document timestamps. |
| P6 | Secret release only to attested code | dstack KMS verifies attestation, checks auth policy, derives per-app keys | dstack KMS verifies the NitroTPM attestation, runs the same `verify_os_image_hash_for_aws_nitro_tpm` binding check as the verifier, builds `BootInfo` from verified boot PCRs plus PCR14 launch events, and checks auth policy before deriving app keys (`dstack/kms/src/main_service.rs`). AWS NitroTPM key release is gated behind the opt-in `aws_nitro_tpm_key_release` flag (default false in `kms.toml`). |
| P7 | Key-release policy is not controlled by the untrusted account admin | KMS runs inside TEE; policy from auth API/contracts; KMS identity measured | Satisfied with dstack KMS or another verifiable secret authority outside the untrusted AWS account admin's control. A NitroTPM-backed dstack KMS keeps root material out of account-admin snapshots and clones. The policy backend (auth-simple in a trusted control plane, or on-chain `DstackKms`/`DstackApp`) must be outside the workload account admin's control. Same-account AWS KMS fails this property if the admin can change key policy, create grants, or call secret-bearing operations through a policy they control. |
| P8 | Operator cannot inject boot-time or runtime inputs that affect secrets without detection | Host-shared files are measured or independently authenticated; KMS URLs not trusted, KMS key identity measured | App TPM access is enforced by measurement, not by a container sandbox: `init_script`, `pre_launch_script`, and the docker-compose are measured into the app-compose hash, hence into the governed app identity, and replayed into non-resettable `PCR14`, so an operator cannot alter app inputs without changing the measured identity and being denied key release. Production dstack-os AWS images exclude SSH, cloud-init, SSM, EC2 Instance Connect, and serial login (checked by `audit-aws-ec2-image-hardening.sh`). IMDS/operator-provided config must not be a secret-affecting input unless measured or authenticated. |
| P9 | Persistent state confidentiality from account admin | dstack disk key derived after attestation; encrypted env vars decrypted only inside CVM | The local TPM key provider seals the disk seed under a SHA384 PCR policy over `[4, 7, 8, 12, 14]` (`AWS_NITRO_PCRS` in `dstack/tpm-attest/src/lib.rs`), so the sealed seed survives same-instance stop/start but does not transfer with cloned EBS volumes to another instance. EBS snapshots and volumes remain account-admin visible at the AWS control plane, so persisted confidential state must stay encrypted inside the instance and AMIs must contain no secrets. |
| P10 | Network and TLS endpoint identity is attestation-bound | RA-TLS / Zero Trust HTTPS / gateway attestation; TLS keys generated in TEE | The Rust RA-TLS verifier exposes `verify_der`/`verify_pem`, which extract the certificate's embedded attestation, verify it with the platform verifier (including AWS NitroTPM), and require `report_data = QuoteContentType::RaTlsCert(SubjectPublicKeyInfo)`. `dstack-verifier --verify-cert` provides an operator/relying-party certificate evidence path that also binds `os_image_hash`. AWS attestation alone does not protect DNS, load balancers, or admin-controlled proxies; clients must require this RA-TLS check, signed responses, or an attested gateway. |
| P11 | Upgrade governance is explicit and non-bypassable | DstackApp/DstackKms whitelists compose hashes, OS images, KMS aggregate MRs | auth-simple and the unchanged on-chain `DstackKms`/`DstackApp` contracts pin OS image hash, app compose hash, device ID, and KMS identity. KMS auth pins the early `mrAggregated` (the `boot-mr-done` launch-event snapshot). AWS reuses the standard gate via `tcbStatus = "UpToDate"` normalization with no AWS-specific on-chain field, plus the opt-in `aws_nitro_tpm_key_release` KMS flag. Secure Boot PCR7 certificate policies need explicit rotation/revocation handling so old AMIs do not remain authorized. |
| P12 | Verifier is independent and complete | `dstack-verifier`, DCAP/QVL, RTMR replay, KMS/app/governance checks | `dstack-verifier` verifies the NitroTPM document against the AWS Nitro PKI, enforces the required `aws_measurement`/`boot_pcr_digest` binding against the unified `os_image_hash`, replays the PCR14 launch-event chain, and emits the canonical auth-policy object as `details.boot_info` for the same policy logic used by `/bootAuth/app` and `/bootAuth/kms`. The relying-party deployment workflow is `docs/aws-ec2-production-verifier-runbook.md`; each deployment must instantiate it with real OS-image, PCR, and compose-hash allowlists. |

## Sources

- AWS EC2 instance attestation:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation.html
- AWS Attestable AMIs:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html
- AWS custom AMI PCR computation:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-pcr-compute.html
- AWS NitroTPM Attestation Document:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestation-get-doc.html
- AWS NitroTPM Attestation Document validation:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-validate.html
- AWS NitroTPM Attestation Document contents:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-content.html
- AWS KMS attested calls:
  https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html
- AWS NitroTPM samples:
  https://github.com/aws/nitrotpm-attestation-samples
- AWS advisory on PCR12:
  https://github.com/aws/nitrotpm-attestation-samples/security/advisories/GHSA-xrv8-2pf5-f3q7
- dstack security model: `docs/security/security-model.md`
- dstack TDX attestation guide: `docs/attestation-tdx.md`
- dstack KMS protocol: `dstack/kms/README.md`
- dstack Nitro Enclave flow: `docs/attestation-nitro-enclave.md`
- dstack GCP TDX + TPM flow: `docs/attestation-gcp.md`
- AWS EC2 production verifier runbook:
  `docs/aws-ec2-production-verifier-runbook.md`
