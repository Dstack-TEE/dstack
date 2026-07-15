# dstack Security Model

dstack protects your code and data from infrastructure operators. Using TEE hardware isolation, your workloads run in encrypted memory that the host cannot read or modify. You can cryptographically verify that your exact code runs in genuine TEE hardware.

This document helps you evaluate whether dstack's security model fits your needs.

## Trust Boundaries

dstack removes the need to trust most infrastructure operators. On TEE platforms such as Intel TDX and AMD SEV-SNP, the cloud or host operator cannot read your protected memory, modify your measured code, or access your secrets without detection. On AWS EC2 NitroTPM attested instances, AWS Nitro is part of the trusted platform, and the untrusted party is the workload AWS account administrator/operator. Network attackers cannot intercept your traffic because TLS terminates inside the attested environment with keys controlled by that environment (Zero Trust HTTPS). Docker registries cannot serve malicious images because the guest verifies SHA256 digests before pulling.

The primary trust input is **attested platform hardware**. Intel TDX is the production TEE path. AMD SEV-SNP is available where the selected dstack OS image and host support it, but it is new and experimental. AWS EC2 NitroTPM attested instances use a different trust root: the AWS Nitro system and AWS NitroTPM attestation PKI. In that mode, the threat model protects against the workload AWS account administrator and EC2 operator actions, but AWS remains trusted. For GPU workloads, you also trust **NVIDIA GPU hardware** and NVIDIA's Remote Attestation Service (NRAS). These are hardware-level trust assumptions.

Everything else is verifiable.

**The dstack OS** is measured during boot and recorded in the attestation quote. You verify it by rebuilding from the [`os/`](../../os/) source and comparing measurements, or by checking that the OS hash is whitelisted in a governance contract you trust.

**The KMS** runs in its own TEE with its own attestation quote. You verify it the same way you verify any dstack workload.

### What dstack Cannot Protect

TEE technology has inherent limitations. Side-channel attacks against TEE hardware are researched actively, and microarchitectural vulnerabilities are discovered periodically. Hardware vendors release TCB updates to address these, so keep your TCB version current.

dstack protects the execution environment, not your application code. Bugs in your application remain exploitable. Secrets that you log or transmit insecurely can still leak. Your code must follow secure development practices.

Infrastructure operators can still deny service. They can shut down your workload, throttle resources, or block network access. If availability matters, plan for redundancy across providers.

## Security Guarantees

### Confidentiality

| Layer | Protection | Mechanism |
|-------|------------|-----------|
| Memory | Encrypted at runtime | TEE hardware encryption |
| Disk | Encrypted at rest | Per-app keys from KMS (AES-256-GCM) |
| Environment | Encrypted in transit | X25519 ECDH + AES-256-GCM |
| Network | Encrypted end-to-end | Zero Trust HTTPS (TLS terminates in TEE) |

### Integrity

| Component | Verification | Measurement |
|-----------|--------------|-------------|
| Hardware/platform | Vendor signature | TDX/SNP quote, NitroTPM Attestation Document, or Nitro Enclave document |
| Firmware and boot path | Boot measurement | TDX/SNP MRTD and RTMR0-2, or AWS NitroTPM PCR4/PCR7/PCR12 |
| OS image | Reproducible image measurement | dstack OS image hash and platform reference measurements |
| Application launch identity | Event-log replay | RTMR3 on TDX-family platforms, SHA384 PCR14 on AWS NitroTPM |
| Application runtime telemetry | Event-log replay when policy requires it | RTMR3 on TDX-family platforms; SHA384 PCR14 on AWS NitroTPM (same event lane as launch; TDX RTMR3 analogue) |

### Isolation

Each application derives unique keys from the KMS based on its identity. Instance-level secrets use the instance ID to create unique disk encryption keys. No keys are shared between different applications.

## GPU Security for AI Workloads

dstack supports NVIDIA H100, H200, and B200 GPUs in confidential compute mode for AI inference and training workloads.

### How It Works

GPUs are passed through via VFIO directly to the TEE-protected CVM. The GPU operates in confidential compute mode, encrypting data during computation. Both the CPU TEE and NVIDIA GPU provide hardware isolation together. If either component fails verification, the security model breaks.

### Dual Attestation

GPU workloads require verification of both hardware components. The CPU TEE provides the quote that verifies CPU and memory isolation. NVIDIA's Remote Attestation Service (NRAS) independently verifies the GPU is genuine and running in confidential mode. Both attestations must pass for complete verification.

### AI Workload Protection

Models and training data stay within the hardware-protected environment. The infrastructure operator cannot access model weights, training data, or inference inputs/outputs. Response integrity is provable through cryptographic signatures generated inside the TEE. Performance overhead is minimal, achieving approximately 99% efficiency compared to native execution.

## Chain of Trust

dstack implements layered verification from platform hardware to application identity. Each layer is measured and included in signed attestation evidence. The exact register names are platform-specific.

```
┌─────────────────────────────────────────────────────────────────┐
│  Signed attestation evidence                                    │
│  ├── Platform: vendor signature proves genuine platform          │
│  ├── Boot: firmware, kernel, initrd, cmdline, rootfs state       │
│  ├── Launch identity: app/config/KMS binding event chain         │
│  └── Freshness binding: challenge, report_data, nonce, or key    │
├─────────────────────────────────────────────────────────────────┤
│  dstack launch event log                                        │
│  ├── compose-hash: SHA256 of your docker-compose                │
│  ├── key-provider: KMS root CA public key hash                  │
│  └── instance-id: Unique per deployment                         │
└─────────────────────────────────────────────────────────────────┘
```

**Hardware/platform layer.** The platform provides the root of trust. TDX and SEV-SNP quotes are signed by CPU-vendor attestation roots. AWS NitroTPM Attestation Documents are signed by the AWS NitroTPM attestation PKI. TDX and SEV-SNP verification surfaces a TCB status. AWS NitroTPM does not expose a dstack-style TCB status, so policy must rely on attestation mode, AWS signature verification, boot PCRs, image hash, and dstack launch-event replay.

**OS layer.** The dstack OS is measured during boot. On TDX-family platforms, MRTD captures the virtual firmware, and RTMR0-2 capture firmware configuration, kernel, initramfs, and command-line state. On AWS NitroTPM, policy checks the AWS boot PCRs for the selected boot path, currently PCR4, PCR7, and PCR12, plus the dstack OS image hash. You verify integrity by computing expected measurements from the monorepo OS source and comparing them to signed evidence.

**Application launch layer.** Your application launch identity includes the compose-hash, app ID, instance ID, key-provider identity, and OS image hash. On TDX-family platforms, dstack extends those events into RTMR3. On AWS NitroTPM, dstack extends those launch events into non-resettable SHA384 PCR14 and treats `system-ready` as the launch boundary. Each container image must use SHA256 digest pinning. This proves which normalized container configuration was authorized before key release.

**Runtime telemetry layer.** Application-owned runtime events remain available after launch. On AWS NitroTPM they extend the same SHA384 PCR14 event lane as OS launch events (like TDX RTMR3). Policy may still treat `system-ready` as a logical boundary when interpreting the event log; there is no separate PCR23 runtime split.

**Key management layer.** The KMS root CA public key hash is recorded as the key-provider launch event. This binds your workload to a specific KMS instance. The KMS itself runs with its own attestation evidence, so you can verify the KMS the same way you verify any workload.

### How `os_image_hash` becomes trusted

The `os_image_hash` carried in `vm_config` is not trusted just because the guest
or host reports it. The verifier first validates the hardware-signed quote, then
uses the quoted measurements to bind `os_image_hash` to the software that
actually booted.

For the full-image TDX path, the verifier obtains the OS image identified by
`os_image_hash`, checks the image checksum manifest, recomputes the expected
MRTD and RTMR0-2 from the image and VM configuration, and requires those values
to match the measurements in the quote. If the host substitutes either the image
hash or the VM configuration, the recomputed measurements no longer match the
quote.

For the no-image-download TDX lite path, the AMD SEV-SNP path, and the GCP TDX
path,
`os_image_hash` is the unified image identity: `sha256(sha256sum.txt)`. The
`sha256sum.txt` file is the image checksum manifest generated at image build
time. It is a text file whose lines contain a SHA-256 digest and relative file
name for each manifest entry, such as `metadata.json`, the kernel, initrd,
firmware, and the split measurement file. Some launch-critical artifacts are
represented indirectly instead of as direct manifest entries: for example, the
rootfs is committed by the measured `dstack.rootfs_hash` kernel command-line
parameter, the SEV firmware is committed by `measurement.snp.cbor`, and the GCP
UKI Authenticode hash is committed by `measurement.gcp.cbor`. The exact
`sha256sum.txt` bytes are hashed, so the manifest contents, file names,
ordering, and line endings are all part of the image identity.

The attestation carries a copy of the image's `sha256sum.txt` plus the platform
specific measurement material (`measurement.tdx.cbor` or
`measurement.snp.cbor`, or `measurement.gcp.cbor`). The verifier checks that:

1. `sha256(checksum_file) == os_image_hash`;
2. the checksum file contains the expected `measurement.*.cbor` entry and that
   entry hashes to the supplied measurement material;
3. the supplied measurement material replays to the hardware-signed TDX
   MRTD/RTMR values, SEV-SNP launch `MEASUREMENT`/`HOST_DATA`, or the GCP TPM
   UKI event.

Only after these checks pass does the verifier treat the returned
`os_image_hash` as the measured OS image identity. Downstream authorization
systems can then compare that trusted value against an allowlist or governance
contract.

## Verification Checklist

Use this checklist to verify a workload running in a dstack CVM.

**Platform verification:**
- [ ] Attestation quote signature is valid
- [ ] TCB status is up-to-date for platforms that report one
- [ ] AWS NitroTPM evidence verifies to the AWS NitroTPM attestation PKI when running on AWS
- [ ] OS measurements match expected values (MRTD/RTMR0-2, or AWS PCR4/PCR7/PCR12)
- [ ] OS image hash is whitelisted (if using governance)

**Application verification:**
- [ ] compose-hash matches your docker-compose
- [ ] All images use SHA256 digests (no mutable tags)
- [ ] Launch event log replays correctly (RTMR3 on TDX-family platforms, PCR14 on AWS NitroTPM)
- [ ] Config commitment matches the expected app/config target (TDX `mr_config_id` / SEV `HOST_DATA`; on AWS NitroTPM the app/config identity is bound by PCR14 event-log replay, and the guest-computed `MrConfig` V2 PCR8 commitment is only an optional shortcut for verifiers that skip that replay)
- [ ] reportData contains your challenge (replay protection)

**Key management verification:**
- [ ] key-provider matches expected KMS identity
- [ ] KMS attestation is valid

## Verification Design Notes

This section explains two deliberate scoping decisions in how dstack verifies a quote. Both are intentional; the rationale is recorded here so the behavior is not mistaken for an oversight.

### Only application measurement lanes are verified via event-log replay

dstack replays event logs for application identity, not for the base OS boot registers. On TDX-family platforms, that replay target is RTMR3. On AWS NitroTPM, the launch replay target is SHA384 PCR14. RTMR0-2, MRTD, and AWS boot PCRs are taken directly from signed platform evidence and compared against expected values computed offline from OS source and image artifacts.

For TDX evidence, the event log shipped alongside an attestation is stripped down to RTMR3 entries before it is embedded. `VersionedAttestation::into_stripped()` keeps only events with `imr == 3` (see `dstack-attest/src/attestation.rs`), and verification replays those events against `rt_mr3` (`verify_tdx_quote_with_events` / `decode_mr_tdx_from_quote`). For AWS NitroTPM evidence, dstack carries runtime event records and verifies the PCR14 launch chain against the NitroTPM Attestation Document.

The reason boot-time event log entries are not the verifier contract is that downstream policy compares boot measurements directly to independently reproduced expected measurements. Keeping full boot event logs would bloat evidence and expose extra detail without adding verification capability. Application identity events, by contrast, include deployment-specific values such as compose-hash, key-provider, instance-id, and runtime events. Their event log is the data a verifier needs to prove what was extended into the application measurement lane.

### Why TDX lite mode does not validate ACPI table contents

TDX lite mode verifies the OS image without downloading the image and without
running QEMU to regenerate ACPI tables. It still uses the three RTMR0 `ACPI
DATA` digests from the attestation event log as measurement inputs. The guest
labels those three events as `acpi-loader`, `acpi-rsdp`, and `acpi-tables`
before exposing the event log, and the verifier checks that the recomputed RTMR
values match the hardware-signed quote. What it does not do is reconstruct and
byte-compare the full ACPI table contents.

This is safe for dstack's threat model because ACPI tables are treated as
untrusted host-provided platform description, not as trusted guest code. The
dangerous executable part of ACPI is AML (ACPI Machine Language): malicious AML
can try to use `SystemMemory` operation regions through the Linux ACPICA
interpreter to read or write guest physical memory. dstack kernels include the
BadAML sandbox patch (`0002-acpi-sandbox-block-aml-systemmemory-ram-access.patch`),
which hooks the ACPI `SystemMemory` region handler, walks the guest page tables,
and denies AML access to encrypted/private guest RAM. AML can only access
unencrypted/shared mappings.

Therefore, an infrastructure operator can still provide bad ACPI data and cause
misconfiguration or denial of service, but unvalidated ACPI/AML cannot tamper
with confidential private memory or extract secrets. That residual availability
risk is already outside dstack's confidentiality/integrity guarantees.

### TCB status is surfaced, not gated, during verification

dstack's `validate_tcb` does not reject a quote based on its TCB status string (`UpToDate`, `OutOfDate`, `ConfigurationNeeded`, `SWHardeningNeeded`, ...). It only enforces hard invariants: debug mode must be off, and the SEAM/service-TD measurements must be well-formed. The verified report carries the `status` field through to the caller.

This is deliberate: whether a non-current TCB (e.g. `OutOfDate`) is acceptable is a **policy decision that belongs downstream**, not in the verification primitive. Different deployments have different risk tolerances, so the verifier surfaces the status and lets the consuming policy decide. The "TCB status is up-to-date" item in the verification checklist above is exactly such a downstream policy check.

The one case dstack does not leave to downstream is a genuinely invalid TCB: `dcap-qvl` rejects `Revoked` outright (its `is_valid()` returns false only for `Revoked`), so a revoked TCB never reaches the policy layer in the first place.

> **Future work:** this will be refactored toward a grace-period model, where an out-of-date TCB is accepted for a bounded window after a new TCB level is published rather than being a binary downstream decision.

### Development modes are auditable, not production-safe

dstack keeps several development switches as runtime or on-chain configuration rather than Cargo feature flags. Examples include KMS `quote_enabled = false`, `auth_api.type = "dev"`, and KMS contract `gateway_app_id = "any"`. These settings exist for local development and integration tests, not for production deployments.

This is intentional. Runtime configuration that affects the trust boundary is visible in attestation measurements or public contract state. Cargo feature gates are not automatically more auditable because feature unification can enable a feature through a dependency graph, and the resulting runtime behavior is not represented as a measured deployment setting.

Production verifiers should reject deployments that use these development settings. Operators should treat them the same way they treat debug-mode TEE quotes: useful for testing, invalid for production trust.

### KMS mTLS is route-enforced for sensitive operations

The KMS Rocket TLS listener permits connections without a client certificate because some bootstrap and public metadata endpoints must be reachable before a client has an RA-TLS certificate. That listener setting is not the authorization boundary for key material.

App key release and KMS key handover require verified caller attestation from the RA-TLS client certificate. Certificate signing verifies the CSR signature and the attestation embedded in the CSR before signing.

The unauthenticated or non-client-certificate surface includes bootstrap and temp-CA bootstrap material retrieval, env-encryption public-key retrieval, metadata, health, and metrics behavior documented for operators. `GetTempCaCert` returns temp CA private material for the bootstrap flow, so operators must treat it as bootstrap-sensitive rather than harmless public metadata.

## Limitations

### Attestation proves identity, not correctness

Attestation proves which code is running, not that the code is bug-free. It proves the environment is isolated, not that your application handles secrets correctly. You still need to audit your application code and follow secure development practices.

### Environment variables need application-layer authentication

Encrypted environment variables prevent the host from reading your secrets. However, the host can replace encrypted values with different ones. Your application should verify authenticity using patterns like LAUNCH_TOKEN. See [security-best-practices.md](./security-best-practices.md) for details.

### KMS root key security

All keys derive from the KMS root key, which is protected by TEE isolation. Like all TEE-based systems, a TEE compromise could expose the root key. We are developing MPC-based KMS where the root key is distributed across multiple parties, eliminating this single point of failure.

## Further Reading

For production deployment guidance, see [security-best-practices.md](./security-best-practices.md). For smart contract authorization details, see [onchain-governance.md](../onchain-governance.md). For technical details about CVM boundaries and APIs, see [cvm-boundaries.md](./cvm-boundaries.md).
