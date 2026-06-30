# dstack Security Model

dstack protects your code and data from infrastructure operators. Using TEE hardware isolation, your workloads run in encrypted memory that the host cannot read or modify. You can cryptographically verify that your exact code runs in genuine TEE hardware.

This document helps you evaluate whether dstack's security model fits your needs.

## Trust Boundaries

dstack removes the need to trust infrastructure operators. The cloud provider cannot read your memory, modify your code, or access your secrets. Network attackers cannot intercept your traffic because TLS terminates inside the TEE with keys fully controlled by the TEE (Zero Trust HTTPS). Docker registries cannot serve malicious images because the TEE verifies SHA256 digests before pulling.

The only thing you must trust is **TEE hardware**. Intel TDX is the production path. AMD SEV-SNP is available where the selected dstack OS image and host support it, but it is new and experimental. You trust that the TEE provides genuine memory encryption and that quotes are signed by real hardware. For GPU workloads, you also trust **NVIDIA GPU hardware** and NVIDIA's Remote Attestation Service (NRAS). These are hardware-level trust assumptions.

Everything else is verifiable.

**The dstack OS** is measured during boot and recorded in the attestation quote. You verify it by rebuilding from [meta-dstack](https://github.com/Dstack-TEE/meta-dstack) source and comparing measurements, or by checking that the OS hash is whitelisted in a governance contract you trust.

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
| Hardware | TEE signature | Attestation quote |
| Firmware | Boot measurement | MRTD |
| OS | Boot measurement | RTMR0-2 |
| Application | Runtime measurement | RTMR3 (compose-hash) |

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

dstack implements layered verification from hardware to application. Each layer is measured and included in the attestation quote, which TEE hardware cryptographically signs.

```
┌─────────────────────────────────────────────────────────────────┐
│  Attestation Quote (signed by TEE hardware)                     │
│  ├── Hardware: TEE signature proves genuine hardware            │
│  ├── MRTD: Virtual firmware measurement                         │
│  ├── RTMR0-2: OS kernel and boot parameters                     │
│  ├── RTMR3: Application (compose-hash) + KMS binding            │
│  └── reportData: Your challenge (replay protection)             │
├─────────────────────────────────────────────────────────────────┤
│  Event Log (RTMR3 breakdown)                                    │
│  ├── compose-hash: SHA256 of your docker-compose                │
│  ├── key-provider: KMS root CA public key hash                  │
│  └── instance-id: Unique per deployment                         │
└─────────────────────────────────────────────────────────────────┘
```

**Hardware layer.** The TEE provides the root of trust. The attestation quote is cryptographically signed by TEE hardware, and verification confirms the signature chain. The TCB status shows whether firmware is patched against known vulnerabilities.

**OS layer.** The dstack OS is measured during boot into MRTD and RTMR0-2. MRTD captures the virtual firmware. RTMR0 captures firmware configuration. RTMR1 captures the Linux kernel. RTMR2 captures kernel command-line parameters. You verify integrity by computing expected measurements from meta-dstack source and comparing them to the quote.

**Application layer.** Your application is measured into RTMR3 as the compose-hash, which is the SHA256 hash of your normalized docker-compose configuration. Each image must use SHA256 digest pinning. This proves exactly which container images are running and that no code substitution happened after measurement.

**Key management layer.** The KMS root CA public key hash is recorded in RTMR3 as the key-provider event. This binds your workload to a specific KMS instance. The KMS itself runs in a TEE with its own attestation quote, so you can verify the KMS the same way you verify any workload.

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

For the no-image-download TDX lite path and the AMD SEV-SNP path,
`os_image_hash` is the unified image identity: `sha256(sha256sum.txt)`. The
`sha256sum.txt` file is the image checksum manifest generated at image build
time. It is a text file whose lines contain a SHA-256 digest and relative file
name for each manifest entry, such as `metadata.json`, the kernel, initrd,
firmware, and the split measurement file. Some launch-critical artifacts are
represented indirectly instead of as direct manifest entries: for example, the
rootfs is committed by the measured `dstack.rootfs_hash` kernel command-line
parameter, and the SEV firmware is committed by `measurement.snp.cbor`. The exact
`sha256sum.txt` bytes are hashed, so the manifest contents, file names, ordering,
and line endings are all part of the image identity.

The attestation carries a copy of the image's `sha256sum.txt` plus the platform
specific measurement material (`measurement.tdx.cbor` or
`measurement.snp.cbor`). The verifier checks that:

1. `sha256(checksum_file) == os_image_hash`;
2. the checksum file contains the expected `measurement.*.cbor` entry and that
   entry hashes to the supplied measurement material;
3. the supplied measurement material replays to the hardware-signed TDX
   MRTD/RTMR values or SEV-SNP launch `MEASUREMENT`/`HOST_DATA`.

Only after these checks pass does the verifier treat the returned
`os_image_hash` as the measured OS image identity. Downstream authorization
systems can then compare that trusted value against an allowlist or governance
contract.

## Verification Checklist

Use this checklist to verify a workload running in a dstack CVM.

**Platform verification:**
- [ ] Attestation quote signature is valid
- [ ] TCB status is up-to-date (no unpatched vulnerabilities)
- [ ] OS measurements match expected values (MRTD, RTMR0-2)
- [ ] OS image hash is whitelisted (if using governance)

**Application verification:**
- [ ] compose-hash matches your docker-compose
- [ ] All images use SHA256 digests (no mutable tags)
- [ ] RTMR3 event log replays correctly
- [ ] reportData contains your challenge (replay protection)

**Key management verification:**
- [ ] key-provider matches expected KMS identity
- [ ] KMS attestation is valid

## Verification Design Notes

This section explains two deliberate scoping decisions in how dstack verifies a quote. Both are intentional; the rationale is recorded here so the behavior is not mistaken for an oversight.

### Only RTMR3 is verified via event-log replay

dstack replays an event log only for RTMR3. RTMR0-2 (and MRTD) are not replayed from an event log — they are taken directly from the hardware-signed quote and compared against expected values computed offline from the OS source (e.g. `dstack-mr`).

This is also reflected at the source: the event log shipped alongside an attestation is stripped down to RTMR3 entries before it is embedded. `VersionedAttestation::into_stripped()` keeps only events with `imr == 3` (see `dstack-attest/src/attestation.rs`), and verification only ever replays those runtime events against `rt_mr3` (`verify_tdx_quote_with_events` / `decode_mr_tdx_from_quote`).

The reason boot-time event log entries (RTMR0-2) are dropped is that **nothing downstream consumes them**. Verification recomputes the OS-layer measurements directly from the signed `rt_mr0/1/2` values and compares them to independently reproduced expected measurements, so the corresponding boot event log would be redundant. Keeping it would only bloat the RA-TLS certificate and expose extra detail without adding any verification capability. RTMR3, by contrast, is runtime-extended (compose-hash, key-provider, instance-id, and application-emitted events), so its event log is the only one with a real consumer — the replay that proves what was extended into RTMR3.

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
