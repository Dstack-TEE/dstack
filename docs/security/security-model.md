# dstack Security Model

dstack protects your code and data from infrastructure operators. Using TEE hardware isolation, your workloads run in encrypted memory that the host cannot read or modify. You can cryptographically verify that your exact code runs in genuine TEE hardware.

This document helps you evaluate whether dstack's security model fits your needs.

## Trust Boundaries

dstack removes the need to trust infrastructure operators. The cloud provider cannot read your memory, modify your code, or access your secrets. Network attackers cannot intercept your traffic because TLS terminates inside the TEE with keys fully controlled by the TEE (Zero Trust HTTPS). Docker registries cannot serve malicious images because the TEE verifies SHA256 digests before pulling.

The only thing you must trust is **TEE hardware** (currently Intel TDX, with AMD SEV support planned). You trust that the TEE provides genuine memory encryption and that quotes are signed by real hardware. For GPU workloads, you also trust **NVIDIA GPU hardware** and NVIDIA's Remote Attestation Service (NRAS). These are hardware-level trust assumptions.

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

## Limitations

### Attestation proves identity, not correctness

Attestation proves which code is running, not that the code is bug-free. It proves the environment is isolated, not that your application handles secrets correctly. You still need to audit your application code and follow secure development practices.

### Environment variables need application-layer authentication

Encrypted environment variables prevent the host from reading your secrets. However, the host can replace encrypted values with different ones. Your application should verify authenticity using patterns like LAUNCH_TOKEN. See [security-best-practices.md](./security-best-practices.md) for details.

### KMS root key security

All keys derive from the KMS root key, which is protected by TEE isolation. Like all TEE-based systems, a TEE compromise could expose the root key. We are developing MPC-based KMS where the root key is distributed across multiple parties, eliminating this single point of failure.

## Further Reading

For production deployment guidance, see [security-best-practices.md](./security-best-practices.md). For smart contract authorization details, see [onchain-governance.md](../onchain-governance.md). For technical details about CVM boundaries and APIs, see [cvm-boundaries.md](./cvm-boundaries.md).
