# dstack Security Model

dstack protects your code and data from infrastructure operators. Using TEE hardware isolation, your workloads run in encrypted memory that the host cannot read or modify. You can cryptographically verify that your exact code runs in genuine TEE hardware.

This document helps you evaluate whether dstack's security model fits your needs.

## Trust Boundaries

dstack removes the need to trust most infrastructure operators. On TEE platforms such as Intel TDX and AMD SEV-SNP, the cloud or host operator cannot read your protected memory, modify your measured code, or access your secrets without detection. On AWS EC2 NitroTPM attested instances, AWS Nitro is part of the trusted platform, and the untrusted party is the workload AWS account administrator/operator. Network attackers cannot intercept your traffic because TLS terminates inside the attested environment with keys controlled by that environment (Zero Trust HTTPS). Docker registries cannot serve malicious images because the guest verifies SHA256 digests before pulling.

The primary trust input is **attested platform hardware**. Intel TDX is the production TEE path. AMD SEV-SNP is available where the selected dstack OS image and host support it, but it is new and experimental. AWS EC2 NitroTPM attested instances use a different trust root: the AWS Nitro system and AWS NitroTPM attestation PKI. In that mode, the threat model protects against the workload AWS account administrator and EC2 operator actions, but AWS remains trusted. For GPU workloads, you also trust **NVIDIA GPU hardware**, NVIDIA's attestation PKI/RIMs, and its revocation service (or NRAS when a deployment selects remote verification). These are hardware-level trust assumptions.

Everything else is verifiable.

**The dstack OS** is measured during boot and recorded in the attestation quote. You verify it by rebuilding from the [`os/`](../../os/) source and comparing measurements, or by checking that the OS hash is whitelisted in a governance contract you trust.

**The KMS** runs in its own TEE with its own attestation quote. You verify it the same way you verify any dstack workload.

### What dstack Cannot Protect

TEE technology has inherent limitations. Side-channel attacks against TEE hardware are researched actively, and microarchitectural vulnerabilities are discovered periodically. Hardware vendors release TCB updates to address these, so keep your TCB version current.

dstack protects the execution environment, not your application code. Bugs in your application remain exploitable. Secrets that you log or transmit insecurely can still leak. Your code must follow secure development practices.

Infrastructure operators can still deny service. They can shut down your workload, throttle resources, or block network access. If availability matters, plan for redundancy across providers.

**Persistent-storage freshness, integrity, and availability.** Disk encryption protects the confidentiality of data at rest. The default ZFS storage filesystem also provides integrity checking; switching the storage filesystem to ext4 may forgo strong integrity protection. Neither filesystem proves that an attached disk represents the latest application state. An infrastructure operator can withhold, delete, replace, or restore an earlier valid encrypted disk image. Applications that require rollback-resistant state must anchor a monotonic version or state commitment in an external trusted service, ledger, or equivalent freshness mechanism.

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

GPUs are passed through via VFIO to the TEE-protected CVM. Before key provisioning, `dstack-util setup` inventories every VGA/3D-controller PCI function, rejects non-NVIDIA display devices, and runs NVIDIA's local `nvattest` verifier over every NVIDIA-driver-visible GPU with a fresh nonce. dstack does not ship or pass a custom relying-party policy to this command; nvattest's built-in appraisal still applies. The complete JSON result (`result_code`, `result_message`, `claims`, and `detached_eat`) is saved at `/run/nvidia-gpu-attestation/attestation.out`.

An application may additionally set `requirements.gpu_policy` to an object with the following deny-unknown-fields schema:

- `attest_gpu` (boolean, default `true`): require local NVIDIA GPU attestation before enabling an attached GPU. Setting this to `false` skips attestation and is an explicit reduction in protection.
- `rego` (optional string): a Rego v0 script evaluated with the nvattest output's `claims` array as `input`. It must define the boolean entrypoint `data.policy.nv_match` in `package policy`.
- `allow_devtools` (boolean, default `false`): permit NVIDIA DevTools mode. Production applications should leave this disabled because DevTools removes the expected GPU memory-confidentiality guarantee.
- `allow_debug` (boolean, default `false`): permit an attestation claim whose `dbgstat` is `enabled`.
- `allow_insecure_boot` (boolean, default `false`): permit an attestation claim whose GPU `secboot` value is false.

The optional Rego v0 policy can enforce deployment-specific claims. A minimal `app-compose.json` containing one looks like this; replace the placeholder with the policy source:

```json
{
  "manifest_version": "3",
  "name": "gpu-app",
  "runner": "docker-compose",
  "requirements": {
    "gpu_policy": {
      "rego": "<rego-v0-policy>"
    }
  }
}
```

For example, the following policy requires exactly one H100 whose `hwmodel` matches the value emitted by `nvattest`:

```rego
package policy
default nv_match = false

nv_match {
  count(input) == 1
  input[0].hwmodel == "GH100 A01 GSP BROM"
}
```

The policy must define the boolean rule `data.policy.nv_match`. Its `input` is the complete `claims` array from `nvattest`; when no attestation is performed, `input` is `[]`, so the example also rejects a launch without exactly one attested GPU.

After measuring `compose-hash`, dstack enters the GPU setup gate and JCS-canonicalizes the original `requirements.gpu_policy` JSON value, then measures its SHA-256 digest in a `gpu-policy-hash` event. When the field is absent—including when `requirements` itself is absent—both parsing and measurement use the default empty object `{}`. Thus an omitted policy and an explicit `{}` have the same digest, while any explicitly present field, including an explicit default value, changes the digest. MrConfigV3 GPU launches also carry this digest as the optional `gpu_policy_hash` field; non-GPU launches omit it for compatibility. When the field is present, the guest compares it with the digest computed from app-compose; when it is absent, the guest skips this MrConfigV3 check. The MrConfigV3 document is bound by TDX `MR_CONFIG_ID` or SEV-SNP `HOST_DATA`, so the host cannot substitute a different GPU policy when this optional binding is present without changing the platform launch identity. The typed policy used for enforcement applies omitted-field defaults and rejects unknown fields. If GPU attestation is enabled and NVIDIA GPUs are present, dstack attests them and applies the basic settings and optional Rego policy before setting the GPU ready state. When no attestation claims are produced—because no GPU is attached or `gpu_policy.attest_gpu` is false—Rego is still evaluated with an empty array as `input` before any ready-state transition. This lets an application reject a launch whose attested GPU count is wrong. A false, undefined, malformed, or non-boolean Rego result stops boot before key provisioning.

Up to five init scripts may be configured. Their ordered SHA-256 digests are
measured as `init-script-hash` runtime events on platforms with a quoted
runtime register. MrConfigV3 also carries the ordered digest list; on SEV-SNP,
the signed report's `HOST_DATA` binds the exact canonical MrConfigV3 document.
An omitted `init_script_hashes` field disables this check,
while an explicit empty list requires app-compose to contain no init scripts.
When present, the guest compares the list with hashes computed from app-compose
before continuing boot. Current VMMs serialize the field explicitly for
manifest v3 launches, including `init_script_hashes: []` when the list is empty.

The policy digest is remotely verifiable on each supported platform, but through different carriers:

- **TDX:** `gpu-policy-hash` contains the raw 32-byte digest and is measured into RTMR3. Replay the event log and compare the result with the quote's RTMR3, then compare the event payload with the expected digest. When an MrConfigV3 document includes `gpu_policy_hash`, TDX `MR_CONFIG_ID` additionally binds that field.
- **AWS NitroTPM:** the same `gpu-policy-hash` event is extended into non-resettable SHA384 PCR14. Replay the PCR14 event chain against the signed NitroTPM Attestation Document, then compare the payload with the expected digest.
- **AMD SEV-SNP:** there is no quote-bound runtime event register in the current stack. Instead, GPU launches put the digest in optional `MrConfigV3.gpu_policy_hash`, and the signed SNP report's `HOST_DATA` binds the exact MrConfigV3 document. Verify the SNP report and `HOST_DATA` binding, then compare the field with the expected digest. If the optional field is absent, this check is not asserted.

For every NVML-enumerated GPU, dstack calls `Device::is_cc_enabled()` and `Device::is_cc_dev_mode_enabled()` and requires the NVML device count to match the expected GPU count. CC must always be ON; DevTools must be OFF unless the measured policy explicitly permits it. The typed claim checks always require `measres == "success"`; by default they also require `dbgstat == "disabled"` and `secboot == true`, with the latter two checks controlled by their explicit opt-ins. Only after the default appraisal, typed claim checks, optional Rego policy, and per-device NVML checks succeed does dstack call `Device::set_confidential_compute_state(true)` to set the GPU ready state. The dstack CPU/guest boot chain is verified independently through measured boot; a GPU claim named `secboot` refers to the GPU appraisal, not UEFI Secure Boot in the CVM.

### Dual Attestation

GPU workloads require verification of both hardware components. The CPU TEE quote verifies the CVM and its measured guest code. NVIDIA-signed evidence, checked against NVIDIA RIMs and certificate status by `nvattest`, verifies the GPU appraisal. After the optional policy and ready-state operations succeed, dstack emits a `gpu-attestation` launch event before `system-ready`. Its versioned payload records the number of appraised devices, asserted CC/DevTools state, and SHA-256 of the complete nvattest JSON output (claims and detached EAT). On TDX, both `gpu-policy-hash` and `gpu-attestation` are append-only RTMR3 events; they are never derived from application-controlled `report_data`.

For a successful TDX GPU launch, the GPU-relevant RTMR3 event order is:

```text
compose-hash
init-script-hash (zero or more, in configured order)
gpu-policy-hash
gpu-attestation
instance-id
boot-mr-done
```

`gpu-policy-hash` is emitted even for a GPU-less launch. `gpu-attestation` is emitted only after an attached GPU passes `nvattest`, the built-in checks, the optional Rego policy, and the NVML state checks. Its UTF-8 JSON payload has this shape:

```json
{
  "version": 2,
  "provider": "nvidia",
  "devices": 1,
  "cc_mode": "on",
  "devtools": false,
  "evidence_sha256": "<sha256-of-complete-nvattest-json>"
}
```

`GpuInfo` returns that complete boot-time `nvattest` JSON in its `attestation` string; it does not run a new attestation. To bind the API result to TDX evidence: verify the quote, replay the event log to the quote's RTMR3, require exactly one pre-`system-ready` `gpu-attestation` event, decode its JSON payload, and compare `evidence_sha256` with `SHA-256(UTF-8(GpuInfo.attestation))`. Only after this comparison should the verifier inspect the returned claims. This exact-byte comparison includes any whitespace or trailing newline in the returned string.

A verifier must replay the measured event log, require exactly one `gpu-policy-hash` event immediately after `compose-hash`, and compare its 32-byte payload with the expected policy digest (`SHA-256(JCS({}))` for the omitted/default policy). When MrConfigV3 includes `gpu_policy_hash`, it must match the same digest. When GPU protection is required, the verifier must also require exactly one pre-`system-ready` `gpu-attestation` event with `devices > 0` and, when applicable, the expected deployment count. The raw `attestation.out` file is not trusted by itself; if it is supplied for inspection, its digest must match the `gpu-attestation` event.

### GPU Threat Model and Lifetime

The GPU gate assumes a malicious host/VMM and untrusted host-provided PCI topology, while trusting the CPU TEE, the measured dstack guest/kernel, NVIDIA hardware/firmware roots, and the cryptography used by both attestation chains. Availability is out of scope.

The events make the following **boot-time** statement: immediately before key provisioning, all attached VGA/3D PCI functions were NVIDIA devices, their count matched the NVML inventory, nvattest returned one fresh successfully appraised claim for each device, the measured application policy accepted those claims and GPU state when present, every enumerated GPU passed the CC/DevTools NVML checks, and setting the GPU ready state succeeded. This closes these cases:

- A GPU-less launch cannot be presented as a GPU-verified launch because it has no `gpu-attestation` event.
- A mixed launch cannot attest only its TEE-capable subset. Non-NVIDIA display GPUs are rejected, and the sysfs, NVML, and nvattest claim counts must all agree. A non-CC NVIDIA GPU either prevents evidence collection/appraisal or causes the default appraisal, application policy, or CC-state check to fail.
- Copying another CVM's result into a file or `report_data` does not work. Only measured pre-application code can place the event before `system-ready`, and event-log replay binds it to the quoted RTMR/PCR value.

This is **not a lifetime or physical co-location guarantee**. After `system-ready`, an application with sufficient guest privileges can unload the NVIDIA driver, and a malicious host may attempt PCI hot-remove/replacement or proxy GPU traffic. The boot event remains a true historical statement but does not prove that the same device is still attached. dstack also cannot rule out a live relay/cuckoo attack to a genuine remote GPU: current Hopper/Blackwell deployments do not provide a CPU-TEE-verifiable TEE-I/O/TDISP device binding. Applications that mutate the driver or PCI topology are outside this guarantee; higher-assurance deployments must prevent that behavior and re-attest before using a newly initialized GPU.

AMD SEV-SNP has no runtime measurement register in the current dstack stack. The local boot gate can still fail closed, but a `gpu-attestation` event carried beside an SNP report is not remotely bound to that report and must not be accepted as dual-attestation evidence. SNP needs a measured vTPM/PCR channel before it can provide the same remote binding.

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
- [ ] Config commitment matches the expected app/config target (on AWS: PCR14 replay; PCR8 is an optional shortcut — see the [AWS verifier runbook](../aws-ec2-production-verifier-runbook.md))
- [ ] reportData contains your challenge (replay protection)
- [ ] No security-relevant check depends on `pre_launch_script` running before the application; such checks belong in `init_script` or in the application itself

**GPU verification (when required):**
- [ ] The `gpu-attestation` device count is greater than zero and matches the expected deployment
- [ ] Exactly one `gpu-policy-hash` event follows `compose-hash`, and its payload matches `SHA-256(JCS(requirements.gpu_policy))` (default `{}` when omitted)
- [ ] When MrConfigV3 includes `gpu_policy_hash`, it matches the same expected GPU policy digest
- [ ] Exactly one `gpu-attestation` event appears before `system-ready`
- [ ] CC is ON and the event's DevTools field complies with the measured policy
- [ ] The platform binds the event log to a quoted RTMR/PCR (do not accept it from current SEV-SNP evidence)

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

dstack keeps several development switches as runtime or on-chain configuration rather than Cargo feature flags. Examples include KMS `attest_rpc_cert = false`, gateway `core.debug.insecure_skip_attestation = true`, KMS `auth_api.type = "dev"`, and KMS contract `gateway_app_id = "any"`. These settings exist for local development and integration tests, not for production deployments.

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

### `pre_launch_script` is not a launch gate

`pre_launch_script` runs after dockerd, so a container with a Docker restart policy can be running before it executes — always with `restart: always`, and after any unclean stop with `restart: unless-stopped`. Attestation still binds the script contents, but not the order. Use `init_script`, which runs before dockerd on every boot, for anything that must precede application code. See [security-best-practices.md](./security-best-practices.md#security-semantics-must-not-depend-on-pre_launch_script-running-first) for the failure modes and auditor guidance.

### KMS root key security

All keys derive from the KMS root key, which is protected by TEE isolation. Like all TEE-based systems, a TEE compromise could expose the root key. We are developing MPC-based KMS where the root key is distributed across multiple parties, eliminating this single point of failure.

## Further Reading

For production deployment guidance, see [security-best-practices.md](./security-best-practices.md). For smart contract authorization details, see [onchain-governance.md](../onchain-governance.md). For technical details about CVM boundaries and APIs, see [cvm-boundaries.md](./cvm-boundaries.md).
