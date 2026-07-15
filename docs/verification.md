# Verification

Attestation is cryptographic proof that your app runs in genuine TEE hardware with exactly the code you expect. No one can fake it.

## What Attestation Proves

When you verify a dstack deployment, you're checking three things:

1. **Genuine platform** - Vendor signatures confirm real attested hardware or platform generated the proof (Intel TDX, AMD SEV-SNP, AWS NitroTPM, Nitro Enclave, or NVIDIA CC)
2. **Correct code** - The compose-hash matches your docker-compose configuration
3. **Secure environment** - OS and firmware measurements show no tampering

If any of these fail, the cryptographic proof won't verify.

## How to Verify

**Phala Cloud users**: Every deployment gets an automatic [Trust Center](https://trust.phala.com) report. This verifies hardware, code, and environment without manual steps.

**Programmatic verification**: dstack provides several tools:

- [dstack-verifier](https://github.com/Dstack-TEE/dstack/tree/master/dstack/verifier) - HTTP service with `/verify` endpoint, also runs as CLI
- [dcap-qvl](https://github.com/Phala-Network/dcap-qvl) - Open source quote verification library (Rust, Python, JS/WASM, CLI)
- [SDKs](../sdk/) - JavaScript and Python SDKs include `replayRtmrs()` for local RTMR verification

## Platform-Specific Verification

Verification has the same goal on every platform: prove the platform signature,
the boot state, and the dstack application identity. The evidence fields differ
by platform.

| Platform | Boot evidence | Application identity replay | Freshness/key binding |
| --- | --- | --- | --- |
| TDX-family dstack CVM | MRTD and RTMR0-2 | RTMR3 event log | `report_data` or RA-TLS certificate binding |
| AMD SEV-SNP | SNP report fields plus `HOST_DATA`/config ID | `MrConfigV3` app/config target | report data or RA-TLS certificate binding |
| AWS EC2 NitroTPM | NitroTPM Attestation Document, AWS NitroTPM PKI, PCR4/PCR7/PCR12, OS image hash | SHA384 PCR14 launch event log through `system-ready` (authoritative; the PCR8 `MrConfig` V2 config commitment is an optional shortcut for verifiers that skip event-log replay) | NitroTPM `nonce`, `user_data`, `public_key`, or RA-TLS certificate binding |

For AWS EC2 NitroTPM, do not treat PCR23 as the launch authorization register.
PCR23 is resettable from the guest and is reserved for optional post-launch
runtime telemetry. Production AWS policy must require the NitroTPM attestation
mode, valid AWS NitroTPM signature chain, expected boot PCRs, expected OS image
hash, verified PCR14 replay, and the recipient public key when key material is
returned to the instance. The PCR8 `MrConfig` V2 config commitment is an
optional shortcut: a verifier that does not want to replay the PCR14 event log
may instead recompute the expected PCR8 from the known compose hash and
key-provider and compare it. It is not required, and dstack's own verifier does
not check it.

## Learn More

- [AWS EC2 NitroTPM production verification](./aws-ec2-production-verifier-runbook.md) - Verify and operate the AWS NitroTPM path
- [Intel TDX attestation](./attestation-tdx.md) - Verify TDX measurements and runtime events
- [AMD SEV-SNP support](./amd-sev-snp.md) - SNP image, attestation, and key-release requirements
- [GCP attestation](./attestation-gcp.md) - Verify the GCP TDX and TPM evidence chain
- [AWS Nitro Enclaves attestation](./attestation-nitro-enclave.md) - Verify NSM evidence
- [Attestation Documentation](https://docs.phala.com/phala-cloud/attestation/overview) - Generating quotes, programmatic verification, RTMR3 replay
- [Confidential AI Verification](https://docs.phala.com/phala-cloud/confidential-ai/verify/overview) - GPU TEE attestation for AI workloads
- [Domain Attestation](https://docs.phala.com/phala-cloud/networking/domain-attestation) - TLS certificates managed in TEE

## See It Live

Visit [chat.redpill.ai](https://chat.redpill.ai) and click the shield icon next to any response. This shows attestation verification from a real confidential AI deployment.
