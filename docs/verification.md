# Verification

Attestation is cryptographic proof that your app runs in genuine TEE hardware with exactly the code you expect. No one can fake it.

## What Attestation Proves

When you verify a dstack deployment, you're checking three things:

1. **Genuine hardware** - Hardware vendor signatures confirm real TEE hardware generated the proof (Intel TDX, NVIDIA CC, or AMD SEV)
2. **Correct code** - The compose-hash matches your docker-compose configuration
3. **Secure environment** - OS and firmware measurements show no tampering

If any of these fail, the cryptographic proof won't verify.

## How to Verify

**Phala Cloud users**: Every deployment gets an automatic [Trust Center](https://trust.phala.com) report. This verifies hardware, code, and environment without manual steps.

**Programmatic verification**: dstack provides several tools:

- [dstack-verifier](https://github.com/Dstack-TEE/dstack/tree/master/verifier) - HTTP service with `/verify` endpoint, also runs as CLI
- [dcap-qvl](https://github.com/Phala-Network/dcap-qvl) - Open source quote verification library (Rust, Python, JS/WASM, CLI)
- [SDKs](../sdk/) - JavaScript and Python SDKs include `replayRtmrs()` for local RTMR verification

## Learn More

- [Attestation Documentation](https://docs.phala.com/phala-cloud/attestation/overview) - Generating quotes, programmatic verification, RTMR3 replay
- [Confidential AI Verification](https://docs.phala.com/phala-cloud/confidential-ai/verify/overview) - GPU TEE attestation for AI workloads
- [Domain Attestation](https://docs.phala.com/phala-cloud/networking/domain-attestation) - TLS certificates managed in TEE

## See It Live

Visit [chat.redpill.ai](https://chat.redpill.ai) and click the shield icon next to any response. This shows attestation verification from a real confidential AI deployment.
