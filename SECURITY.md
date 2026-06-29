# Security

dstack is security-critical infrastructure for confidential workloads. This page is the root entry point for private vulnerability reporting, threat-model documentation, and public status for already-addressed findings.

## Report a vulnerability

Please report exploitable vulnerabilities privately to security@phala.network. We will respond within 48 hours.

Do not open GitHub issues for exploitable vulnerabilities. Public issues are for questions, documentation gaps, duplicate-prone prior findings, and hardening ideas that do not disclose an exploit path.

Use private disclosure for issues that could expose secrets, bypass attestation or authorization, compromise KMS keys, weaken workload isolation, or enable unauthorized code or configuration changes in production deployments.

## Public security documentation

- [Security documentation index](./docs/security/) - start here for the full security docs map
- [Security model](./docs/security/security-model.md) - threat model, trust boundaries, and verification checklist
- [Security best practices](./docs/security/security-best-practices.md) - production hardening guidance
- [Security issue triage](./docs/security/security-issue-triage.md) - public status for answered, fixed, accepted, and roadmap reports
- [CVM boundaries](./docs/security/cvm-boundaries.md) - what crosses the CVM boundary and why
- [zkSecurity audit report](./docs/security/dstack-audit.pdf) - third-party audit

## Before filing a public security question

Check [Security Issue Triage](./docs/security/security-issue-triage.md) before opening a public security question. It records reports that were fixed, accepted by design, documented, or moved to roadmap work.

For duplicate-prone findings, search for the exact setting or behavior:

- `quote_enabled = false`
- `auth_api.type = "dev"`
- `gateway_app_id = "any"`
- `rpc.tls.mutual.mandatory = false`
- `ed25519` and `secp256k1` key derivation for the same path
- `RATLS` HKDF salt and key versioning

## Production trust boundary

Development settings are not production-safe merely because they are present in the codebase. Production deployments must rely on measured configuration, expected TEE measurements, authorization policy, and attestation verification. The documented security model is the source of truth for what dstack treats as a production guarantee.
