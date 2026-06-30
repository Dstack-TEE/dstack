# Security

Use this file for vulnerability reports. For the security model, production guidance, audit, and already-answered public findings, start with [Security Documentation](./docs/security/).

## Report a vulnerability

If you believe you found a vulnerability, please use [GitHub's private security reporting features](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately) for this repository. If GitHub private reporting is unavailable, contact security@phala.network.

Do not open public GitHub issues for exploitable vulnerabilities or details that could help exploit production deployments.

Use private reporting for issues that could expose secrets, bypass attestation or authorization, compromise KMS keys, weaken workload isolation, or enable unauthorized code or configuration changes in production deployments.

## Public security questions

Use public issues only for questions about documented behavior, documentation gaps, already-public findings, or hardening ideas that do not include an exploit path.

Before opening a public security question, check [Public Security Reports](./docs/security/public-security-reports.md). It records public reports that were fixed, accepted by design, documented, or split into related hardening and roadmap work.

## Production trust boundary

Development settings are not production-safe merely because they are present in the codebase. Production deployments must rely on measured configuration, expected TEE measurements, authorization policy, and attestation verification. The [Security Model](./docs/security/security-model.md#development-modes-are-auditable-not-production-safe) is the source of truth for what dstack treats as a production guarantee.
