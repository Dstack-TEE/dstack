# Security Documentation

dstack security resources for auditors, researchers, and operators.

## Start Here

- **Users and verifiers:** read the [Security Model](./security-model.md) to understand what dstack guarantees and what you must verify.
- **Operators:** read [Security Best Practices](./security-best-practices.md) before deploying production KMS, gateway, or VMM services.
- **Security researchers and AI agents:** report exploitable vulnerabilities through the private path in [SECURITY.md](../../SECURITY.md). For already-public findings or docs questions, check [Security Issue Triage](./security-issue-triage.md) before opening a public issue.
- **Maintainers:** use [Security Issue Triage](./security-issue-triage.md) to classify public reports and close issues once the maintainer position is clear.

## Audit

dstack has been audited by zkSecurity. See the [full audit report](./dstack-audit.pdf).

## Documentation

- [Security Model](./security-model.md) - Threat model, trust boundaries, and verification checklist
- [Security Best Practices](./security-best-practices.md) - Production hardening guide
- [Security Issue Triage](./security-issue-triage.md) - Public status for answered, fixed, accepted, and roadmap reports
- [CVM Boundaries](./cvm-boundaries.md) - Information exchange and isolation details

## Already Answered Reports

Some public security reports describe real hardening work. Some describe behavior that is intentional for development or compatibility, and some are false positives under production configuration. The canonical list is [Security Issue Triage](./security-issue-triage.md). Search that page by issue number, component, or exact setting name before treating an old report as unresolved.

## Report Vulnerabilities

If you believe you found an exploitable vulnerability, use GitHub's private security reporting features as described in [SECURITY.md](../../SECURITY.md). If GitHub private reporting is unavailable, contact security@phala.network.

Do not open GitHub issues for exploitable vulnerabilities.
