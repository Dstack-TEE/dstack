# Security Issue Triage

Security issues should not remain open after the maintainer position is clear. An open issue means one of two things: a fix is still required, or a concrete design/roadmap item is intentionally being tracked. Everything else should be closed with a final maintainer comment and a link to the code or documentation that records the decision.

This page is not a vulnerability reporting channel. Report exploitable vulnerabilities privately through [SECURITY.md](../../SECURITY.md). Use public issues only for questions, documentation gaps, duplicate-prone prior findings, or hardening ideas that do not disclose an exploit path.

## Triage labels

Use these categories when evaluating public security questions and already-public reports:

| Category | Meaning | Expected issue state |
| --- | --- | --- |
| Real blocker | Confirmed vulnerability that can compromise production security under supported configuration | Keep open until fixed; close as completed when the fix lands |
| Needs hardening | Not a broken trust boundary, but a defense-in-depth improvement with no compatibility cost | Keep open only while the patch is pending; close as completed when merged |
| Fixed | The reported behavior has already been fixed or is fixed by the linked change | Close as completed |
| Docs-only | The behavior is intentional or lower severity, but the repo must say so clearly | Close after documentation is merged |
| Accepted by design | The report conflicts with the documented threat model or with an intentional compatibility constraint | Close as not planned, with the design rationale linked |

When a report mixes several claims, split the actionable work into separate issues before closing the original. Do not leave a broad "security" issue open just to remember future work.

## March 2026 security cluster

The March cluster contained a mix of real hardening, compatibility decisions, and false positives. The current repo position is:

| Issue | Classification | Maintainer action |
| --- | --- | --- |
| [#606](https://github.com/Dstack-TEE/dstack/issues/606) App keys and decrypted env files world-readable | Needs hardening | Tightening secret-bearing file writes to owner-only permissions (`0600`) is a valid defense-in-depth improvement with no expected compatibility cost |
| [#605](https://github.com/Dstack-TEE/dstack/issues/605) Identical raw key material across `ed25519` and `secp256k1` for the same path | Accepted compatibility decision, docs-only | Existing derived key bytes are preserved; docs now state that `path` is the domain separator and callers must use algorithm-specific paths when they require independent keys |
| [#607](https://github.com/Dstack-TEE/dstack/issues/607) `gateway_app_id = "any"` disables gateway identity pinning | Accepted by design for dev/test deployments | `gateway_app_id` is KMS contract configuration and is publicly auditable; production deployments must not use `"any"` |
| [#608](https://github.com/Dstack-TEE/dstack/issues/608) `auth_api.type = "dev"` allows all authorization | Accepted by design for local/integration testing | Dev auth is measured runtime configuration, not a production mode; production must use webhook/on-chain authorization |
| [#609](https://github.com/Dstack-TEE/dstack/issues/609) `quote_enabled = false` bypasses attestation | Accepted by design for local development | The flag is measured in runtime configuration and should fail production attestation policy |
| [#561](https://github.com/Dstack-TEE/dstack/issues/561) KMS TLS client certificates are non-mandatory in Rocket config | Docs-only for current architecture | The TLS listener allows unauthenticated bootstrap endpoints, while sensitive KMS handlers enforce client certificate and attestation checks in application code |
| [#552](https://github.com/Dstack-TEE/dstack/issues/552) Static HKDF salt and no key versioning | Design roadmap, not a near-term vulnerability | Static salt is acceptable with high-entropy KMS root material and explicit context; key versioning/rotation requires a broader compatibility design |

Recommended GitHub cleanup for this cluster:

- Keep #606 open until the `0600` hardening change lands, then close it as completed.
- Close #605, #561, #607, #608, and #609 with links to the relevant security docs and maintainer rationale.
- Keep a separate roadmap issue for KMS key versioning/rotation if it has an owner and migration plan; otherwise close #552 as not planned for the current KDF version.

## Search terms for duplicate-prone findings

Researchers and AI agents should search this page and linked issues before treating these as new vulnerabilities:

- `quote_enabled = false`
- `auth_api.type = "dev"`
- `gateway_app_id = "any"`
- `rpc.tls.mutual.mandatory = false`
- `get_temp_ca_cert`
- `ed25519` and `secp256k1` with the same derivation path
- `RATLS` HKDF salt
- KMS key versioning and rotation
- app keys and decrypted env file permissions
