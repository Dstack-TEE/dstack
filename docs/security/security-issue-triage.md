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

## March 2026 audit cluster (#549-#609)

The March audit cluster contained a mix of real fixes, hardening work, compatibility decisions, false positives, and public threat-model questions. Several implementation PRs in this number range fixed reports, and some issue state has not caught up with the maintainer position.

Already closed as completed: [#550](https://github.com/Dstack-TEE/dstack/issues/550), [#551](https://github.com/Dstack-TEE/dstack/issues/551), [#553](https://github.com/Dstack-TEE/dstack/issues/553), [#558](https://github.com/Dstack-TEE/dstack/issues/558), [#565](https://github.com/Dstack-TEE/dstack/issues/565), and [#568](https://github.com/Dstack-TEE/dstack/issues/568). The sibling public security issues [#614](https://github.com/Dstack-TEE/dstack/issues/614), [#615](https://github.com/Dstack-TEE/dstack/issues/615), [#616](https://github.com/Dstack-TEE/dstack/issues/616), [#617](https://github.com/Dstack-TEE/dstack/issues/617), [#618](https://github.com/Dstack-TEE/dstack/issues/618), and [#619](https://github.com/Dstack-TEE/dstack/issues/619) are also closed as completed.

| Issue | Classification | Maintainer action |
| --- | --- | --- |
| [#549](https://github.com/Dstack-TEE/dstack/issues/549) Disk encryption key collision when `no_instance_id=true` and HKDF context ambiguity | Accepted by design, optional hardening | `no_instance_id=true` intentionally shares disk keys across instances, and the HKDF inputs have fixed lengths. Close the original as not planned, or split zero-padding for the unset instance ID into a separate hardening issue if an owner wants it |
| [#552](https://github.com/Dstack-TEE/dstack/issues/552) Static HKDF salt and no key versioning | Design roadmap, not a near-term vulnerability | Static salt is acceptable with high-entropy KMS root material and explicit context; key versioning/rotation requires a broader compatibility design |
| [#554](https://github.com/Dstack-TEE/dstack/issues/554) Signature concatenation without length prefixes enables collision | Fixed | [#604](https://github.com/Dstack-TEE/dstack/pull/604) enforces the 20-byte `app_id` length in CVM setup; close as completed |
| [#555](https://github.com/Dstack-TEE/dstack/issues/555) LUKS header TOCTOU between validation and `luksOpen` | Accepted by design | The setup code validates and opens the same in-memory LUKS header. Close as not planned with the maintainer rationale |
| [#556](https://github.com/Dstack-TEE/dstack/issues/556) Disk encryption key and WireGuard key visible in `/proc/PID/cmdline` | Needs hardening | Keep open while removing transient command-line exposure for secret-bearing setup commands, or close only if the maintainer explicitly accepts the early-boot exposure in the documented threat model |
| [#557](https://github.com/Dstack-TEE/dstack/issues/557) Runtime event log writable by any VM process | Fixed | [#602](https://github.com/Dstack-TEE/dstack/pull/602) restricts runtime event-log permissions; close as completed |
| [#559](https://github.com/Dstack-TEE/dstack/issues/559) Zero `mr_config_id` bypasses verification and weakens `mr_aggregated` identity | Accepted compatibility decision, docs-only | Zero `mr_config_id` remains an unset-value compatibility case, and configuration changes are still reflected through RTMR-based measurements. Close as not planned after linking the threat-model rationale |
| [#560](https://github.com/Dstack-TEE/dstack/issues/560) Admin token comparison not constant-time | Accepted by design | The comparison is over a SHA-256 digest of a high-entropy token, not the raw token. Close as not planned unless the token format changes |
| [#561](https://github.com/Dstack-TEE/dstack/issues/561) KMS TLS client certificates are non-mandatory in Rocket config | Docs-only for current architecture | The TLS listener allows unauthenticated bootstrap endpoints, while sensitive KMS handlers enforce client certificate and attestation checks in application code |
| [#562](https://github.com/Dstack-TEE/dstack/issues/562) Configfs path overridable through an environment variable | Accepted threat-model decision, possible hardening | A process that can choose its own quote path is already inside the measured CVM behavior. Close the original with that rationale, or split a production guard for `DCAP_TDX_QUOTE_CONFIGFS_PATH` into a hardening issue |
| [#563](https://github.com/Dstack-TEE/dstack/issues/563) `simulate_quote` runtime path in production guest agent | Fixed | [#582](https://github.com/Dstack-TEE/dstack/pull/582) isolates the simulator into a dedicated binary; close as completed |
| [#564](https://github.com/Dstack-TEE/dstack/issues/564) `GetAppEnvEncryptPubKey` unauthenticated app ID enumeration | Accepted by design | The RPC returns a public encryption key before an app has an attested identity, and `app_id` is not treated as secret. Close as not planned after linking the bootstrap rationale |
| [#566](https://github.com/Dstack-TEE/dstack/issues/566) Gzip decompression bomb in RA-TLS cert extension | Fixed | [#595](https://github.com/Dstack-TEE/dstack/pull/595) bounds decompressed RA-TLS event-log extension size; close as completed |
| [#567](https://github.com/Dstack-TEE/dstack/issues/567) Unbounded allocation in `VecOf` decode | Fixed | [#570](https://github.com/Dstack-TEE/dstack/pull/570) caps `VecOf` decode length and pre-allocation; close as completed |
| [#605](https://github.com/Dstack-TEE/dstack/issues/605) Identical raw key material across `ed25519` and `secp256k1` for the same path | Accepted compatibility decision, docs-only | Existing derived key bytes are preserved; docs now state that `path` is the domain separator and callers must use algorithm-specific paths when they require independent keys |
| [#606](https://github.com/Dstack-TEE/dstack/issues/606) App keys and decrypted env files world-readable | Needs hardening | Tightening secret-bearing file writes to owner-only permissions (`0600`) is a valid defense-in-depth improvement with no expected compatibility cost |
| [#607](https://github.com/Dstack-TEE/dstack/issues/607) `gateway_app_id = "any"` disables gateway identity pinning | Accepted by design for dev/test deployments | `gateway_app_id` is KMS contract configuration and is publicly auditable; production deployments must not use `"any"` |
| [#608](https://github.com/Dstack-TEE/dstack/issues/608) `auth_api.type = "dev"` allows all authorization | Accepted by design for local/integration testing | Dev auth is measured runtime configuration, not a production mode; production must use webhook/on-chain authorization |
| [#609](https://github.com/Dstack-TEE/dstack/issues/609) `quote_enabled = false` bypasses attestation | Accepted by design for local development | The flag is measured in runtime configuration and should fail production attestation policy |

Recommended GitHub cleanup for this cluster:

- Keep #556 and #606 open only while their hardening patches are pending, then close them as completed.
- Close #554, #557, #563, #566, and #567 as completed, with links to the fixing PRs.
- Close #549, #555, #559, #560, #561, #562, #564, #605, #607, #608, and #609 with links to the relevant security docs and maintainer rationale.
- Keep a separate roadmap issue for #552 key versioning/rotation if it has an owner and migration plan; otherwise close #552 as not planned for the current KDF version.
