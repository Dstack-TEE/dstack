# Public Security Reports

This page tracks public GitHub issues filed as security reports or mirrors of private advisories. It shows whether each report is fixed, documented, not a production vulnerability, duplicate, or still open.

For new exploitable vulnerabilities, use the private reporting path in [SECURITY.md](../../SECURITY.md). Do not include exploit details in public issues.

Status snapshot: 2026-06-30. General support, process, consolidation, and feature-request issues are excluded. Related hardening and roadmap trackers are listed separately.

## Report outcomes

Use these outcomes when reading public security reports and already-public findings:

| Outcome | Meaning |
| --- | --- |
| Valid report, fixed | The report was valid and was addressed by a code or configuration change |
| Valid report, documented | The report describes real behavior, but the project response is documentation or threat-model clarification rather than a code change |
| Valid hardening, open | The report is valid defense-in-depth work and remains open |
| Valid roadmap, open | The report identifies security-related design work that needs a compatibility or migration plan |
| Not a production vulnerability | The report does not compromise supported production deployments under the documented threat model |
| Duplicate | The report repeats another public issue or private advisory response |

## Public reports and findings

These issues were filed as concrete vulnerability reports, security audit findings, or public mirrors of private advisories. Some resulted in fixes. Some are documented design choices or not production vulnerabilities.

| Issue | Status | Outcome | Project response |
| --- | --- | --- | --- |
| [#549](https://github.com/Dstack-TEE/dstack/issues/549) Disk encryption key collision when `no_instance_id=true` and HKDF context ambiguity | Open | Valid report, documented | `no_instance_id=true` intentionally shares disk keys across instances, and the HKDF inputs have fixed lengths. No code fix has been applied. Zero-padding for the unset instance ID remains optional hardening |
| [#550](https://github.com/Dstack-TEE/dstack/issues/550) Compose hash computed on raw bytes, not canonicalized JSON | Closed | Valid report, documented | dstack treats compose JSON as an opaque byte sequence. Any byte-level change is a different measured application configuration. No code fix was applied |
| [#551](https://github.com/Dstack-TEE/dstack/issues/551) Shell injection via `init_script` and `pre_launch_script` in compose | Closed | Valid report, documented | Scripts are application-owned code and are measured as part of app configuration. Verifiers must treat script contents as part of the application trust decision. No code fix was applied |
| [#552](https://github.com/Dstack-TEE/dstack/issues/552) Static HKDF salt and no key versioning | Open | Valid roadmap, open | Static salt is acceptable with high-entropy KMS root material and explicit context. No code fix has been applied. Key versioning and rotation require a broader compatibility design |
| [#553](https://github.com/Dstack-TEE/dstack/issues/553) `derive_dh_secret` hashes PKCS#8 DER | Closed | Valid report, fixed | [#603](https://github.com/Dstack-TEE/dstack/pull/603) stabilizes the P-256 private key encoding used for derivation |
| [#554](https://github.com/Dstack-TEE/dstack/issues/554) Signature concatenation without length prefixes enables collision | Open | Valid report, fixed | [#604](https://github.com/Dstack-TEE/dstack/pull/604) enforces the 20-byte `app_id` length in CVM setup |
| [#555](https://github.com/Dstack-TEE/dstack/issues/555) LUKS header TOCTOU between validation and `luksOpen` | Open | Not a production vulnerability | The setup code validates and opens the same in-memory LUKS header. No code fix was applied |
| [#556](https://github.com/Dstack-TEE/dstack/issues/556) Disk encryption key and WireGuard key visible in `/proc/PID/cmdline` | Open | Valid hardening, open | Tracks removal of transient command-line exposure for secret-bearing setup commands |
| [#557](https://github.com/Dstack-TEE/dstack/issues/557) Runtime event log writable by any VM process | Open | Valid report, fixed | [#602](https://github.com/Dstack-TEE/dstack/pull/602) restricts runtime event-log permissions |
| [#558](https://github.com/Dstack-TEE/dstack/issues/558) Path traversal in KMS `remove_cache` | Closed | Valid report, fixed | [#601](https://github.com/Dstack-TEE/dstack/pull/601) validates cache paths before deletion |
| [#559](https://github.com/Dstack-TEE/dstack/issues/559) Zero `mr_config_id` bypasses verification and weakens `mr_aggregated` identity | Open | Not a production vulnerability | Zero `mr_config_id` remains an unset-value compatibility case, and configuration changes are still reflected through RTMR-based measurements. No code fix was applied |
| [#560](https://github.com/Dstack-TEE/dstack/issues/560) Admin token comparison not constant-time | Open | Not a production vulnerability | The comparison is over a SHA-256 digest of a high-entropy token, not the raw token. No code fix was applied |
| [#561](https://github.com/Dstack-TEE/dstack/issues/561) KMS TLS client certificates are non-mandatory in Rocket config | Open | Valid report, documented | The TLS listener allows unauthenticated bootstrap endpoints, while sensitive KMS handlers enforce client certificate and attestation checks in application code. No code fix was applied |
| [#562](https://github.com/Dstack-TEE/dstack/issues/562) Configfs path overridable through an environment variable | Open | Not a production vulnerability | A process that can choose its own quote path is already inside the measured CVM behavior. No code fix has been applied. A production guard for `DCAP_TDX_QUOTE_CONFIGFS_PATH` remains possible hardening |
| [#563](https://github.com/Dstack-TEE/dstack/issues/563) `simulate_quote` runtime path in production guest agent | Open | Valid report, fixed | [#582](https://github.com/Dstack-TEE/dstack/pull/582) isolates the simulator into a dedicated binary |
| [#564](https://github.com/Dstack-TEE/dstack/issues/564) `GetAppEnvEncryptPubKey` unauthenticated app ID enumeration | Open | Not a production vulnerability | The RPC returns a public encryption key before an app has an attested identity, and `app_id` is not treated as secret. No code fix was applied |
| [#565](https://github.com/Dstack-TEE/dstack/issues/565) Infinite loop in `wait_for_generation_change` | Closed | Valid report, fixed | [#596](https://github.com/Dstack-TEE/dstack/pull/596) bounds the ConfigFS generation wait loop |
| [#566](https://github.com/Dstack-TEE/dstack/issues/566) Gzip decompression bomb in RA-TLS cert extension | Open | Valid report, fixed | [#595](https://github.com/Dstack-TEE/dstack/pull/595) bounds decompressed RA-TLS event-log extension size |
| [#567](https://github.com/Dstack-TEE/dstack/issues/567) Unbounded allocation in `VecOf` decode | Open | Valid report, fixed | [#570](https://github.com/Dstack-TEE/dstack/pull/570) caps `VecOf` decode length and pre-allocation |
| [#568](https://github.com/Dstack-TEE/dstack/issues/568) Webhook URL leaked via `println!` in production code | Closed | Valid report, fixed | Fixed before the issue was triaged by removing the unsafe log output in `79b8b8d2` |
| [#605](https://github.com/Dstack-TEE/dstack/issues/605) Guest agent derives identical key material for `ed25519` and `secp256k1` | Open | Valid report, documented | Existing derived key bytes are preserved. Docs state that `path` is the domain separator and callers must use algorithm-specific paths when they require independent keys. No code fix was applied |
| [#606](https://github.com/Dstack-TEE/dstack/issues/606) App keys and decrypted env files world-readable | Open | Valid hardening, open | Tightening secret-bearing file writes to owner-only permissions (`0600`) is valid defense-in-depth work with no expected compatibility cost |
| [#607](https://github.com/Dstack-TEE/dstack/issues/607) `gateway_app_id = "any"` disables gateway identity pinning | Open | Not a production vulnerability | `gateway_app_id` is KMS contract configuration and is publicly auditable. Production deployments must not use `"any"`. No code fix was applied |
| [#608](https://github.com/Dstack-TEE/dstack/issues/608) `auth_api.type = "dev"` allows all authorization | Open | Not a production vulnerability | Dev auth is measured runtime configuration, not a production mode. Production must use webhook/on-chain authorization. No code fix was applied |
| [#609](https://github.com/Dstack-TEE/dstack/issues/609) `quote_enabled = false` bypasses attestation | Open | Not a production vulnerability | The flag is measured in runtime configuration and should fail production attestation policy. No code fix was applied |
| [#610](https://github.com/Dstack-TEE/dstack/issues/610) Unauthenticated bootstrap endpoint can overwrite root keys | Closed | Not a production vulnerability | The bootstrap endpoint does not accept caller-supplied root key material. Root keys are generated server-side, and the operator chooses which result to publish. No code fix was applied |
| [#611](https://github.com/Dstack-TEE/dstack/issues/611) Unauthenticated `/finish` endpoint can shut down KMS onboard service | Closed | Not a production vulnerability | The onboard service is a short-lived setup flow. Premature shutdown causes operator retry, not persistent compromise or data loss. No code fix was applied |
| [#612](https://github.com/Dstack-TEE/dstack/issues/612) Gateway `register_cvm` prefers stale `app_info` over live attestation | Closed | Not a production vulnerability | Cert-embedded `app_info` is extracted from attestation and signed by KMS. Preferring it avoids redundant extraction and is not a trust bypass. No code fix was applied |
| [#613](https://github.com/Dstack-TEE/dstack/issues/613) 10-year default certificate validity undermines attestation freshness | Closed | Not a production vulnerability | RA-TLS certificates embed attestation evidence and verifiers validate that evidence during connection handling. Freshness policy belongs in verifier policy, not only certificate expiry. No code fix was applied |
| [#614](https://github.com/Dstack-TEE/dstack/issues/614) VMM `no_tee` flag allows launching VMs without TDX protection | Closed | Not a production vulnerability | `no_tee` VMs cannot produce valid TDX quotes and cannot join the production trust chain unless other development-only checks are also disabled. No code fix was applied |
| [#615](https://github.com/Dstack-TEE/dstack/issues/615) Host-supplied `sys_config` not measured but influences security-critical behavior | Closed | Not a production vulnerability | Network endpoints are not trust anchors. KMS, gateway, and PCCS trust decisions rely on cryptographic verification, not host-supplied URLs. No code fix was applied |
| [#616](https://github.com/Dstack-TEE/dstack/issues/616) Host-controlled Docker registry mirror enables image substitution attacks | Closed | Not a production vulnerability | Registry mirrors are untrusted transport. Digest-pinned image references and measured compose configuration protect against substitution. No code fix was applied |
| [#617](https://github.com/Dstack-TEE/dstack/issues/617) Guest agent exposes raw private keys to all local processes | Closed | Not a production vulnerability | dstack treats a CVM as one application trust domain. It does not provide per-container key isolation inside the same measured application. No code fix was applied |
| [#618](https://github.com/Dstack-TEE/dstack/issues/618) Disk encryption disableable via kernel cmdline, not measured in RTMR | Closed | Not a production vulnerability | The kernel command line is measured into RTMR2, so changing `dstack.storage_encrypted=false` changes attestation evidence. No code fix was applied |
| [#619](https://github.com/Dstack-TEE/dstack/issues/619) KMS `get_temp_ca_cert` returns temp CA private key without authentication | Closed | Duplicate | The report duplicates the private advisory response for the temp CA bootstrap flow |

## Related security roadmap and hardening

These issues affect security architecture, future verification behavior, operational hardening, or security documentation. They are intentionally separated from the report table because they are not vulnerability reports.

| Issue | Status | Type | Scope |
| --- | --- | --- | --- |
| [#113](https://github.com/Dstack-TEE/dstack/issues/113) Alternative to RA-TLS | Open | Architecture roadmap | Tracks possible application-level attestation or pre-registration approaches |
| [#114](https://github.com/Dstack-TEE/dstack/issues/114) On-chain logs for KMS replication | Open | Auditability roadmap | Tracks transparency for KMS onboarding and replication events |
| [#115](https://github.com/Dstack-TEE/dstack/issues/115) Censorship resistance in the KMS | Open | Governance roadmap | Tracks how KMS instances should prove an up-to-date chain view after de-registration or policy changes |
| [#411](https://github.com/Dstack-TEE/dstack/issues/411) Adopt RFC 8785 JCS for canonical compose hash calculation | Open | Measurement roadmap | Tracks a possible future canonical hash scheme. Current raw-byte hashing is intentional and recorded in #550 |
| [#745](https://github.com/Dstack-TEE/dstack/issues/745) `secure_time: true` cannot sync because guest chrony lacks NTS | Open | Security feature bug | Tracks a secure-time boot failure. The fix is in [meta-dstack#76](https://github.com/Dstack-TEE/meta-dstack/pull/76) |
| [#746](https://github.com/Dstack-TEE/dstack/issues/746) Harden AMD SEV-SNP KDS collateral fetch | Open | Availability hardening | Tracks async client, timeout, and caching hardening for SNP KDS collateral fetch. Verification remains fail-closed |
