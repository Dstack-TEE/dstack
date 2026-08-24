# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- sdk: `verify_signature` and `verify_signature_chain` in all four SDKs, replacing the deprecated guest-agent `Verify` RPC. `verify_signature_chain` is new capability rather than a port: it walks all three links of a `Sign` signature chain -- payload signature, the app root key attesting `"{purpose}:{hex(pubkey)}"`, and the KMS root attesting that app root for this `app_id` -- and requires the chain to anchor at a KMS root public key **the caller supplies**. That anchor has to come from somewhere independently trusted (the `DstackKms` contract's `kmsInfo().k256Pubkey`, or a pinned value); read it from the KMS being checked and an attacker who can answer that query can also mint a self-consistent chain. The four ports are pinned against one committed set of test vectors, `sdk/tests/vectors/signature_chain.json`, generated from the real KMS and guest-agent primitives -- this repo has shipped cross-language crypto drift twice already
- guest-agent: a versioned API, `dstack.guest.v1`, covering both trust surfaces. `DstackGuestV1` is served at `/v1` on the internal socket (`IssueCert`, `GetKey`, `Attest`, `AttestGpu`, `Info`, `Version`); `WorkerV1` at `/prpc/v1` on the external listener (`Info`, `Version`, `AttestAppKey`, `Health`). They are two services rather than one mounted twice because the two listeners have different reachability: the internal socket answers only the app itself and hands out key material, the external one answers anyone who can route to the CVM and never does. The scheme is uniform across both listeners: `/v0` and `/v1` on the internal socket, `/prpc/v0` and `/prpc/v1` on the external one, where `v0` is the frozen v0.5.11 surface. The historical unversioned paths (`/` and `/prpc`) stay mounted as aliases onto the same frozen handlers, so a pre-0.6 client keeps working unchanged and cannot drift from `/v0` -- they are additional mounts, not a parallel implementation. Version selection is by URL path alone -- no header negotiation, no default-version redirect -- so a request URL is the whole record of which contract the caller asked for. `Tappd` predates this scheme and is untouched. Specified byte-for-byte in `docs/guest-api-v1.md`, which is the normative reference an implementation is written from
- guest-agent: v1 derives application keys under a real domain-separated KDF. v0 fed the path alone into HKDF and handed the same 32 bytes to both secp256k1 and ed25519, so the two curves shared one secret and the algorithm a caller asked for changed nothing about the key it got. v1 derives under its own HKDF salt (`dstack-guest-v1`, against the legacy `RATLS`) and binds a versioned context tag, the algorithm and the caller's `domain` as length-prefixed fields, so the curves never collide and no two names encode alike -- a path is arbitrary caller-chosen bytes, so any delimiter it could also contain is a collision waiting to happen. **v1 keys are therefore not v0 keys for the same name**, deliberately and with no compatibility mode; an app holding assets under a v0 key migrates them with a transaction signed by the old key. The separate salt matters because the legacy HKDF `info` is the caller's `path` verbatim: under a shared salt, a caller passing the v1 `info` byte string as a v0 `path` reproduced a v1 key exactly. That was never a privilege boundary -- same app, same root key, either surface reachable -- but a KDF whose separation depends on nobody choosing an awkward input is one refactor from separating nothing, and it costs nothing to close on a surface with no deployed keys. The derivation is flat: `a/b` is not a child of `a`, and there is no BIP-32-style hierarchy. Committed test vectors pin the output bytes
- guest-agent: v1's signature-chain claim cannot be forged through the v0 surface. v0's first link signs `keccak256("{purpose}:{hex(pubkey)}")` over a caller-chosen `purpose`, which lets a malicious app steer the app root key into signing nearly any ASCII string ending in `:` plus hex. The v1 claim is length-prefixed and binds the raw public key bytes, so it always contains `00` bytes inside the region a v0 preimage requires to be hex-only. The exclusion is structural rather than probabilistic, and a regression test builds the strongest available forgery and asserts it fails
- guest-agent: v1 ships no `Sign` and no `Verify`. The agent is not an HSM: anything that can reach this socket can ask `GetKey` for the private key, so a server-side `Sign` grants no capability its caller lacks and buys an IPC round trip and another entry point to audit. Verifying needs neither key nor attestation, and the agent's answer arrives unattested. Apps sign locally with a standard library; relying parties verify locally against the normative rules in `docs/guest-api-v1.md`, which specify the KDF, the claim encoding, and every verification step down to the trust anchor. Both RPCs stay on the unversioned surface for 0.5.x clients
- guest-agent: v1 `GetTlsKey` is renamed `IssueCert`, because certificate issuance is the operation -- the agent builds a CSR and relays it to the KMS `SignCert` flow. The returned private key is incidental: freshly generated per call, fed by none of the request fields, and unrelated to the app identity. Only the integrated one-step mode ships; a caller-supplied-CSR mode would arrive as new fields
- guest-agent: v1 `Info` returns identity and configuration only. The `tcb_info` JSON blob is gone: its measurement values are typed top-level fields that each appear exactly once, and the documents it nested (`app_compose`, `vm_config`) are served directly instead of through two layers of JSON parsing. MRTD, RTMR0-3 and the event log are deliberately absent -- they are attestation data, and `Info` handing out unattested copies invited relying parties to trust values nothing vouched for. Ask `Attest` and verify. The demo `app_cert` is dropped as well
- guest-agent: `AttestGpu` collects vendor-native GPU evidence on demand against a caller-supplied 32-byte nonce. It returns opaque, versioned evidence bundles identified by vendor and format for independent appraisal, and the response format is extensible to additional GPU vendors. v1 only
- guest-agent: v1 `Attest` accepts `include_boottime_gpu_evidence` and returns the boot-time GPU attestation evidence in `AttestResponse.boottime_gpu_evidence`, so a verifier fetches the attestation and the GPU evidence in one round trip. `Attest` is also v1's sole CVM attestation entry point: the `VersionedAttestation` it returns already carries the TDX quote and event log, and unlike `GetQuote` it answers on every supported platform
- sdk: `AppCompose` in the Go SDK gained `init_script`, `storage_fs`, `swap_size`, `event_log_version`, `port_policy` and `verity_volumes`, and `Requirements` gained `gpu_policy` in the Go and Python SDKs
- shared API authentication (`dstack-api-auth`) protecting the full VMM HTTP/pRPC/UI surface and unifying Gateway/KMS admin auth: bearer/`X-Admin-Token`/HTTP Basic/bcrypt htpasswd, constant-time verification (#796)
- gateway: `Admin.Status` reports `health_gating`, so an operator can see whether this node's health polling is switched on. With it off, instances that opted in sit at `unknown` forever and are all in rotation, which is otherwise indistinguishable on the dashboard from being held out pending a first answer
- gateway: `Admin.SetInstanceReady` takes a CVM instance out of its app's load-balancing rotation without stopping it; instance-id routing stays open so the instance can still be investigated, and the setting survives re-registration
- gateway: operator-set per-instance overrides now live under their own KV keys — `admin/<instance_id>/ready` and `admin/<instance_id>/port_policy` — instead of inside the instance record, so a CVM re-registration can no longer drop them and setting one cannot discard a peer's unsynced change to the other. An override left in an instance record by an earlier build is moved across on load
- gateway: opt-in application-level health polling. An app sets `requirements.health_check` in its app-compose; the gateway then asks that CVM's guest agent (new `WorkerV1.Health` RPC, polled at `/prpc/v1`) whether the app is serving, and keeps instances that say no -- or that have not answered since registering -- out of app-id load balancing. Apps that do not opt in are never polled. Instance-id routing is never gated, and an app whose every instance reports unhealthy is routed to anyway rather than blackholed. Verdicts are per-node and not persisted: a gateway restart puts the whole app back at `unknown` at once, which is exactly the case the fail-open covers. Documented in `docs/app-health-checks.md`
- app-compose: `requirements.health_status_file` names a file the app writes its own verdict into -- two lines, `healthy`/`unhealthy` and the unix timestamp it was written at, treated as unhealthy once older than 60s. It must be a regular file (a FIFO would park a thread of the agent's blocking pool on every refresh); symlinks are followed, and its contents are never quoted back into a report. Without it the agent judges the app's own Compose project: every container that declares a `healthcheck` must be running and healthy, and a project where *no* container declares one reports unhealthy rather than passing silently
- guest-agent: container health also covers the `nerdctl-compose` runner, read through `nerdctl inspect` (its output is Docker-compatible). Requires nerdctl >= 2.3.1 for Compose `healthcheck:` to be honoured; the mkosi backend is pinned to 2.3.5
- http-client: a caller can bound the response body (`http_request_bounded`, `PrpcClient::with_max_response_bytes`). Nothing is bounded by default — `dstack vmm logs --lines 100000` is a legitimate multi-megabyte fetch — but every client that talks to a guest agent opts in, in the gateway and in the VMM, because a CVM is untrusted and one of them polls on a timer against the whole fleet

### Fixed
- gateway: a node removed via `RemoveNode` silently rejoined the cluster the next time it started, because every node re-registers its own sync address on boot. Once tombstone GC is collecting, that comeback is worse than an annoyance: a stale data directory diverges from every digest, and the divergence repair's full re-exchange resurrects records whose deletes the cluster already collected. Removal now writes a durable marker — a live record, so the GC can never eat it — that every gateway's sync endpoints enforce; a removed node's envelopes are refused until an operator re-admits it with `SetNodeUrl`. The refused node counts HTTP 403 sync rejections (`dstack_gateway_sync_rejected_total`), including removal lockouts and app-identity mismatches. Every gateway also exposes `dstack_gateway_node_last_seen_timestamp_seconds` per known node, so a long-offline gateway is a one-line alert instead of an ack-watermark puzzle
- gateway: deleted KV records left a tombstone that nothing ever collected, so every deregistered CVM stayed on disk for the life of the deployment. Tombstones every peer has acknowledged are now dropped once every `tombstone_gc_writes` replicated writes (default 10000, zero disables); the trigger counts replicated writes rather than reading a clock, so nodes in a cluster collect in the same window without depending on time synchronization. A `SetTombstoneGcConfig` admin RPC stores an operator override in the KV itself, replicating one pace to every node
- gateway: `Admin.RemoveCvm` now reports the outcome of the `inst/` tombstone alone. A failure to delete associated override or telemetry records is logged instead of failing the call, so a removal that did take effect is no longer reported as failed — which also aborted the local routing cleanup that follows it. Re-issuing a removal still sweeps up override and telemetry records orphaned by an earlier partial failure
- sdk: `get_compose_hash` in the Python SDK mutated the dictionary it was given, stripping `docker_config` and `requirements` from it, so hashing the same manifest twice returned two different digests -- the second one for a manifest missing those blocks
- sdk: the Go compose-hash helper HTML-escaped `<`, `>` and `&`, so an app-compose carrying an `os_version` bound such as `">=0.6.1"` hashed differently in Go than in Rust, Python and JavaScript. Any digest Go produced for such a manifest was wrong, and that digest is what gets whitelisted on chain
- sdk: the Go SDK's `gpu_policy` silently dropped sub-fields it did not declare on a decode/re-hash round trip; it now carries them through like the rest of `Requirements`
- bound VMM-to-guest RPCs and guest-agent dependency calls to prevent stalled peers from retaining request resources indefinitely
- sdk: the Go and Python compose-hash helpers silently dropped every app-compose field they did not declare, so `getComposeHash` returned a digest for an app-compose that was not the one being deployed — and that digest is what gets whitelisted on chain. The missing fields are named above; both now keep unrecognised keys as well, so a guest that gains a field before the SDK does still hashes correctly

### Changed
- kms: client certificates are authenticated by the attestation they carry rather than by their issuer. Rocket configures mutual TLS through rustls' `WebPkiClientVerifier`, which pins a CA — but an RA-TLS certificate is self-issued and carries its identity in a TEE quote, so there is nothing to chain to. `GetTempCaCert` bridged the gap by handing every caller a shared CA private key purely so the minted certificate would chain somewhere; the CA established nothing (its key is public by design, and the endpoint is unauthenticated) and the check that has always carried the meaning is the quote verification that runs afterwards. The KMS now hands rustls a verifier that requires an attestation and ignores the issuer. Nothing changes for callers: guests and KMS-to-KMS onboarding still mint their client certificates from the temp CA, and those are now accepted for the attestation they carry. What changes is that the TLS layer went from admitting any certificate signed by a public key to requiring an attested one, and that a self-issued certificate is now accepted — which is what lets callers be migrated off `GetTempCaCert` in a follow-up. `[rpc.tls.mutual]` is no longer the trust anchor and is dropped from `kms.toml` and the KMS config templates; leaving it in an existing deployment's config is inert. The gateway's `[tls.mutual]` is unaffected — it pins the KMS root CA, which is a real trust anchor
- guest-agent: the `/metrics` exposition gains a conventions-compliant `dstack_guest_*` series set (application prefix; `_bytes`/`_seconds` unit suffixes; no `_total` suffix on gauges, which reads as a counter to every tool; the four OS/kernel/CPU gauges folded into one `dstack_guest_info`; `disk_used_ratio` 0–1 instead of a percentage). The old `system_*`/`disk_*` names are still emitted verbatim, marked deprecated, and will be removed in a future release — this endpoint is tenant-facing, so existing dashboards get a migration window
- dstack-util: a CVM re-registers with the gateway node that last accepted it, before falling back to the configured order. The list used to be walked from the top every time, so every CVM piled onto the first URL and the whole fleet snapped back to it the moment it recovered from an outage — and each move rewrites the instance record from a different node's memory
- vmm: optionally randomize the KMS and gateway URL orders written to each CVM's system configuration so new CVMs distribute their initial requests across service nodes; both are enabled by default in `vmm.toml`
- http-client: HTTP clients are built once and shared instead of per request, which is what every `http_request*` call did until now -- each one paid for a connection pool, a DNS resolver and a TLS configuration it then threw away. Callers choose whether requests may reuse a connection (`RequestOptions::connection_reuse`, `PrpcClient::with_connection_reuse`); the default is to reuse. The gateway's health poller opts out: opening the connection is half of what a probe asks, since an agent that has run out of file descriptors keeps serving connections it already has while refusing every new one -- and every connection the gateway proxies to an app is a new one
- os/yocto: nerdctl 2.2.1 → 2.3.5, so `nerdctl compose` honours the Compose `healthcheck:` field (only translated into `--health-*` flags from 2.3.1 on). Requires openembedded-core to move to `wrynose` head for go 1.26.5, which also brings gcc 15.2 → 15.3 — every guest image measurement changes, so the new image hashes need whitelisting in KMS
- guest-agent: both unversioned surfaces are closed at exactly v0.5.11, and every new capability goes to `dstack.guest.v1` instead. Everything added to them after v0.5.11 never shipped in a release, so it is removed rather than frozen in: on the internal `DstackGuest`, `GpuInfo`, `AttestGpu` and `Attest`'s `include_boottime_gpu_evidence`/`boottime_gpu_evidence`; on the external `Worker`, `AttestAppKey` and `Health`. `AttestGpu`, the boot-time evidence, `AttestAppKey` and `Health` are v1 features now; `GpuInfo` is gone entirely, because `Attest(include_boottime_gpu_evidence)` returns the same bytes. No released client is affected -- both services are now byte-identical to v0.5.11 apart from doc comments and `reserved` statements holding the interim field numbers, so an unreleased `next` build in a dev environment cannot have one of them silently absorbed by a future field. "Frozen except for additions" is how all of them arrived in the first place
- guest-agent: `GetQuote` is restricted to Intel TDX. It used to answer on every platform, returning an empty `quote` plus a `GetQuoteResponse.attestation` field carrying the versioned attestation — a shape only that one RPC produced, and one `Attest` already covers. Platforms without TDX now get an error telling them to call `Attest`, and the `attestation` field is gone from the RPC and from the Rust, Python, Go and JS SDKs. GCP Confidential VMs still get an answer — the gate is whether the platform has a TDX quote — but only the TDX half of one: `GetQuoteResponse` has no field for the vTPM quote GCP's verification also binds, so relying parties there want `Attest`, and the docs say so. `Tappd.TdxQuote`/`RawQuote` share the same backend path, so they fail closed there too instead of returning an empty quote
- guest-agent: `Worker.GetAttestationForAppKey` is **retained** on the frozen external surface, and `WorkerV1.AttestAppKey` supersedes it. The old method returns a `GetQuoteResponse`, so restricting `GetQuote` to Intel TDX leaves it unable to answer anywhere else, which would have left an external caller on any other platform with no way to attest an app key at all -- `Attest` is on the internal socket, and an external caller could not use it anyway, not knowing the app key's public key until the agent derives it. Rather than change an RPC present since v0.5.7, it keeps its v0.5.11 wire shape and stays TDX-only, and `AttestAppKey` on the v1 external surface takes the same request and returns an `AttestResponse` on every platform. Both build their report data through the same code, so they commit to the same public key for a given algorithm; only the envelope differs


### Removed
- sdk: the client-side `verify()` method is gone from the Rust, Python, Go and JavaScript SDKs, replaced by the standalone `verify_signature` above -- it never needed a client connection in the first place. Checking a signature needs no key material and no attestation, and the agent's verdict arrived over the socket unattested, so a caller who believed the TEE was vouching for it was mistaken and one who did not gained nothing over checking the signature locally. Verification also became stricter in one respect: non-canonical high-S secp256k1 signatures are now rejected explicitly everywhere. `k256` accepted only the canonical form, so the Rust agent already behaved this way, but a naive port to Python or Go would have silently accepted both `(r, s)` and `(r, n-s)` for the same message. The server-side `Verify` RPC (`/Verify`, present since v0.5.6) is **retained** on the unversioned guest-agent path so 0.5.x SDKs keep working against a 0.6 agent unchanged; it is deprecated, its semantics are frozen at the v0.5.11 wire surface, and it will not be carried into the v1 API. New code should verify locally
- guest-agent: the `EmitEvent` RPC no longer records anything -- runtime RTMR3 events are system-owned in 0.6.0, so an app can no longer extend the measurement chain. The method itself stays on the unversioned path and always fails with an error naming the removal, rather than being deleted outright: prpc answers both "no such method" and "the handler failed" with HTTP 400 and drops the message, so a deleted method would leave a 0.5.x caller with a generic error indistinguishable from a wrong socket or a version skew. **Breaking:** any app extending RTMR3 at runtime must stop; bind app data through `report_data` instead, which is what most callers wanted anyway


## [0.5.5] - 2025-10-20

### Added
- SDK sync agent for automated protobuf schema synchronization (#366)
- dstack-verifier CLI tool with OS image hash verification (#341)
- built-in swap configuration support for CVMs (#348, #357, #358)
- support for ext4 filesystem type on storage (#348)
- size-parser crate for handling size configurations (#355)
- init_script support in app-compose.json (#337)
- cache for verifier (#341)
- Add QEMU version and image name in VmConfig (#340)
- documentation for minimum version of each compose field (#363)

### Changed
- max app compose size increased to 256K (#349)
- default timeout increased to 3 secs for python SDK (#339)
- auto reconnect when WireGuard gets stuck (#350)
- put filesystem type in RTMR3 event log (#348)
- read QEMU path from /etc/dstack/client.conf (#332)
- refactor sys-config generation code (#351)
- when formatting app_url, skip port if it's 443 (#326)
- update docker organization references (#342, #343)
- RA-TLS: add KeyCertSign and CrlSign usages for CA cert (#320)

### Fixed
- guest-agent: request demo cert lazily
- VmConfig decode error (#347)
- potential panic due to int overflow in dstack-mr (#345)
- SDK issues - marked rootfs_hash optional (#339)

### Removed
- docker_config field from app-compose.json (#374)

## [0.5.4] - 2025-09-01

### Security
- Fixed LUKS header validation security vulnerability (GHSA-jxq2-hpw3-m5wf)

### Added
- Support for generating borsh schema for public types (#302)
- Python SDK v0.5.0 with async support
- Auth backend examples (auth-mock, auth-eth-bun)
- Support for passt as network egress
- Support for more than 255 CPUs
- SPDX license annotations
- Security audit report and documentation
- Media kit and branding updates
- gRPC proxy support for gateway
- Browser compatibility for JS SDK
- git-cliff based changelog generation
- CONTRIBUTING.md documentation

### Changed
- Better error reporting for TDX quote errors
- Moved generated prpc files to OUT_DIR
- Refactored dstack-sdk into two crates for no_std support
- Updated various dependencies (sha.js, elliptic, tokio, etc.)
- Improved vmm with one-shot support
- Updated documentation for non-KMS app access
- Consolidated dstack branding capitalization

### Fixed
- Warnings and clippy issues
- Networking configuration issues
- Typing errors in Python SDK
- Compilation errors in supervisor
- Reserved IP allocation issues

### Contributors
New contributors in this release:
- @DSharifi
- @pbeza
- @bravesasha
- @Olexandr88
- @crStiv

## [0.5.3] - 2025-06-24

### Added
- Add doc design-and-hardening-decisions.md by @kvinwang
- Add doc cvm-boundaries.md by @kvinwang
- Add ERC-165 support with hardcoded interface IDs by @Leechael
- Add warning for dev kms by @kvinwang
- Add script to config firewall for qemu by @kvinwang

### Changed
- Bump version to 0.5.3 by @kvinwang
- Merge pull request #225 from Dstack-TEE/license by @h4x3rotab in [#225](https://github.com/Dstack-TEE/dstack/pull/225)
- Create LICENSE by @h4x3rotab
- Merge pull request #221 from Dstack-TEE/doc-harden by @kvinwang in [#221](https://github.com/Dstack-TEE/dstack/pull/221)
- Update dcap-qvl to 0.3.0 by @kvinwang
- Default max disk size to 10T by @kvinwang
- Merge pull request #220 from Dstack-TEE/feat-gateway-admin-rpc-get-meta-v05x by @Leechael in [#220](https://github.com/Dstack-TEE/dstack/pull/220)
- Merge pull request #216 from Dstack-TEE/doc-cvm-boundaries by @kvinwang in [#216](https://github.com/Dstack-TEE/dstack/pull/216)
- Merge pull request #215 from Dstack-TEE/sec-guide by @kvinwang in [#215](https://github.com/Dstack-TEE/dstack/pull/215)
- Merge branch 'master' into sec-guide by @kvinwang
- Add security guide by @kvinwang
- Merge pull request #217 from Dstack-TEE/add-reprobuid-note by @kvinwang in [#217](https://github.com/Dstack-TEE/dstack/pull/217)
- Add link to reproducible build by @kvinwang
- Merge pull request #213 from Dstack-TEE/kms-erc-165-support by @Leechael in [#213](https://github.com/Dstack-TEE/dstack/pull/213)
- Remove duplicate code. by @Leechael
- Update kms auth related docs by @Leechael
- Commands in hardhat.config.ts by @Leechael
- Build error. by @Leechael
- Update typechain-types. by @Leechael
- Add C code source URL by @kvinwang
- Add security guide by @kvinwang
- Better deployment script by @kvinwang
- Don't copy symbol link files by @kvinwang
- Merge pull request #212 from Dstack-TEE/impl-up-user-config by @kvinwang in [#212](https://github.com/Dstack-TEE/dstack/pull/212)
- Implement update user_config in UI and CLI by @kvinwang
- Merge pull request #199 from Dstack-TEE/config-fw by @Leechael in [#199](https://github.com/Dstack-TEE/dstack/pull/199)
- Update comments by @kvinwang
- Correct checking symlink existance by @kvinwang
- Merge pull request #207 from Dstack-TEE/gw-rt by @kvinwang in [#207](https://github.com/Dstack-TEE/dstack/pull/207)
- Seperate proxy runtime from Rocket by @kvinwang
- Use jemalloc by @kvinwang
- Merge pull request #210 from Dstack-TEE/vmm-gpu-attach-all-opt by @kvinwang in [#210](https://github.com/Dstack-TEE/dstack/pull/210)
- Optional disable attach all gpus by @kvinwang
- Merge pull request #204 from Dstack-TEE/gw-reload-cert by @kvinwang in [#204](https://github.com/Dstack-TEE/dstack/pull/204)
- Fix unit tests by @kvinwang
- Hot reload TLS certificate by @kvinwang
- Add helper function reload_certs by @kvinwang
- Merge pull request #203 from Dstack-TEE/gw-health by @kvinwang in [#203](https://github.com/Dstack-TEE/dstack/pull/203)
- Add health check endpoint by @kvinwang
- Merge pull request #202 from Dstack-TEE/config-tls-ver by @kvinwang in [#202](https://github.com/Dstack-TEE/dstack/pull/202)
- Cargo fmt by @kvinwang
- Configrable tls version and crypto provider by @kvinwang
- Extract create acceptor to a function by @kvinwang
- Merge pull request #205 from Dstack-TEE/vmm-cfg-id by @kvinwang in [#205](https://github.com/Dstack-TEE/dstack/pull/205)
- Only set mr_config_id for supported images by @kvinwang
- Update dstack version to 0.5.2 in docs by @kvinwang
- Merge branch 'gw-no-status' by @kvinwang in [#198](https://github.com/Dstack-TEE/dstack/pull/198)
- Move rpc status/info to admin port by @kvinwang
- Fix tboot.service in dep by @kvinwang

### Fixed
- Move get_meta to admin API. by @Leechael
- Fix test cases for AppAuth test. by @Leechael

### Removed
- Remove unused field bootstraped from InstanceInfo by @kvinwang
- Remove head from dstack-util show by @kvinwang

## [0.5.2] - 2025-06-04

### Added
- Add optional appAuthImplementation setting in initialize by @Leechael
- Add AI generated cheatsheet. by @Leechael
- Add add deploy factory support to KmsAuth by @Leechael
- Add initializeWithData to AppAuth by @Leechael
- Add debug hints for download_image by @Leechael
- Add gateway_app_id to KMS.GetMetaResponse by @Leechael
- Add get_compose_hash endpoint for compose-hash check. by @Leechael
- Added detail in error message for destination issue debugging. by @Leechael
- Adds docstrings by @tuddman

### Changed
- Dstack v0.5.2 by @kvinwang in [#196](https://github.com/Dstack-TEE/dstack/pull/196)
- Merge pull request #195 from Dstack-TEE/mr_config_id_v2 by @kvinwang in [#195](https://github.com/Dstack-TEE/dstack/pull/195)
- Better way to get td report by @kvinwang
- Implement mr_config_id v2 by @kvinwang
- Merge pull request #181 from Dstack-TEE/feat/gateway-rpc-domain-and-kms-info-enhancements by @kvinwang in [#181](https://github.com/Dstack-TEE/dstack/pull/181)
- Merge pull request #182 from Dstack-TEE/imp-app-auth-contract by @Leechael in [#182](https://github.com/Dstack-TEE/dstack/pull/182)
- Code review feedback. by @Leechael
- Update typechain-types by @Leechael
- Update deploy script & cheatsheet docs. by @Leechael
- _registerAppInternal. by @Leechael
- Remove redundant initialization code. by @Leechael
- Expose app implementation address by @Leechael
- Update generated assets. by @Leechael
- Clippy by @Leechael
- Chore（gateway): Add debug log for AcmeClient. by @Leechael
- Expose more metadata in GetMeta API. by @Leechael
- Fmt by @Leechael
- Allows to configure RPC_DOMAIN optionally by @Leechael
- Merge pull request #177 from Dstack-TEE/cvm-kms-url by @kvinwang in [#177](https://github.com/Dstack-TEE/dstack/pull/177)
- Merge pull request #179 from Dstack-TEE/fix-vmm-cli by @Leechael in [#179](https://github.com/Dstack-TEE/dstack/pull/179)
- Update_vm_env with custom kms_urls by @Leechael
- Support for set kms/gw urls for individual CVM by @kvinwang
- Merge pull request #193 from near-bookrock/master by @kvinwang in [#193](https://github.com/Dstack-TEE/dstack/pull/193)
- Merge branch 'master' into master by @near-bookrock
- Merge pull request #194 from tuddman/rust-sdk-docstrings by @kvinwang in [#194](https://github.com/Dstack-TEE/dstack/pull/194)
- Vmm ui: Fix gpu mode display in upgrade panel by @kvinwang
- Use rbind mount by @kvinwang
- Merge pull request #192 from Dstack-TEE/fix-log-span by @kvinwang in [#192](https://github.com/Dstack-TEE/dstack/pull/192)
- Fix bug in log span by @kvinwang
- Make all fields public by @near-bookrock
- Make tcb_info public by @near-bookrock

### Fixed
- Clippy by @Leechael
- Abi in factory method is incorrect. by @Leechael
- Set ensure_ascii=False when generated compose-hash by @Leechael
- Compatible with custom kms-url and gateway-url by @Leechael

## New Contributors
* @near-bookrock made their first contribution
## [0.5.1] - 2025-05-29

### Added
- Support for enforce key provider id in compose by @kvinwang
- Add deepwiki badge by @h4x3rotab
- Add option to hide tcbinfo from 8090 port by @kvinwang
- Add repobeats analytics by @h4x3rotab

### Changed
- Merge branch 'configid' by @kvinwang in [#190](https://github.com/Dstack-TEE/dstack/pull/190)
- Support for bind key provider by @kvinwang
- Set compose hash to mr_config_id by @kvinwang
- Validate compose_hash according to configid by @kvinwang
- Merge pull request #191 from Dstack-TEE/rm-mr-kp by @kvinwang in [#191](https://github.com/Dstack-TEE/dstack/pull/191)
- Fix typo by @kvinwang
- Merge pull request #187 from Dstack-TEE/kms-clear-cache by @kvinwang in [#187](https://github.com/Dstack-TEE/dstack/pull/187)
- Minor rename by @kvinwang
- Add ensure_admin by @kvinwang
- Add RPC to clear image cache by @kvinwang
- Update to v0.5.1 in README by @kvinwang
- Merge branch 'up-md' by @kvinwang in [#189](https://github.com/Dstack-TEE/dstack/pull/189)
- Update build steps in README by @kvinwang
- Update build steps in README by @kvinwang
- Merge pull request #188 from Dstack-TEE/readme by @h4x3rotab in [#188](https://github.com/Dstack-TEE/dstack/pull/188)
- Merge pull request #186 from Dstack-TEE/rpc-req-id by @kvinwang in [#186](https://github.com/Dstack-TEE/dstack/pull/186)
- Add request id by @kvinwang
- Merge pull request #180 from Dstack-TEE/gw-app-auth by @kvinwang in [#180](https://github.com/Dstack-TEE/dstack/pull/180)
- Add LAUNCH TOKEN by @kvinwang
- Add auth API by @kvinwang
- Merge pull request #183 from Dstack-TEE/md-custom-domain by @kvinwang in [#183](https://github.com/Dstack-TEE/dstack/pull/183)
- Update Custom Domain in README by @kvinwang
- Merge pull request #184 from Dstack-TEE/public-tcbinfo by @kvinwang in [#184](https://github.com/Dstack-TEE/dstack/pull/184)
- Merge pull request #185 from Dstack-TEE/readme by @h4x3rotab in [#185](https://github.com/Dstack-TEE/dstack/pull/185)
- Merge pull request #178 from Dstack-TEE/metrics by @Leechael in [#178](https://github.com/Dstack-TEE/dstack/pull/178)
- Add prometheus metrics API by @kvinwang
- Merge pull request #176 from Dstack-TEE/fix-subvar by @kvinwang in [#176](https://github.com/Dstack-TEE/dstack/pull/176)
- More for the rename by @kvinwang
- Rename mr_image to os_image_hash by @kvinwang
- Update deployment doc by @kvinwang
- Update kms compose file by @kvinwang
- Fix mr_image verification issues by @kvinwang
- Minor rename by @kvinwang
- Cargo fmt by @kvinwang
- Support for the new mr_image model by @kvinwang
- Add mr_image in sys-config.json by @kvinwang
- Update CI config by @kvinwang
- Bump versio to 0.5.1 by @kvinwang
- Auto setulimit by @kvinwang
- Remove dep on openssl by @kvinwang in [#174](https://github.com/Dstack-TEE/dstack/pull/174)

### Fixed
- Missed subvar in deploy-to-vmm.sh script by @Leechael

### Removed
- Remove the unused mr_key_provider by @kvinwang

## [0.5.0] - 2025-05-15

### Added
- Add extend_rtmr3 in tdx-attest by @kvinwang
- Support verity based rootfs by @kvinwang
- Adds build-able TlsKeyConfig by @tuddman
- Add rust client for dstack by @Created-for-a-purpose
- Add extend_rtmr3 in tdx-attest by @kvinwang
- Add inspect API for kms/auth-api by @Leechael
- Added requirements.txt by @Leechael

### Changed
- Fix update compose file by @kvinwang
- Fix mount path by @kvinwang
- Update rust in tproxy docker image to 1.86 by @kvinwang
- Merge pull request #173 from Dstack-TEE/sodiumbox by @kvinwang in [#173](https://github.com/Dstack-TEE/dstack/pull/173)
- Implement sodiumbox by @kvinwang
- Better layout for upgrade pannel by @kvinwang
- Merge pull request #171 from Dstack-TEE/dev-0.5.0 by @kvinwang in [#171](https://github.com/Dstack-TEE/dstack/pull/171)
- Cargo fmt by @kvinwang
- Add venv.sh by @kvinwang
- Upgraded test kms contract by @kvinwang
- Auto update certs on start by @kvinwang
- Rm gpus section when no GPUs by @kvinwang
- Mount overlayfs on /home/root by @kvinwang
- Allow null gpu config by @kvinwang
- Fix clippy by @kvinwang
- Use 0.5.0 base image by @kvinwang
- Allow non-zero mr_config_id by @kvinwang
- Add tproxy_app_id for compatibility by @kvinwang
- Merge remote-tracking branch 'ds/master' into dev-0.5.0 by @kvinwang
- Better layout for Features by @kvinwang
- Fix gpu config issues by @kvinwang
- New gpu config format by @kvinwang
- Load tdx-guest.ko in prepare.sh by @kvinwang
- Fix invalid config in dstack-prepare.service by @kvinwang
- Run dstack-prepare service after chronyd by @kvinwang
- Use ZFS for data partition by @kvinwang in [#159](https://github.com/Dstack-TEE/dstack/pull/159)
- Optional secure time by @kvinwang
- Use extend_rtmr3 from tdx-attest by @kvinwang
- Rename tdxctl to dstack-util by @kvinwang
- Bump version to 0.5.0 by @kvinwang
- Merge pull request #170 from Dstack-TEE/rust-1.86 by @kvinwang in [#170](https://github.com/Dstack-TEE/dstack/pull/170)
- Use rust 1.86 by @kvinwang
- Merge pull request #169 from Dstack-TEE/fix-rust-sdk by @kvinwang in [#169](https://github.com/Dstack-TEE/dstack/pull/169)
- Fix incorrect args in rust-sdk by @kvinwang
- Merge pull request #161 from RizeLabs/feat/dstack-sdk-rust by @kvinwang in [#161](https://github.com/Dstack-TEE/dstack/pull/161)
- Merge pull request #6 from tuddman/rust-sdk-addendum-4 by @nlok5923
- Merge pull request #5 from tuddman/rust-sdk-addendum-3 by @nlok5923
- Merge pull request #4 from tuddman/rust-sdk-addendum-2 by @nlok5923
- Merge pull request #3 from tuddman/rust-sdk-addendum by @nlok5923
- Replace evidence-api with dcap-qvl by @Created-for-a-purpose
- Replace ethers with alloy by @Created-for-a-purpose
- Crate renaming + add readme by @nlok5923
- Merge pull request #1 from Created-for-a-purpose/dstack-sdk-rust by @nlok5923
- Minor cleanup by @Created-for-a-purpose
- Merge pull request #168 from Dstack-TEE/rust-1.86 by @kvinwang in [#168](https://github.com/Dstack-TEE/dstack/pull/168)
- Update Rust in CI to 1.86 by @kvinwang
- Merge pull request #165 from Dstack-TEE/fix-upgrade-btn by @kvinwang in [#165](https://github.com/Dstack-TEE/dstack/pull/165)
- Fix disappeared [Upgrade] button by @kvinwang
- Merge pull request #164 from Dstack-TEE/agent-start-order by @kvinwang in [#164](https://github.com/Dstack-TEE/dstack/pull/164)
- Ensure agent starts before docker by @kvinwang
- Merge pull request #166 from Dstack-TEE/rm-command by @kvinwang in [#166](https://github.com/Dstack-TEE/dstack/pull/166)
- Remove command from the api by @kvinwang
- Merge pull request #160 from Dstack-TEE/api-extend-rtmr3 by @h4x3rotab in [#160](https://github.com/Dstack-TEE/dstack/pull/160)
- Add API EmitEvent by @kvinwang
- Add API EmitEvent by @kvinwang
- Optimize vmm firewall rules by @kvinwang
- Merge pull request #156 from Dstack-TEE/fix-phala-cloud-integration by @Leechael in [#156](https://github.com/Dstack-TEE/dstack/pull/156)
- Gateway app: Optional turning on sync mode by @kvinwang
- Fmt(tdxctl) by @Leechael
- Merge pull request #155 from Dstack-TEE/docs by @h4x3rotab in [#155](https://github.com/Dstack-TEE/dstack/pull/155)
- Update docs by @h4x3rotab
- Merge pull request #154 from Dstack-TEE/app-deploy by @h4x3rotab in [#154](https://github.com/Dstack-TEE/dstack/pull/154)
- [doc] Add app deployment section in deployment.md by @kvinwang

### Fixed
- Ordering and unnecessary import by @tuddman
- Suggested changes by @tuddman
- Fixes PR feedback by @tuddman
- Allowed_app_id comparation for gateway should be case insensitive. by @Leechael
- Deploy scripts. by @Leechael
- Tappd.sock has been rename to dstack.sock by @Leechael
- Use up-to-date package name in docker-compose.yml by @Leechael
- Typechain-types by @Leechael

### Removed
- Remove sodiumoxide from Cargo.toml by @kvinwang

## New Contributors
* @nlok5923 made their first contribution
* @tuddman made their first contribution
* @Created-for-a-purpose made their first contribution
## [0.4.2] - 2025-04-18

### Added
- Support https for prpc client by @kvinwang
- Add client agent API docs by @kvinwang
- Add signature verification in go tests by @kvinwang
- Add back the previous go sdk implementation by @kvinwang
- Add dstack simulator config by @kvinwang
- Add a note on how to access info about Dstack by @HashWarlock
- Add unknown-2035.json by @kvinwang
- Add mr_system by @kvinwang
- Add info API. by @Leechael
- Add ethereum Account transform. by @Leechael
- Add optional dependencies solders & keypair generate support by @Leechael
- Add encryptEnvVars by @Leechael
- Add docs/deployment.md by @kvinwang
- Added view stderr in teepod's builtin console by @Leechael
- Add note about how to view stderr by @Leechael
- Add tproxy setup guide & faq by @Leechael
- Add script to deploy kms to teepod by @kvinwang
- Support ACME_STAGING for the docker by @kvinwang
- Add --build to docker compose by @kvinwang
- Add dbg log by @kvinwang
- Add example code by @kvinwang
- Add Attestation doc by @kvinwang

### Changed
- V0.4.2 by @kvinwang in [#153](https://github.com/Dstack-TEE/dstack/pull/153)
- Merge pull request #152 from Dstack-TEE/fix-status by @kvinwang in [#152](https://github.com/Dstack-TEE/dstack/pull/152)
- Fix status display after CVM updated by @kvinwang
- Merge pull request #149 from Dstack-TEE/pccs_url by @kvinwang in [#149](https://github.com/Dstack-TEE/dstack/pull/149)
- Read pccs_url from env var by @kvinwang
- Merge pull request #150 from Dstack-TEE/prpc-client-https by @kvinwang in [#150](https://github.com/Dstack-TEE/dstack/pull/150)
- Merge pull request #151 from Dstack-TEE/api-doc by @kvinwang in [#151](https://github.com/Dstack-TEE/dstack/pull/151)
- Better config fallback for tproxy_enabled by @kvinwang
- Don't include compose file in brief mode by @kvinwang
- Merge pull request #148 from Dstack-TEE/rename-tapp by @kvinwang in [#148](https://github.com/Dstack-TEE/dstack/pull/148)
- Cargo fmt by @kvinwang
- Rename tapp to app or /dstack by @kvinwang
- Unify dstack agent address getter by @kvinwang
- Rename run_as_tapp to run_in_dstack by @kvinwang
- Rename _tapp-address to _dstack-app-address by @kvinwang
- Fix default agent_port and gateway_urls alias by @kvinwang
- Merge pull request #146 from Dstack-TEE/auto-restart by @kvinwang in [#146](https://github.com/Dstack-TEE/dstack/pull/146)
- Auto restart exited VMs by @kvinwang
- Merge pull request #147 from Dstack-TEE/error-on-wrong-contract by @kvinwang in [#147](https://github.com/Dstack-TEE/dstack/pull/147)
- Kms script: Throw error if app auth not found by @kvinwang
- Merge pull request #145 from Dstack-TEE/cross-tdx-attest by @kvinwang in [#145](https://github.com/Dstack-TEE/dstack/pull/145)
- Make tdx-attest compile on non-linux by @kvinwang
- Merge pull request #144 from Dstack-TEE/rename-sdk by @kvinwang in [#144](https://github.com/Dstack-TEE/dstack/pull/144)
- Js sdk: Warn for  simulator endpoint by @kvinwang
- Refactor python SDK by @kvinwang
- Refactor js sdk by @kvinwang
- Refactor go sdk by @kvinwang
- Merge pull request #142 from Dstack-TEE/renaming by @kvinwang in [#142](https://github.com/Dstack-TEE/dstack/pull/142)
- Merge pull request #143 from Dstack-TEE/simulator by @kvinwang in [#143](https://github.com/Dstack-TEE/dstack/pull/143)
- Use app key to sign the derived key by @kvinwang
- Rename more tappd in comments to guest agent by @kvinwang
- Always generate random tls key by @kvinwang
- One more rename by @kvinwang
- Rename get_eth_key to get_key by @kvinwang
- API backward compatibility for vmm and gw by @kvinwang
- Set mime application/json by @kvinwang
- Rename kms to dstack-kms by @kvinwang
- Rename teepod to dstack-vmm by @kvinwang
- Rename tproxy to dstack-gateway by @kvinwang
- Different handler for v0 and latest by @kvinwang
- Fix service name emittion by @kvinwang
- Add report_data in GetQuote response by @kvinwang
- Rename tappd to dstack-guest-agent by @kvinwang
- Fix file existance check by @kvinwang
- Update safe-write to 0.1.2 by @kvinwang
- Merge pull request #140 from Dstack-TEE/tappd-health by @kvinwang in [#140](https://github.com/Dstack-TEE/dstack/pull/140)
- Don't reuse connections in healthy check client by @kvinwang
- Persistent iptalbes rules by @kvinwang
- Merge pull request #139 from Dstack-TEE/teepod-compat by @kvinwang in [#139](https://github.com/Dstack-TEE/dstack/pull/139)
- Compatible older images by @kvinwang
- Merge pull request #138 from HashWarlock/patch-1 by @h4x3rotab in [#138](https://github.com/Dstack-TEE/dstack/pull/138)
- Merge pull request #137 from Dstack-TEE/gpu-include by @kvinwang in [#137](https://github.com/Dstack-TEE/dstack/pull/137)
- Add gpu whitelist by @kvinwang
- Merge pull request #135 from Dstack-TEE/mr-kms by @kvinwang in [#135](https://github.com/Dstack-TEE/dstack/pull/135)
- Add mr-kms to RTMR3 by @kvinwang
- Merge pull request #134 from Dstack-TEE/teepod-ui-opt by @kvinwang in [#134](https://github.com/Dstack-TEE/dstack/pull/134)
- Auto close dropdown by @kvinwang
- Store page size to localStorage by @kvinwang
- More efficient pagination by @kvinwang
- Add pagination/search and optimize net traffic by @kvinwang
- Support for updating port mapping by @kvinwang
- Merge pull request #133 from Dstack-TEE/cvm-fw by @kvinwang in [#133](https://github.com/Dstack-TEE/dstack/pull/133)
- Add script setting the user net firewall by @kvinwang
- Update deployment.md by @kvinwang
- Validate TCB attributes by @kvinwang
- Default memory size to 2048 by @kvinwang
- Show compose hash in the UI by @kvinwang
- Print watchdog error detail by @kvinwang
- Default max_disk_size to 500GB by @kvinwang
- Merge pull request #132 from Dstack-TEE/vec-reserved-net by @kvinwang in [#132](https://github.com/Dstack-TEE/dstack/pull/132)
- Turns reserved-net into an array by @kvinwang
- Fix used slots detect by @kvinwang
- Update unknown-2035.json by @kvinwang
- Release GPU for exited instances by @kvinwang
- Merge pull request #131 from Dstack-TEE/kms-tcb by @kvinwang in [#131](https://github.com/Dstack-TEE/dstack/pull/131)
- Reject to send keys to outdated TCB nodes by @kvinwang
- Add tcbStatus and advisoryIds to BootInfo by @kvinwang
- Update unknown-2035.json by @kvinwang
- Fix missing mrImage in BootInfo by @kvinwang
- V0.4.1 by @kvinwang
- Merge pull request #130 from Dstack-TEE/refactor-contracts by @kvinwang in [#130](https://github.com/Dstack-TEE/dstack/pull/130)
- Refactor KMS contracts to support the new MRs by @kvinwang
- Add device control by @kvinwang
- Merge pull request #128 from Dstack-TEE/det-rtmr3 by @kvinwang in [#128](https://github.com/Dstack-TEE/dstack/pull/128)
- Teepod ui: no_instance_id if no tproxy by @kvinwang
- Rename fn by @kvinwang
- Support for --no-instance-id by @kvinwang
- Optional instance-id by @kvinwang
- Merge pull request #129 from Dstack-TEE/up-deps by @kvinwang in [#129](https://github.com/Dstack-TEE/dstack/pull/129)
- Update dependencies by @kvinwang
- Merge pull request #110 from Dstack-TEE/sdk-updates by @Leechael in [#110](https://github.com/Dstack-TEE/dstack/pull/110)
- Doc update & release. by @Leechael
- Bump py sdk to 0.1.6 & js sdk to 0.1.11 by @Leechael
- Info API & update docs. by @Leechael
- Udpate sdk docs. by @Leechael
- V0.1.10 by @Leechael
- V0.1.8 by @Leechael
- Helper function for solana Keypair by @Leechael
- Update README.md by @Leechael
- TappdInfo API. by @Leechael
- Merge pull request #127 from Dstack-TEE/teepod-gpu by @kvinwang in [#127](https://github.com/Dstack-TEE/dstack/pull/127)
- Cargo fmt by @kvinwang
- Show slot or product_id for associated device by @kvinwang
- Refresh gpus status while opening deploy panel by @kvinwang
- Filter started vm while restore devices by @kvinwang
- Also release devices after shutdown by @kvinwang
- Auto start vm after created by @kvinwang
- Store allocated device id to instance state by @kvinwang
- Add pin-numa and hugepages by @kvinwang
- Add slot in gpu list by @kvinwang
- Support to start CVM with GPUs by @kvinwang
- Merge pull request #126 from Dstack-TEE/teepod-foreground by @kvinwang in [#126](https://github.com/Dstack-TEE/dstack/pull/126)
- Support for non-detached supervisor by @kvinwang
- Add #[serde(default)] by @kvinwang
- Fix compilation error by @kvinwang
- Add secret pubkey verification by @kvinwang
- Fix pubkey in GetMeta by @kvinwang
- Merge pull request #124 from Dstack-TEE/docs-deployment by @kvinwang in [#124](https://github.com/Dstack-TEE/dstack/pull/124)
- Merge pull request #123 from Dstack-TEE/docs by @kvinwang in [#123](https://github.com/Dstack-TEE/dstack/pull/123)
- Merge branch 'deploy-script' by @kvinwang
- Merge pull request #122 from Dstack-TEE/deploy-script by @kvinwang in [#122](https://github.com/Dstack-TEE/dstack/pull/122)
- Update contracts DB by @kvinwang
- Kms cli: Remove salt from app:deploy by @kvinwang
- Add update-env by @kvinwang
- Better deployment script by @kvinwang
- Support for UDS by @kvinwang
- Refactor kms deployment script by @kvinwang
- Add nextAppId by @kvinwang
- Merge pull request #121 from Dstack-TEE/set-caa by @kvinwang in [#121](https://github.com/Dstack-TEE/dstack/pull/121)
- Recreate acme account if the stored url doesn't matches by @kvinwang
- Add rpc set CAA by @kvinwang
- Support allowed_envs by @kvinwang
- Show mrs after got key if the provider is not KMS by @kvinwang
- Don't compile contracts in docker by @kvinwang
- Use lkp for kms by @kvinwang
- Merge pull request #120 from Dstack-TEE/kp-dockerfile by @kvinwang in [#120](https://github.com/Dstack-TEE/dstack/pull/120)
- Refactor key-provider docker files by @kvinwang
- Update hardhat config by @kvinwang
- Merge pull request #119 from Dstack-TEE/sign-pubkey by @kvinwang in [#119](https://github.com/Dstack-TEE/dstack/pull/119)
- Sign env encrypt pubkey by @kvinwang
- Merge pull request #118 from Dstack-TEE/env-whitelist by @kvinwang in [#118](https://github.com/Dstack-TEE/dstack/pull/118)
- Only allow wihtelisted envs by @kvinwang
- Merge pull request #117 from Dstack-TEE/refactor-shared by @kvinwang in [#117](https://github.com/Dstack-TEE/dstack/pull/117)
- Fix unit tests by @kvinwang
- Only allow wihtelisted envs by @kvinwang
- Refactor host shared files by @kvinwang
- Merge pull request #116 from Dstack-TEE/multiple-urls by @kvinwang in [#116](https://github.com/Dstack-TEE/dstack/pull/116)
- Support for multiple kms and tproxy URLs as fallback by @kvinwang
- Merge pull request #111 from Dstack-TEE/tproxy-p2p by @kvinwang in [#111](https://github.com/Dstack-TEE/dstack/pull/111)
- Degrade some logs to debug level by @kvinwang
- Fix bad wg config by @kvinwang
- Event channel buffer size=1 by @kvinwang
- Switch to use wg pubkey as internal map key by @kvinwang
- Dedup nodes when updating by @kvinwang
- Broadcast sync when CVM registered by @kvinwang
- Add broadcast syncing by @kvinwang
- Always sync self config to node list by @kvinwang
- Recycle staled nodes by @kvinwang
- Move dashboard to admin port by @kvinwang
- Avoid using unsafe port by @kvinwang
- Cert renew timeout 5mins by @kvinwang
- Fix NODE_URL in deploy script by @kvinwang
- Fix host_address parsing by @kvinwang
- Print unsettled challenges by @kvinwang
- Add SUBNET_INDEX in compose file by @kvinwang
- Refactor deploy script by @kvinwang
- Allow multiple tproxy appid by @kvinwang
- Support for config subnet index by @kvinwang
- Exclude broadcast ip by @kvinwang
- Add wg info in net info rpc by @kvinwang
- Show number of connections for cvm by @kvinwang
- Implement new tproxy reg protocol by @kvinwang
- Send all wg servers to client by @kvinwang
- Refactor the config file by @kvinwang
- Fix nodes update by @kvinwang
- Refacto certbot task creation by @kvinwang
- Don't abort on state loading failure by @kvinwang
- Remove app cert from dashboard by @kvinwang
- Add upgrading flag file by @kvinwang
- Better instance-id handling by @kvinwang
- Add connections counter by @kvinwang
- Add proxy nodes info in dashboard by @kvinwang
- Implement sync client by @kvinwang
- Rename tls_domain to rpc_domain by @kvinwang
- Add API update_state by @kvinwang
- Fix dashboard layout by @kvinwang
- Support for multiple servers in the protocol by @kvinwang
- Merge pull request #107 from Dstack-TEE/tproxy-dev by @kvinwang in [#107](https://github.com/Dstack-TEE/dstack/pull/107)
- Add USE_HEAD option by @kvinwang
- Update compose rev by @kvinwang
- User letsencrypt prod api by @kvinwang
- Refine deploy script by @kvinwang
- Add teepod-cli.py by @kvinwang
- Add host_address in portmap RPC by @kvinwang
- Support for localhost by @kvinwang
- Enable certbot by @kvinwang
- Better log by @kvinwang
- Built-in certbot by @kvinwang
- Tune tproxy config by @kvinwang
- Remove debug log by @kvinwang
- Fix default rocket config by @kvinwang
- Add renew hook by @kvinwang
- Add admin RPC by @kvinwang
- Wip by @kvinwang
- Add tappd client by @kvinwang
- Add tapp for tproxy by @kvinwang
- Merge pull request #91 from Dstack-TEE/kms-onchain by @kvinwang in [#91](https://github.com/Dstack-TEE/dstack/pull/91)
- Minor rename by @kvinwang
- Fix unittests by @kvinwang
- Adjust the deployment scripts by @kvinwang
- Support Upgrade for AppAuth by @kvinwang
- Add proxy deployment script by @kvinwang
- Implement OwnableUpgradable by @kvinwang
- Add fn initialize by @kvinwang
- Append some RPC description by @kvinwang
- RPC Comment by @kvinwang
- Minor rename by @kvinwang
- Refined key derivation by @kvinwang
- Update README.md by @kvinwang
- Merge pull request #99 from Dstack-TEE/attestation-doc by @kvinwang in [#99](https://github.com/Dstack-TEE/dstack/pull/99)
- Merge pull request #98 from 0xshawn/key-provider-enhancement by @kvinwang in [#98](https://github.com/Dstack-TEE/dstack/pull/98)
- Make docker restart always and run as daemon by @0xshawn

### Fixed
- Fix sig verification by @kvinwang
- Parse failed on tcb_info by @Leechael
- Test case for solana. by @Leechael
- ToKeypair failed by @Leechael
- Fix typo in doc. by @Leechael
- Fix js test case. by @Leechael
- Fixed image url by @Leechael

### Removed
- Remove examples by @kvinwang
- Remove service namespace from the RPC by @kvinwang
- Remove /etc in compose file by @kvinwang

## New Contributors
* @HashWarlock made their first contribution
* @0xshawn made their first contribution
## [dev-v0.4.0.0] - 2025-01-17

### Added
- Add kms compose-dev.yaml by @kvinwang
- Add eventlog in KmsInfo by @kvinwang
- Add event digest validation in event logs replay by @kvinwang
- Add kms/README.md by @kvinwang
- Add transfer ownership to AppAuth.sol by @kvinwang
- Add demo cert in tappd by @kvinwang
- Add random seed for DeriveKey by @kvinwang
- Support for escape ansi color for docker logs by @kvinwang
- Add kms tapp by @kvinwang
- Add workaround for the network issue of the keyprovider by @kvinwang
- Add ci for next branch by @kvinwang
- Support for local key provider by @kvinwang
- Add key-provider build files by @kvinwang
- Add example of using prelaunch script by @kvinwang
- Add apparmor_restrict_unprivileged_userns troubleshooting. by @PierreLeGuen

### Changed
- Use intermediate cert to sign app certs by @kvinwang
- Merge remote-tracking branch 'master' into kms-onchain by @kvinwang
- Update kms/tapp/compose-dev.yaml by @kvinwang
- Rename mr_enclave to mr_aggregated by @kvinwang
- Update dependency versions by @kvinwang
- Validate kms cert by @kvinwang
- Fix cargo clippy by @kvinwang
- Update contract address by @kvinwang
- Add function to set quote and eventlog by @kvinwang
- Store bootstrap info on disk by @kvinwang
- Fix ts error in unittest by @kvinwang
- Show deploy tx hash by @kvinwang
- Update hardhat config by @kvinwang
- Add eventlog in bootstrap result by @kvinwang
- Default to 50 lines of log by @kvinwang
- Show tx hash by @kvinwang
- Better mrs display in the log by @kvinwang
- Fix response data schema by @kvinwang
- Hide Upgrade button for local instances by @kvinwang
- Add tasks by @kvinwang
- Use string as type of tproxyAppId by @kvinwang
- Auto apply certs from tappd by @kvinwang
- Add optional app_id set in UI by @kvinwang
- No default pccs_url by @kvinwang
- Add option tls_no_check_hostname by @kvinwang
- Better auto cert gen for kms & tproxy by @kvinwang
- Update typechain types by @kvinwang
- Update contract deployment script by @kvinwang
- Add api get_root_ca by @kvinwang
- Fix potential start failure by @kvinwang
- Update README.md by @kvinwang
- Update kms app compose by @kvinwang
- Update README by @kvinwang
- Cargo fmt by @kvinwang
- Layout adjustment for README by @kvinwang
- Fix cargo clippy and warnings by @kvinwang
- Remove a debug print by @kvinwang
- Print error log to console by @kvinwang
- Update .gitignore by @kvinwang
- Remove certs copying by @kvinwang
- Support for auto-bootstrap by @kvinwang
- Auto generate certs for dev by @kvinwang
- Fix cert issue in tproxy setup by @kvinwang
- Extract cert-client to seperate crate by @kvinwang
- Max cert chain len = 2 by @kvinwang
- Wip by @kvinwang
- Fix cert chain in derived key by @kvinwang
- Root-ca default filename by @kvinwang
- Write full certchain in cert by @kvinwang
- No short arg for certgen by @kvinwang
- Providing trusted tproxy id by @kvinwang
- Use mr-kp instead of kp-info to calc mr_enclave by @kvinwang
- Print key provider MR by @kvinwang
- Default kms port 8000 by @kvinwang
- Change default onboard port by @kvinwang
- Consistent appid by @kvinwang
- Optimize onboard UI by @kvinwang
- Fix 0x prefix when checking App authority by @kvinwang
- Better error report by @kvinwang
- Fix boot auth url path by @kvinwang
- Update kms config by @kvinwang
- Fix minor issues by @kvinwang
- Fix rootfs_hash parsing in tdxctl by @kvinwang
- Fix hardhat typechain error by @kvinwang
- Display compose hash by @kvinwang
- Kms contracts: Remove appController method by @kvinwang
- Refactor the contracts by @kvinwang
- Update kms Config by @kvinwang
- Tested by @kvinwang
- Auth-eth in ts by @kvinwang
- Add test for contract by @kvinwang
- Derive k256 keys by @kvinwang
- Onboard by @kvinwang
- Add more fields in AppInfo by @kvinwang
- Add ecdsa key provision by @kvinwang
- Support for webhook by @kvinwang
- Put rootfs_hash to kernel args by @kvinwang
- Update Cargo.lock by @kvinwang
- Merge remote-tracking branch 'ds/master' into next by @kvinwang
- Don't redirect stderr to /dev/null by @kvinwang
- Merge pull request #87 from Dstack-TEE/kp-compose by @kvinwang in [#87](https://github.com/Dstack-TEE/dstack/pull/87)
- Update .gitignore by @kvinwang
- Merge pull request #81 from Dstack-TEE/key-provider by @kvinwang in [#81](https://github.com/Dstack-TEE/dstack/pull/81)
- Add device-id in RTMR3 by @kvinwang
- KMS key provider takes precedence by @kvinwang
- Merge pull request #112 from AndrewMohawk/patch-1 by @kvinwang in [#112](https://github.com/Dstack-TEE/dstack/pull/112)
- Update README.md by @AndrewMohawk
- Merge pull request #105 from Dstack-TEE/prune-images by @kvinwang in [#105](https://github.com/Dstack-TEE/dstack/pull/105)
- Pruning unused images by @kvinwang
- Merge pull request #100 from Dstack-TEE/prelaunch-demo by @kvinwang in [#100](https://github.com/Dstack-TEE/dstack/pull/100)
- Merge pull request #106 from Dstack-TEE/fix-clippy by @kvinwang in [#106](https://github.com/Dstack-TEE/dstack/pull/106)
- Fix cargo clippy errors by @kvinwang
- Merge pull request #104 from Dstack-TEE/disk-req by @kvinwang in [#104](https://github.com/Dstack-TEE/dstack/pull/104)
- Add RAM and disk requirement by @kvinwang
- Update prerequisite dependencies by @nanometerzhu
- Merge pull request #95 from Dstack-TEE/remove-orphans by @kvinwang in [#95](https://github.com/Dstack-TEE/dstack/pull/95)
- Implement tdxctl remove-orphans by @kvinwang
- Merge pull request #94 from Dstack-TEE/pre_launch_script by @kvinwang in [#94](https://github.com/Dstack-TEE/dstack/pull/94)
- Add pre_launch_script in app-compose by @kvinwang
- Merge pull request #90 from PierreLeGuen/master by @kvinwang in [#90](https://github.com/Dstack-TEE/dstack/pull/90)

### Removed
- Remove mr ca-cert-hash by @kvinwang

## New Contributors
* @AndrewMohawk made their first contribution
* @PierreLeGuen made their first contribution
## [0.3.4] - 2025-01-04

### Changed
- Update Cargo.lock by @nanometerzhu
- Bump version to v0.3.4 by @nanometerzhu

## [0.3.4-beta] - 2025-01-02

### Changed
- No default not_before by @kvinwang
- Don't redirect stderr to /dev/null by @kvinwang
- Update .gitignore by @kvinwang
- Merge pull request #86 from Dstack-TEE/oom-protect by @kvinwang in [#86](https://github.com/Dstack-TEE/dstack/pull/86)
- Prevent tappd from be killed by OOM-killer by @kvinwang
- Merge pull request #85 from Dstack-TEE/fix-tproxy-conn by @Leechael in [#85](https://github.com/Dstack-TEE/dstack/pull/85)
- Fix bug in connection choosing by @kvinwang
- Merge pull request #84 from Dstack-TEE/readme by @h4x3rotab in [#84](https://github.com/Dstack-TEE/dstack/pull/84)
- Improve readme, address both code contrib and community by @h4x3rotab
- Fix a warning by @kvinwang
- Merge pull request #83 from Dstack-TEE/json-prpc by @kvinwang in [#83](https://github.com/Dstack-TEE/dstack/pull/83)
- Choose json codec in prpc clients by @kvinwang
- Move docker-daemon.json to meta repo by @kvinwang
- Merge pull request #82 from Dstack-TEE/safe-remove-orphans by @kvinwang in [#82](https://github.com/Dstack-TEE/dstack/pull/82)
- A better way to remove orphans by @kvinwang
- Merge pull request #46 from Dstack-TEE/feat-get-meta-api by @Leechael in [#46](https://github.com/Dstack-TEE/dstack/pull/46)
- Inspect public_logs and public_sysinfo option in Worker.Info by @Leechael
- Format by @Leechael
- Rename 'id' to 'instance_id' to avoid potential confusion by @Leechael
- Add GetMeta API for heartbeat. by @Leechael
- Add GetMeta API for heartbeat. by @Leechael
- Add GetMeta API for heartbeat. by @Leechael
- Merge pull request #80 from Dstack-TEE/tboot-no-shutdown by @kvinwang in [#80](https://github.com/Dstack-TEE/dstack/pull/80)
- Don't shutdown when tboot.sh fail by @kvinwang
- Merge pull request #79 from Dstack-TEE/remove-orphans by @kvinwang in [#79](https://github.com/Dstack-TEE/dstack/pull/79)
- Add --remove-orphans to docker compose up by @kvinwang
- Correct check for kmsEnabled in secrets reset by @kvinwang
- Merge pull request #78 from Dstack-TEE/wdg-tappd by @kvinwang in [#78](https://github.com/Dstack-TEE/dstack/pull/78)
- No hardcoded port for watchdog by @kvinwang
- Merge pull request #77 from Dstack-TEE/raw-quote by @kvinwang in [#77](https://github.com/Dstack-TEE/dstack/pull/77)
- Add standalone RawQuote API by @kvinwang
- Merge pull request #76 from Dstack-TEE/quote-prefix by @kvinwang in [#76](https://github.com/Dstack-TEE/dstack/pull/76)
- Add `prefix` for TdxQuote API by @kvinwang
- Merge pull request #74 from Dstack-TEE/confirm-rm by @kvinwang in [#74](https://github.com/Dstack-TEE/dstack/pull/74)
- Comfirm on removal by @kvinwang
- Merge pull request #75 from Dstack-TEE/git-ver by @kvinwang in [#75](https://github.com/Dstack-TEE/dstack/pull/75)
- Add git rev in Version rpc by @kvinwang
- Merge pull request #72 from Dstack-TEE/prpc-query-params by @kvinwang in [#72](https://github.com/Dstack-TEE/dstack/pull/72)
- Eliminates prpc routes file by @kvinwang
- Make the ra_rpc more easier to use by @kvinwang
- Support for reading args from url query by @kvinwang
- Merge pull request #73 from Dstack-TEE/e2fsck-no-reboot by @kvinwang in [#73](https://github.com/Dstack-TEE/dstack/pull/73)
- Don'nt reboot if the e2fsck corrected the fs errors by @kvinwang
- Better logs by @kvinwang
- Show compose file in tcb info by @kvinwang
- Display app name by @kvinwang
- Extract config loading logic to crate load_config by @kvinwang
- Add qmp sock by @kvinwang
- Better status display by @kvinwang

### Fixed
- Fix rev display by @kvinwang

## [0.3.3] - 2024-12-19

### Added
- Add service wg-checker by @kvinwang
- Support for upgrade image by @kvinwang
- Support for disk resizing by @kvinwang
- Add log config by @kvinwang
- Add default docker daemon config by @kvinwang
- Support for boot progress report by @kvinwang
- Add endpoint to ra-rpc server-side by @kvinwang
- Add crate http-client by @kvinwang
- Add crate host-api by @kvinwang
- Add rocket-vsock-listener by @kvinwang
- Add load file button to reset secret panel by @kvinwang

### Changed
- Make some codes more clear using cmd_lib by @kvinwang in [#71](https://github.com/Dstack-TEE/dstack/pull/71)
- Fix dev image does not upgrade by @kvinwang
- Remove since=1d from default logs url by @kvinwang
- Dstack v0.3.3 by @kvinwang in [#70](https://github.com/Dstack-TEE/dstack/pull/70)
- Merge pull request #69 from Dstack-TEE/kms-up by @kvinwang in [#69](https://github.com/Dstack-TEE/dstack/pull/69)
- Fix clippy by @kvinwang
- Allow upgrade base image by @kvinwang
- Fix first boot failure by @kvinwang
- Show version info on page by @kvinwang
- Fix error in console.html by @kvinwang
- Fix error removing .rootfs_hash in upgrading by @kvinwang
- Fix error in e2fsck by @kvinwang
- Fix error: missing bootstrapped when upgraded from old instance by @kvinwang
- Don't run docker compose pull by @kvinwang
- Merge pull request #68 from Dstack-TEE/wg-fix by @kvinwang in [#68](https://github.com/Dstack-TEE/dstack/pull/68)
- Set iptables to reject arbitray ip to send packets to wg port by @kvinwang
- Merge pull request #55 from Dstack-TEE/tappd-api by @kvinwang in [#55](https://github.com/Dstack-TEE/dstack/pull/55)
- Teepod & tappd: Default logs tail=20 by @kvinwang
- Handle app compose versioning by @kvinwang
- Support for optional logs/sysinfo API by @kvinwang
- Merge pull request #67 from Dstack-TEE/up-img by @kvinwang in [#67](https://github.com/Dstack-TEE/dstack/pull/67)
- Allow upgrade in 'exited' state by @kvinwang
- Sync dynamic config on start vm by @kvinwang
- Merge pull request #66 from Dstack-TEE/resize-disk by @kvinwang in [#66](https://github.com/Dstack-TEE/dstack/pull/66)
- Fix clippy by @kvinwang
- Turnneournald config by @kvinwang
- Web display by @kvinwang
- Only refress netinfo when running by @kvinwang
- Fix watchdog issue by @kvinwang
- Better status display by @kvinwang
- Merge pull request #64 from Dstack-TEE/tappd-wd by @kvinwang in [#64](https://github.com/Dstack-TEE/dstack/pull/64)
- Fix clippy by @kvinwang
- Add systemd watchdog by @kvinwang
- Merge pull request #65 from Dstack-TEE/docker-cfg by @kvinwang in [#65](https://github.com/Dstack-TEE/dstack/pull/65)
- Merge pull request #63 from Dstack-TEE/tappd-vsock by @kvinwang in [#63](https://github.com/Dstack-TEE/dstack/pull/63)
- Fix clippy by @kvinwang
- Adjust buttons layout by @kvinwang
- Reuse the same proto of guest api for teepod and tappd by @kvinwang
- Delegate tappd RPCs by @kvinwang
- Add guest api by @kvinwang
- Merge pull request #62 from Dstack-TEE/teepod-vsock by @kvinwang in [#62](https://github.com/Dstack-TEE/dstack/pull/62)
- Fix clippy by @kvinwang
- Accept boot progress report by @kvinwang
- Add client code in by @kvinwang
- Add prpc support by @kvinwang
- Impl host-api by @kvinwang
- Rename upgraded-app-id to compose-hash by @kvinwang
- Merge pull request #61 from Dstack-TEE/tproxy-url-rule by @kvinwang in [#61](https://github.com/Dstack-TEE/dstack/pull/61)
- The ending `s` in the url must be on the port part by @kvinwang
- Change logs since=1h to 0 by @kvinwang
- Merge pull request #60 from Dstack-TEE/tproxy-multi-connect by @kvinwang in [#60](https://github.com/Dstack-TEE/dstack/pull/60)
- Connect to multiple hosts by @kvinwang
- Fix clippy by @kvinwang
- Update prpc-build to 0.3.6 by @kvinwang
- Merge pull request #59 from Dstack-TEE/fix-app-id-on-reset by @kvinwang in [#59](https://github.com/Dstack-TEE/dstack/pull/59)
- Fix incorrect app-id on reset by @kvinwang
- Better logs filter by @kvinwang in [#58](https://github.com/Dstack-TEE/dstack/pull/58)
- Config for overall timeout for a connection by @kvinwang in [#57](https://github.com/Dstack-TEE/dstack/pull/57)
- Auto set ulimit -n by @kvinwang in [#56](https://github.com/Dstack-TEE/dstack/pull/56)
- Upgrade prpc-build to 0.3.5 by @kvinwang
- Upgrade to prpc-build 0.3.4 by @kvinwang
- Merge pull request #54 from Dstack-TEE/disable-scale-ext by @kvinwang in [#54](https://github.com/Dstack-TEE/dstack/pull/54)
- Disable scale ext for protos by @kvinwang
- Add load from file for secrets by @kvinwang
- Fix clippy by @kvinwang
- Merge pull request #52 from Dstack-TEE/vm-pty by @kvinwang in [#52](https://github.com/Dstack-TEE/dstack/pull/52)
- Open a pty for vm console by @kvinwang
- Merge pull request #51 from Dstack-TEE/cert-sign by @kvinwang in [#51](https://github.com/Dstack-TEE/dstack/pull/51)
- Add subcommand to sign a single cert by @kvinwang
- Use safe-write to store the state by @kvinwang
- Merge pull request #50 from Dstack-TEE/setup-wg by @kvinwang in [#50](https://github.com/Dstack-TEE/dstack/pull/50)
- Auto setup wg interface if not already by @kvinwang
- Merge pull request #49 from Dstack-TEE/fix-sdk-hint by @Leechael in [#49](https://github.com/Dstack-TEE/dstack/pull/49)
- Release js sdk 0.1.7 & python sdk 0.1.5 by @Leechael
- The length hint for raw report data in JS/TS SDK by @Leechael
- The length hint for raw report data in Python SDK by @Leechael
- Merge pull request #47 from Hyodar/feat/go-sdk by @kvinwang in [#47](https://github.com/Dstack-TEE/dstack/pull/47)
- Add package summary and author by @Hyodar
- Mention report data size and padding for raw hashing by @Hyodar
- Avoid unnecessary string operations by @Hyodar
- Add DeriveKeyWithSubject and DeriveKeyWithSubjectAndAltNames by @Hyodar
- Add TdxQuoteWithHashAlgorithm by @Hyodar
- Fix typo by @Hyodar
- Improve report data size check error on raw report by @Hyodar
- Add installation instructions and snippet by @Hyodar
- Add constructor options by @Hyodar
- Mention when altNames is included in the request by @Hyodar
- Avoid extra hex decoding in go SDK by @Hyodar
- Add logger to Tappd client creation in go SDK by @Hyodar
- Use info log instead of warn by @Hyodar
- Add RTMR replay to go SDK by @Hyodar
- Add hash algorithms support to go SDK by @Hyodar
- Add Go SDK README by @Hyodar
- Rename go package to tappd by @Hyodar
- Add Golang SDK by @Hyodar
- Simplify the syntax in Cargo.toml by @kvinwang
- Merge pull request #48 from Dstack-TEE/abspath by @kvinwang in [#48](https://github.com/Dstack-TEE/dstack/pull/48)
- Use path-absolutize instead of canonicalize by @kvinwang
- Merge pull request #45 from Dstack-TEE/sysinfo by @kvinwang in [#45](https://github.com/Dstack-TEE/dstack/pull/45)
- Fix cargo clippy by @kvinwang
- Add API SysInfo by @kvinwang

### Fixed
- Keep js sdk padding behavior consistent to python sdk by @Leechael
- Fix raw hashing test using SHA512 by @Hyodar
- Parse RTMRs manually and remove go-tdx-qpl dependency by @Hyodar
- Move tests to test package by @Hyodar
- Test parsing TDX quotes by @Hyodar
- Add go SDK unit tests by @Hyodar
- Add Go SDK unit tests by @Hyodar

## New Contributors
* @Hyodar made their first contribution
## [0.3.2] - 2024-12-09

### Added
- Add support for deriving an app instance by @kvinwang
- Add test case for reportdata check by @Leechael
- Add cargo test in action by @kvinwang
- Add github action clippy by @kvinwang
- Python SDK: add fn info() by @kvinwang
- Add killswitch contract by @kvinwang
- Add example crypt-kv by @kvinwang

### Changed
- V0.3.2 by @kvinwang in [#44](https://github.com/Dstack-TEE/dstack/pull/44)
- Merge pull request #43 from Dstack-TEE/custom-appid by @kvinwang in [#43](https://github.com/Dstack-TEE/dstack/pull/43)
- Cargo fmt by @kvinwang
- Teepod ui: Support for updating vcpu and memory by @kvinwang
- Support custom app-id by @kvinwang
- Validate the compose file when upgrading by @kvinwang
- Only list loadable images by @kvinwang
- Merge pull request #42 from Dstack-TEE/sdk-test-case-for-reportdata-verification by @Leechael in [#42](https://github.com/Dstack-TEE/dstack/pull/42)
- Fix clippy warnings for latest Rust by @kvinwang
- Fix tests by @kvinwang
- Cargo clippy by @kvinwang
- Cargo fmt by @kvinwang
- Format code by @kvinwang
- Merge pull request #41 from Dstack-TEE/cert-time by @kvinwang in [#41](https://github.com/Dstack-TEE/dstack/pull/41)
- Set the default certificate validity period to 1 year by @kvinwang
- Merge pull request #11 from Dstack-TEE/killswitch by @kvinwang in [#11](https://github.com/Dstack-TEE/dstack/pull/11)
- Update notebook by @kvinwang
- Add client code by @kvinwang
- Allow owner to ban self by @kvinwang
- Add info for internal RPC by @kvinwang
- Merge pull request #10 from Dstack-TEE/crypt-kv by @kvinwang in [#10](https://github.com/Dstack-TEE/dstack/pull/10)
- Add ipynb by @kvinwang
- Reduce directory level by @kvinwang

## [0.3.1] - 2024-12-05

### Added
- Add connect timeout & read first byte timeout for proxy by @Leechael
- Add hash_algorithm support python sdk by @Leechael
- Add VmMonitor.get_vm and VmInfo.to_pb by @Leechael
- Add Teepod.GetInfo & Teepod.ResizeVm by @Leechael
- Add TProxy.GetInfo by @Leechael
- Add supervisor by @kvinwang
- Add git rev to apps by @kvinwang
- Add cargo-check-all.sh by @kvinwang
- Support for docker login and registry mirror by @kvinwang
- Support for encrypted env vars by @kvinwang
- Add doc comment for tdxctl by @kvinwang
- Support for no KMS mode by @kvinwang
- Add tappd python client by @kvinwang
- Support for verify quote with PCCS by @kvinwang
- Add instance ID by @kvinwang
- Support to tls passthrough on common domain by @kvinwang
- Support for App Upgrade by @kvinwang
- Add contributors by @h4x3rotab
- Add troubleshooting by @h4x3rotab
- Add LICENSE by @kvinwang
- Support for dev version of image by @kvinwang
- Support for strip ansi colors by @kvinwang
- Add .cursorrules by @kvinwang
- Add certbot-cli by @kvinwang
- Add cert_bot and tests by @kvinwang
- Add Rust version ct_monitor by @kvinwang
- Add ct_monitor.py by @kvinwang
- Add certbot by @kvinwang
- Add user to libvirt group by @kvinwang
- Add external rpc for tappd by @kvinwang
- Add build script by @kvinwang
- Add list page for tproxy by @kvinwang
- Add --config for commands by @kvinwang
- Add vsock modules by @kvinwang
- Add missing cargo feature by @kvinwang
- Add test-scripts by @kvinwang
- Add tproxy by @kvinwang
- Add README.md by @kvinwang
- Support to install image by @kvinwang
- Add default config dir by @kvinwang
- Add teepod by @kvinwang
- Add tappd/tappd-rpc by @kvinwang
- Add mkguest by @kvinwang
- Add tdx-attest/tdxctl/iohash by @kvinwang
- Add tdx-attest-sys by @kvinwang
- Add kms-rpc,rarpc by @kvinwang
- Add kms by @kvinwang
- Add ratls by @kvinwang

### Changed
- Bump version to 0.3.1 by @kvinwang in [#39](https://github.com/Dstack-TEE/dstack/pull/39)
- Merge pull request #32 from Leechael/feat-tproxy-timeouts by @kvinwang in [#32](https://github.com/Dstack-TEE/dstack/pull/32)
- Fix jupyter notebook not work when the browser using a proxy network by @kvinwang
- More flex timeout config and other refactor by @kvinwang
- Merge pull request #38 from Dstack-TEE/universion by @kvinwang in [#38](https://github.com/Dstack-TEE/dstack/pull/38)
- Extract dependencies to workspace level by @kvinwang
- Use universe version for all Rust crates by @kvinwang
- Merge pull request #36 from Leechael/feat-sdk-and-quote by @kvinwang in [#36](https://github.com/Dstack-TEE/dstack/pull/36)
- Update js sdk by @Leechael
- Update python sdk by @Leechael
- Copy sdk codes from tappd-simulator by @Leechael
- Merge pull request #37 from Dstack-TEE/nanometerzhu-readme-mkisofs by @kvinwang in [#37](https://github.com/Dstack-TEE/dstack/pull/37)
- Mkisofs is also essential by @nanometerzhu
- Add app version header by @kvinwang
- Fix cid already in use by @kvinwang
- Merge pull request #33 from Leechael/feat-apis by @kvinwang in [#33](https://github.com/Dstack-TEE/dstack/pull/33)
- Merge remote-tracking branch 'origin/master' into mrg-master by @kvinwang
- Comment on the resize disk size behavior by @Leechael
- Merge pull request #35 from Dstack-TEE/raw-report-data by @kvinwang in [#35](https://github.com/Dstack-TEE/dstack/pull/35)
- Default to sha512 by @kvinwang
- Support for chosing hash for quote by @kvinwang
- Log by @kvinwang
- Use abspath for supervisor bin by @kvinwang
- Merge pull request #34 from Dstack-TEE/supervisor by @kvinwang in [#34](https://github.com/Dstack-TEE/dstack/pull/34)
- Rm comment by @kvinwang
- Update tests by @kvinwang
- Rename by @kvinwang
- Fix a deadlock by @kvinwang
- Fix the broken default log level by @kvinwang
- Extract process management to a standalone process by @kvinwang
- Add probe based client creation by @kvinwang
- Add client lib by @kvinwang
- Support for redirect log file by @kvinwang
- Expose some process structs by @kvinwang
- Support daemonize self and --pid-file by @kvinwang
- Add config and cmd args by @kvinwang
- Update rocket-apitoken by @kvinwang
- Merge pull request #31 from Dstack-TEE/teepod-auth by @kvinwang in [#31](https://github.com/Dstack-TEE/dstack/pull/31)
- Support for bearer auth by @kvinwang
- Fix Upgrade failure by @kvinwang
- Show qemu log in serial.log by @kvinwang
- Disable buffering for nginx by @kvinwang
- Extract cc-eventlog as a crate by @kvinwang
- Fix reboot issue for no-fde instance by @kvinwang
- Merge pull request #30 from Dstack-TEE/opt-fde by @kvinwang in [#30](https://github.com/Dstack-TEE/dstack/pull/30)
- Support for opt-out disck encryption by @kvinwang
- Merge pull request #29 from Dstack-TEE/docker-login by @kvinwang in [#29](https://github.com/Dstack-TEE/dstack/pull/29)
- Merge pull request #28 from Dstack-TEE/up-rustls by @kvinwang in [#28](https://github.com/Dstack-TEE/dstack/pull/28)
- Update rustls to 0.23.19 by @kvinwang
- Fix console crash if vm files are removed by @kvinwang
- No ca cert if kms is disabled by @kvinwang
- Custom event type by @kvinwang in [#27](https://github.com/Dstack-TEE/dstack/pull/27)
- Show event log in tappd dashboard by @kvinwang
- Define RTMR3 digest format by @kvinwang
- Update dcap-qvl to 0.1.6 by @kvinwang
- Prpc returns non Result by @kvinwang
- Better event log format by @kvinwang
- Merge pull request #26 from Dstack-TEE/tboot-rs by @kvinwang in [#26](https://github.com/Dstack-TEE/dstack/pull/26)
- Fix tproxy crash by @kvinwang
- Minor rename by @kvinwang
- Configurable dir for tboot by @kvinwang
- Use Rust client instead of curl by @kvinwang
- Update prpc to 0.3 by @kvinwang
- Fix qemu net args by @kvinwang
- Fix pubkey update issue after instance reboot by @kvinwang
- Cargo fmt by @kvinwang
- Merge pull request #25 from Dstack-TEE/tboot-rs by @kvinwang in [#25](https://github.com/Dstack-TEE/dstack/pull/25)
- Rewrite tboot.sh in Rust by @kvinwang
- Merge pull request #24 from Dstack-TEE/tproxy-update-pubkey by @kvinwang in [#24](https://github.com/Dstack-TEE/dstack/pull/24)
- Reject register without pubkey by @kvinwang
- Don't allocate new ip for rebooted instance by @kvinwang
- Merge pull request #23 from Dstack-TEE/tproxy-loadbalance by @kvinwang in [#23](https://github.com/Dstack-TEE/dstack/pull/23)
- Load balance by @kvinwang
- Merge pull request #22 from Dstack-TEE/tproxy-persistent by @kvinwang in [#22](https://github.com/Dstack-TEE/dstack/pull/22)
- Show latest handshake by @kvinwang
- Save/Load state by @kvinwang
- Merge pull request #21 from Dstack-TEE/recycle by @kvinwang in [#21](https://github.com/Dstack-TEE/dstack/pull/21)
- Recycle stale instances by @kvinwang
- Merge pull request #19 from Dstack-TEE/custom-net by @kvinwang in [#19](https://github.com/Dstack-TEE/dstack/pull/19)
- Support for custom netdev by @kvinwang
- Merge pull request #18 from Dstack-TEE/sec-env by @kvinwang in [#18](https://github.com/Dstack-TEE/dstack/pull/18)
- Derive for env encrypt key by @kvinwang
- Break on io error by @kvinwang
- Merge pull request #17 from Dstack-TEE/rm-build-sh by @kvinwang in [#17](https://github.com/Dstack-TEE/dstack/pull/17)
- Move build.sh to repo meta-dstack by @kvinwang
- Merge pull request #16 from Dstack-TEE/tailf by @kvinwang in [#16](https://github.com/Dstack-TEE/dstack/pull/16)
- Workaround for client disconnect issue for logs by @kvinwang
- Use tailf instead of linemux for log tailling by @kvinwang
- Move some basefiles from meta-dstack to this repo by @kvinwang
- Bump version to dstack-0.2.0 by @kvinwang
- Merge pull request #15 from Dstack-TEE/teepod-show-detail by @kvinwang in [#15](https://github.com/Dstack-TEE/dstack/pull/15)
- Show vm instance detail information by @kvinwang
- Merge pull request #14 from Dstack-TEE/no-kms by @kvinwang in [#14](https://github.com/Dstack-TEE/dstack/pull/14)
- Merge pull request #13 from Dstack-TEE/port_map by @kvinwang in [#13](https://github.com/Dstack-TEE/dstack/pull/13)
- Support for mapping host port to CVM by @kvinwang
- Merge pull request #12 from Dstack-TEE/rm-mkguest by @kvinwang in [#12](https://github.com/Dstack-TEE/dstack/pull/12)
- Fix compilation error by @kvinwang
- Merge pull request #9 from Dstack-TEE/py-tappd by @kvinwang in [#9](https://github.com/Dstack-TEE/dstack/pull/9)
- Support for setting alt names in derive_key by @kvinwang
- Add fn derive_key by @kvinwang
- Update README by @kvinwang
- Merge pull request #8 from Dstack-TEE/ccel by @kvinwang in [#8](https://github.com/Dstack-TEE/dstack/pull/8)
- Handle eventlogs by @kvinwang
- Support for parsing CCEL logs by @kvinwang
- Set default PCCS URL to PCS by @kvinwang
- Update dcap-qvl by @kvinwang
- Merge pull request #7 from Dstack-TEE/ratls-verify by @kvinwang in [#7](https://github.com/Dstack-TEE/dstack/pull/7)
- Add subcommand rand by @kvinwang
- Auto refresh by @kvinwang
- Merge pull request #6 from Dstack-TEE/instance-id by @kvinwang in [#6](https://github.com/Dstack-TEE/dstack/pull/6)
- Update README for address by instance id and passthrough by @kvinwang
- Use instance url instead of app url for dashboard by @kvinwang
- Merge pull request #5 from Dstack-TEE/passthrough by @kvinwang in [#5](https://github.com/Dstack-TEE/dstack/pull/5)
- Better base domain striping from SNI by @kvinwang
- Fix IPs in build.sh by @kvinwang
- Merge pull request #4 from Dstack-TEE/define-report-data by @kvinwang in [#4](https://github.com/Dstack-TEE/dstack/pull/4)
- Define quote report_data format and check the cert pubkey by @kvinwang
- Remove app id preview by @kvinwang
- Merge pull request #3 from Dstack-TEE/app-compose by @kvinwang in [#3](https://github.com/Dstack-TEE/dstack/pull/3)
- Switch to App compose format by @kvinwang
- Turn deploy into dialog by @kvinwang
- Check config by @kvinwang
- Better error message by @kvinwang
- Merge pull request #2 from Dstack-TEE/upgrade-app by @kvinwang in [#2](https://github.com/Dstack-TEE/dstack/pull/2)
- Support for App Upgrade by @kvinwang
- Store issued certs to fs by @kvinwang
- Merge pull request #1 from Dstack-TEE/contributors by @kvinwang in [#1](https://github.com/Dstack-TEE/dstack/pull/1)
- Update repo URL by @kvinwang
- Update README.md by @kvinwang
- Remove rproxy and implement our own by @kvinwang
- Fix md syntax by @kvinwang
- Update Cargo.lock by @kvinwang
- Update README.md by @kvinwang
- Fix utf8 decoding error in log by @kvinwang
- Default to show 1 hour logs by @kvinwang
- Implement TLS passthrough by @kvinwang
- Move deployed containers up by @kvinwang
- Optimiza tappd dashboard by @kvinwang
- Sort by create time by @kvinwang
- Support for start/remove by @kvinwang
- Support for reloading VMs by @kvinwang
- Modify manifest when stop vm by @kvinwang
- Use vm name and image name by @kvinwang
- Pretify console.html by @kvinwang
- Add link to tproxy by @kvinwang
- Support for bare log lines by @kvinwang
- Fix cvm log lines by @kvinwang
- Default to use dstack-0.1.0-dev by @kvinwang
- Add CID pool by @kvinwang
- Streaming API for CVM logs by @kvinwang
- Fix v9 mount name by @kvinwang
- Minor log fix by @kvinwang
- Add api to get Docker logs by @kvinwang
- Add subcommand add-caa by @kvinwang
- Don't add wg if exists by @kvinwang
- Better log by @kvinwang
- Soundness CAA setting by @kvinwang
- Support for adding CAA by @kvinwang
- Refine logs by @kvinwang
- Report error when CT log missing by @kvinwang
- CT log support for tproxy by @kvinwang
- Minor rename by @kvinwang
- Minor refactor by @kvinwang
- Use fs_err by @kvinwang
- Add auto renew feature by @kvinwang
- Add some doc comments by @kvinwang
- Adapt yocto by @kvinwang
- Make tdx-guest compatible with kernel 6.6 by @kvinwang
- Make mod tdx-guest compatible with yocto by @kvinwang
- Move tdx-guest src to root by @kvinwang
- Use syncconf instead of setconf by @kvinwang
- Use rinja for tproxy page by @kvinwang
- Use rinja instead of minijinja by @kvinwang
- Fix tests by @kvinwang
- Simplify the config file format by @kvinwang
- Minor rename by @kvinwang
- Mod default build config values by @kvinwang
- Minor HTML label change by @kvinwang
- Truncate rootfs hash to 64 by @kvinwang
- Better permission require in prepare_env.sh by @kvinwang
- Turn /tapp/config to /tapp by @kvinwang
- Show containers in Tappd by @kvinwang
- Fix invalid url by @kvinwang
- Fix incomplate build.sh by @kvinwang
- Fix empty attestation in CaCert by @kvinwang
- Enable ssh passwd login by @kvinwang
- Fix run scripts by @kvinwang
- Portmap for tproxy by @kvinwang
- Move the rpc crates into it's main crate by @kvinwang
- Use rproxy as a library by @kvinwang
- Change default config for kms by @kvinwang
- Teepod can run CVMs now by @kvinwang
- Add rpc List by @kvinwang
- Reconfig wg and proxy on startup by @kvinwang
- Truncate app id to 40 chars by @kvinwang
- Fix wg config issues by @kvinwang
- Optimize makefile by @kvinwang
- Fix a warning by @kvinwang
- Update ubuntu to 20240911 by @kvinwang
- Initramfs works now by @kvinwang
- Update kmfs by @kvinwang
- Update README.md by @kvinwang
- Refactor initrd by @kvinwang
- Create certgen by @kvinwang
- Implement derive key by @kvinwang
- Fix wg & rproxy config issues by @kvinwang
- Gen cert signed by ca file by @kvinwang
- Record empty app-id in MR by @kvinwang
- Fix panic in gen-ra-cert by @kvinwang
- Remvoe ifname from config by @kvinwang
- Use wg-quick to config wg interface by @kvinwang
- Exclude self-ip from the client pool by @kvinwang
- Add tests by @kvinwang
- Add EventLog by @kvinwang
- Better logs display by @kvinwang
- Fix mutlpile instance start failure by @kvinwang
- Fix initramfs hooks by @kvinwang
- Implement vm deployment by @kvinwang
- Port teepod to prpc by @kvinwang
- Add rpc TdxQuote by @kvinwang
- Implement rpc DeriveKey for tappd by @kvinwang
- Implement kdf for rcgen::KeyPair by @kvinwang
- Load app key by @kvinwang
- Use fs-err for better error message by @kvinwang
- Minor rename by @kvinwang
- Refactor kms-rpc file structure by @kvinwang
- Add --get-ra-cert by @kvinwang
- Implement RA RPC by @kvinwang
- Add Attestation extractor by @kvinwang

### Removed
- Remove a todo comment by @kvinwang
- Remove ubuntu-based image making by @kvinwang
- Remove app_info from cert by @kvinwang
- Remove deps on openssl by @kvinwang
- Remove the account_id workaround by @kvinwang
- Remove error in build.sh by @kvinwang
- Remove unused code by @kvinwang
- Remove certs dir by @kvinwang

## New Contributors
* @Leechael made their first contribution
* @nanometerzhu made their first contribution
* @h4x3rotab made their first contribution
[unreleased]: https://github.com/Dstack-TEE/dstack/compare/v0.5.5..HEAD
[0.5.5]: https://github.com/Dstack-TEE/dstack/compare/v0.5.4..v0.5.5
[0.5.4]: https://github.com/Dstack-TEE/dstack/compare/v0.5.3..v0.5.4
[0.5.3]: https://github.com/Dstack-TEE/dstack/compare/v0.5.2..v0.5.3
[0.5.2]: https://github.com/Dstack-TEE/dstack/compare/v0.5.1..v0.5.2
[0.5.1]: https://github.com/Dstack-TEE/dstack/compare/v0.5.0..v0.5.1
[0.5.0]: https://github.com/Dstack-TEE/dstack/compare/v0.4.2..v0.5.0
[0.4.2]: https://github.com/Dstack-TEE/dstack/compare/dev-v0.4.0.0..v0.4.2
[dev-v0.4.0.0]: https://github.com/Dstack-TEE/dstack/compare/v0.3.4..dev-v0.4.0.0
[0.3.4]: https://github.com/Dstack-TEE/dstack/compare/v0.3.4-beta..v0.3.4
[0.3.4-beta]: https://github.com/Dstack-TEE/dstack/compare/v0.3.3..v0.3.4-beta
[0.3.3]: https://github.com/Dstack-TEE/dstack/compare/v0.3.2..v0.3.3
[0.3.2]: https://github.com/Dstack-TEE/dstack/compare/v0.3.1..v0.3.2

<!-- generated by git-cliff -->
