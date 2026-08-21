# Coding Taste Guide

Conventions and design taste for contributing code and PRs to dstack. The first half is
distilled from the project's code-review history and security-advisory responses — PR
numbers reference the real discussions where each rule was set. The second half — project
structure, design patterns, readability — is distilled from the codebase itself, with file
references pointing at canonical examples. When in doubt, read the cited example.

The short version: dstack review optimizes for **small maintainable surface area, backward
compatibility, security reasoned from the threat model, and claims backed by evidence**.
Speculative complexity gets rejected; pragmatic imperfection is accepted when the risk is
quantified and bounded.

## API and interface design

- **Use builder patterns for argument lists that will grow.** A function taking positional
  bools (`get_tls_key(None, None, true, true, true)`) breaks every caller when a parameter
  is added and is unreadable at the call site. Use a config struct with `bon::Builder`
  and defaults, so adding a field is non-breaking (#161 has the full rationale).
- **Prefer generics over dynamic typing.** `send_rpc_request<S: Serialize, D: DeserializeOwned>`
  instead of passing `serde_json::Value` around (#161).
- **Use `anyhow::Error`, not `Box<dyn Error>`** (#161).
- **Every new API endpoint is a liability** — another path to audit, keep in sync with policy
  changes, and reason about in security reviews. Converge on one model instead of forking
  parallel paths (a separate `GetAppKeyAmd` was rejected on these grounds, #630). When an
  existing API is the wrong shape, add a purpose-built one rather than overloading a return
  value (`is_app_allowed` returning policy → add `auth_api.get_app_policy` instead, #538).
- **Names must say what the thing does.** `GetQuote` for an app key → `GetAttestationForAppKey`
  (#360). An RPC named `ComposeHash` that returns an `app_id` is wrong (#181).
- **Avoid enums in protobuf APIs** that surface as JSON — proto has no way to express
  snake_case serde renaming, so use strings (#241).
- **SDK parity is mandatory.** A new guest-agent API means updating the Rust, Python, Go,
  and JS SDKs. A `Sign()` needs a `Verify()` counterpart (#360). Keep names and semantics
  consistent across language implementations — renaming the `dstack-sdk` crate was rejected
  for exactly this reason (#161, #272).

## Backward compatibility

This is close to absolute. Assume any observable behavior is load-bearing.

- **Never change key derivation, hashes, or measurements** without a migration story.
  Cryptographic-hygiene improvements (domain-separated KDF contexts, salt changes) have
  been rejected because they'd silently change all derived keys in existing deployments
  (see the responses in #605, #552). Compatibility special cases are acceptable — all-zero
  `mr_config_id` means "unset" to avoid breaking old quotes (#559).
- **Pin encodings that feed key derivation.** When a derived secret depended on a library's
  DER serialization, the fix was a fixed, dstack-defined layout plus a regression test
  proving old and new outputs are identical (#553 → #603).
- **Wire formats and URL schemes are frozen.** `*-8080-h2` was rejected as breaking;
  keep deprecated aliases (`TappdClient`) alongside new clients (#292, #306).
- **New endpoints ship behind a config gate**, so operators opt in and existing deployments
  are unaffected (metrics endpoint in #657).

## Security reasoning

Argue from dstack's threat model, not from generic best practices.

- **Attestation is the trust boundary — not TLS, not the network, not URLs.** Endpoints
  (KMS URL, PCCS, registry) are untrusted transport; the remote party's identity is verified
  cryptographically (RA-TLS quote verification, Intel signatures, image digests). Proposals
  to "measure the URL" or pin transport add no security and reduce flexibility (#615, #616).
- **Runtime config measured into RTMRs beats compile-time cargo features.** Features are
  additive and invisible at runtime; a measured config flag is auditable by any verifier.
  This is the project's standard response to `#[cfg(feature = "dev-mode")]`-style gating
  proposals (#608, #609).
- **The CVM is single-tenant.** All containers in a CVM share one trust domain; file
  permissions between them are not a security boundary. Don't add intra-CVM isolation
  machinery (#606, #617).
- **Fail closed on unknown variants.** A Go `switch` on a string type without a `default`
  silently passes validation for new types — Rust exhaustive `match` is the model; in other
  languages, add the explicit error case (#512).
- **Validate early with explicit checks.** Constraints enforced implicitly deep in the stack
  (a `try_into::<[u8; 20]>()`) should also be checked explicitly at the entry point with a
  clear error (#554 → #604).
- **Cheap, bounded hardening is always welcome** even when no realistic attack exists:
  0600 file permissions, a 16 KiB cap on decompressed cert extensions, `MAX_LEN` bounds on
  length-prefixed decoding, path normalization before deletion (#557, #566, #567, #558).
  The line: hardening with no downside → yes; complexity for a hypothetical attacker who
  already breached the trust boundary → no.
- **Attestation payloads need content-type discipline.** Prefix `report_data` so external
  verifiers can parse it unambiguously (#360, the `dip1:` proposal in #330). Don't spam
  runtime events — "emitting many events in the application is a disaster for the verifier;
  in most scenarios, you only need report_data" (#273).

## Performance and pragmatism

- **Quantify before adding machinery.** A bounded channel + semaphore was rejected because
  the computed worst case was ~80 KB of memory and tens of tasks: "not adding speculative
  complexity now… easy to add later without API changes" (#361 replies). If you propose a
  limit, pool, or backpressure mechanism, bring the numbers that make it necessary.
- **Never block the hot path.** No blocking commands or syscalls under a lock (`wg show`
  under `ProxyState` — #740); no `reqwest::blocking` inside async contexts spawning nested
  runtimes (#750); reuse clients/resolvers instead of constructing per-connection (#741).
  Snapshot behind `Arc` instead of cloning big maps while holding a lock (#740).
- **Caches are bounded and TTL'd** (moka with size limits, TTL-aware DNS caching; #741, #750).
- **Know your data structures.** Don't linear-scan something that's already a map (#33).
- **Dependencies: judge by maturity and removability, not fashion.** An archived-but-mature
  crate is fine if dropping it later is a one-line change (#207 on jemallocator).

## Code organization

- **Workspace-managed dependencies.** Declare versions in `dstack/Cargo.toml`, reference
  with `foo.workspace = true` (#161, #360).
- **One source of truth.** Shared logic used by two components lives in one crate
  (`dstack-mr::sev` used by both KMS and verifier). Duplicated blocks get extracted —
  contract logic into `_registerApp` (#182), repeated fetch/parse into `http_get`/`http_post`
  helpers that unify error context in one place (#525), shared lookup between `list_vms`
  and `get_vm` (#33). Duplicated magic numbers become constants (#541).
- **Generic mechanics go in small reusable crates; domain logic stays in the service.**
  `TtlCell` owns caching/refresh mechanics; the gateway only defines how to fetch
  WireGuard handshakes (#740).
- **Delete, don't accumulate.** Remove functions that lost their purpose (#538), stray
  `println!` debugging (#525), obsolete Dockerfiles superseded by better infrastructure
  (#311). Avoid `unsafe` when a safe construction exists (#360).
- **Config over hardcoding.** Defaults belong in the embedded base config layer
  (`load_config` figment merge), not scattered in code (#646). Operator-facing values —
  DNS servers, TTLs, ports — are configurable, never hardcoded (#409, #436).

## Errors and logging

- **Lowercase log and error messages** — `bail!("failed to connect to server")`, never
  capitalized (`.cursorrules`, enforced).
- **Errors speak the caller's language.** If the caller passed raw bytes, the size-limit
  error talks about bytes — not the hex-encoded internal representation (#47).
- **Include actionable context, bounded.** URL, status, and response body truncated to
  ~512 bytes so an HTML error page can't blow up the logs (#525).
- **Don't skip silently.** If code ignores malformed input to stay lenient, log a warning —
  silent skips hide corruption (#541).

## Scope and diffs

- **One concern per PR.** Unrelated changes get called out immediately ("It shouldn't be
  in this PR", #301).
- **Never remove existing behavior without saying why** ("Why removing the entire resizing
  logic?", #251).
- **`cargo fmt` and clippy-clean before pushing**; preserve surrounding blank-line structure
  rather than reflowing untouched code (#251).

## Commits and PR descriptions

Commits are **subject-only conventional commits**, one logical change each:
`fix(gateway): reuse app address DNS resolver`, `refactor(snp): split ovmf parsing helpers`,
`test: add SEV-SNP verifier fixture`. Big features arrive as a stack of small,
independently-readable commits (see the #703 follow-up series). Lowercase after the colon.

PR descriptions follow **Problem → Fix**, and the problem section names the root cause,
not just the symptom:

- Lead with what's broken and why, with the failing behavior shown concretely (error
  output, wrong digest, stale tag) — see #722, #723, #654.
- Explain the mechanism: #688 traces a package drift to deb822 sources on trixie bypassing
  the snapshot pin, then fixes the cause instead of bumping pinned versions — "the version
  bumps only paper over a bug".
- **State how you verified it, specifically.** Not "tested locally" but "verified inside
  both `rust:1.92.0` (trixie) and `debian:bookworm`: `apt-get update` only contacts
  `snapshot.debian.org`" (#688), or a full end-to-end deployment table with real endpoints
  and observed client IPs (#361). For infra/measurement changes, capture fixtures from real
  CVMs (#678).
- Use evidence when making performance or behavioral claims: measurements, strace output,
  before/after tables (#410 is the canonical example — IPI counts, futex timing, per-config
  pull times).
- When choosing between designs, show the alternatives and the trade-offs briefly, then
  commit to one (#353's stateful-RPC vs URL-flag comparison).

## Responding to review

- **When you fix it:** reply "Addressed in `<commit>`" plus one sentence on what changed —
  precise enough that the reviewer needn't re-read the diff (#740, #678).
- **When you disagree:** push back with numbered, quantified reasons grounded in the threat
  model or measured behavior, and end with a decision: "Going to leave this as-is" (#361),
  "we do not think the security benefit justifies that operational cost" (#552). Never
  silently ignore a comment.
- **When the reviewer is right:** say so plainly — "Good catch — updated the doc to spell
  out the difference" (#678) — and fix it in the same round.

---

# How the code itself is written

## Tooling constraints (non-negotiable)

- **CI rejects `.unwrap()` and `.expect()` in non-test code**: clippy runs with
  `-D clippy::unwrap_used -D clippy::expect_used` (`.github/workflows/rust.yml`). The house
  replacement for "this cannot fail" is the `or-panic` crate with a terse lowercase reason:
  `self.state.lock().or_panic("mutex poisoned")`. Tests are exempt and unwrap freely.
- **Stock `cargo fmt`** — there is no rustfmt.toml, clippy.toml, or `[workspace.lints]`.
  Toolchain is pinned in `rust-toolchain.toml`.
- **Every source file starts with a 3-line SPDX header** (REUSE-compliant).
- `.cursorrules`: log and error messages start lowercase. The old code is ~50/50 on this;
  new code must follow the rule, but don't mass-fix existing strings in unrelated diffs.

## Project structure

- **One workspace, ~54 crates, every dependency version declared once** in root
  `[workspace.dependencies]` (grouped under comment banners: `# Core dependencies`,
  `# Cryptography/Security`, …) and consumed via `foo.workspace = true`. Internal RPC
  crates live at `<service>/rpc` but are aliased to `dstack-<service>-rpc` package names.
- **Extract a crate when a utility is reusable across binaries, independently publishable,
  or has a distinct dependency footprint — and keep it tiny.** `serde-duration` is 54
  lines; `cached-cell` is one `TtlCell<T>` (263 lines); `load_config` is one function.
  Otherwise stay a module: `ra-tls` keeps cert/kdf/oids as sibling modules. The `dstack-`
  name prefix is reserved for published or product-facing crates.
- **All four services share one bootstrap skeleton**: clap `Args { config: Option<String> }`
  → `load_config` figment layering (Rocket defaults → embedded default TOML via
  `include_str!` → `/etc/<name>/` → cwd → `--config` file) → tracing `EnvFilter` defaulting
  to `info` → `rocket::custom(figment)` mounting `ra_rpc::prpc_routes!` → `anyhow::Result`
  main. Each defines `app_version()` from `CARGO_PKG_VERSION` + `git_version!` and attaches
  an `X-App-Version` response header. Follow this skeleton exactly when adding a service.
- **Module layout**: the core RPC surface lives in `main_service.rs` (or `rpc_service.rs`
  in guest-agent). When a module grows subordinate concerns, promote it to `foo.rs` + a
  `foo/` directory of submodules (`dstack/gateway/src/proxy.rs` + `proxy/{sni,tls_terminate,...}`).
  Core files routinely run 800–1500+ lines before splitting — don't over-fragment into
  many small files.
- **Config conventions**: each service embeds its default TOML (`include_str!`), extracts
  the app config from the `[core]` section, and adding an option means: add a field with
  `#[serde(default)]` (or `default = "default_true"` free fns), then document it with a
  comment in the embedded TOML. Variant config uses `#[serde(tag = "type")]` enums.

## Design patterns

- **Shared state is a `Clone` newtype over `Arc<Inner>` with `Deref`**: `KmsState {
  inner: Arc<KmsStateInner> }`, `Proxy { _inner: Arc<ProxyInner> }`. Immutable-after-boot
  state needs no lock; mutable parts sit behind a std `Mutex` (not tokio, not parking_lot)
  accessed through a `fn lock(&self)` helper that `or_panic`s. Critical sections are
  short and block-scoped — snapshot what you need, drop the guard, then do the work.
- **RPC handler pattern**: a per-request `RpcHandler` struct holds a clone of the state
  plus request auth context (`attestation`, `remote_app_id`). It implements the generated
  `*Rpc` trait (methods take `self` by value, return `anyhow::Result<Resp>`) plus
  `RpcCall<State>::construct`. Method bodies start with `ensure_*` guard calls; the ra-rpc
  layer maps any `Err` to HTTP 400 with the `{err:#}` context chain — handlers never build
  HTTP responses. Multiple handlers over one state model multiple trust surfaces
  (internal/external/admin/guest-api).
- **Builder-config-then-convert**: structs with several optional fields get
  `#[derive(bon::Builder)]` with `#[builder(default = ...)]` field defaults, and a
  conversion to the live object (`RaClientConfig::builder()...build().into_client()`).
  Constructors: `new` for the common case, named alternates (`from_parts`, `load`,
  `new_mtls`) for the rest.
- **Static dispatch over trait objects**: closed sets of implementations are enums —
  hand-rolled (`CertRequestClient::{Local, Kms}`, `KeyProvider::{None,Local,Tpm,Kms}`) or
  via `enum_dispatch` (`Dns01Client`). `dyn` is reserved for user-supplied callbacks
  (`Box<dyn Fn(...) + Send + Sync>`). Traits define a minimal required core and layer
  convenience as default methods (`CertExt`, `Csr`).
- **Wire format ≠ public type**: on-wire layouts get their own mirror structs with a
  `version` field and explicit `From` conversions (`CborTdxOsImageMeasurement`). Formats
  that must evolve are versioned enums (`VersionedAttestation::{V0,V1}`) with sniffing
  decoders and upcast methods. Anything decoded from untrusted input carries an explicit
  size bound (`VecOf<I, T, const MAX_LEN: usize>`, `MAX_ATTESTATION_BYTES`).
- **Serde house rules**: byte fields are hex via `use serde_human_bytes as hex_bytes;` +
  `#[serde(with = "hex_bytes")]`; large blobs are `serde_human_bytes::base64`. Renames keep
  `#[serde(alias = "old_name")]`. New fields use `#[serde(default,
  skip_serializing_if = ...)]` so legacy configs serialize byte-identically. Enums are
  strings with `rename_all = "snake_case"`.
- **Feature flags gate capabilities, not variants**: `quote` threads through the
  attestation stack to separate quote *generation* (needs TDX device) from verification;
  `serde`/`std` are optional on leaf type crates (`no_std_check` compile-guards the SDK
  types). Defaults are what the main binaries need.

## Readability and idioms

- **Import for readability, not minimum path length.** Import specific types and
  frequently repeated operations when their short names remain unambiguous
  (`TcpListener::bind`, `timeout`, `Command::new`). Keep qualifiers that carry useful
  semantic context (`serde_json::from_slice`, `tokio::spawn`, `anyhow::bail!`). Follow
  the surrounding module when either form is equally clear.
- **Errors**: `anyhow` everywhere in services — `thiserror` only in library crates whose
  callers match on error variants. `bail!` inside an `if` is the guard idiom; **`ensure!`
  is never used in this codebase** (0 occurrences) and reads as foreign. `let ... else
  { bail!("...") }` is the standard Option guard. `.context("static string")` by default;
  `.with_context(|| format!(...))` only when interpolating runtime values. Non-fatal
  errors are logged, not propagated: `if let Err(err) = ... { warn!("...: {err:?}") }`.
  The error binding is named `err`, logged as `{err:?}` internally or `{err:#}` when
  surfaced to users. Use `fs_err as fs` instead of `std::fs`.
- **Naming**: validation guards are `ensure_*` returning `Result` and bailing inside
  (`ensure_attested`, `ensure_admin`, `ensure_app_boot_allowed`); conditional actions take
  `_if_needed`/`_if_exists` suffixes (`renew_cert_if_needed`); the common verb prefixes
  are `get_`, `verify_`, `parse_`, `build_`, `derive_`. Descriptive names, minimal
  abbreviation.
- **Functions are 20–40 lines, guard-clause style, shallow nesting.** When a wrapper needs
  cleanup or retry around a `?`-heavy core, split into `foo` + `foo_inner` (`renew_inner`,
  `handle_prpc_impl`). Iterator chains for pure transforms; plain `for` loops when the body
  awaits or side-effects; `match` over if-let chains at 3+ arms.
- **Comments are earned.** They explain threat models, compat rationale, and protocol
  steps — not mechanics: the 20-line doc on `platform_instance_binding()` explaining
  VM-clone identity attacks (`dstack-util/src/system_setup.rs`), numbered step comments in
  ACME flows (`certbot/src/acme_client.rs`). Field-level doc comments on config/wire
  structs explain semantics and compat implications (`dstack-types/src/lib.rs`). TODO is
  rare (4 in the tree); never leave commented-out code.
- **Formatting details**: inline format args for simple identifiers (`bail!("invalid app
  id: {app_id}")`), positional `{}` only for expressions. Derives in the order `Debug,
  Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize`. `pub(crate)` for
  intra-crate visibility (258 uses; `pub(super)` nearly never). Pragmatic `.clone()` of
  `Arc`s/`String`s is normal — don't contort code to avoid a clone off the hot path.
- **`unsafe` is FFI-only** (~15 sites: ioctl/flock/daemon/fd-borrowing). Business logic
  never needs it; if you think it does, redesign (see #360: "avoid unnecessary unsafe").
- **Docs discipline scales with audience**: `ra-tls` enforces `#![deny(missing_docs)]`;
  published crates get READMEs and doctests; internal crates get module-level `//!` docs
  stating the responsibility split (see `cached-cell`).

## Testing

- **Inline `#[cfg(test)] mod tests` is the default**; `tests/` directories only when
  fixtures or integration binaries are involved. Plain `#[test]` preferred; `#[tokio::test]`
  when async is unavoidable.
- **Golden vectors over mocks**: real captured binary fixtures embedded with
  `include_bytes!("../samples/...")`, asserted against inline hex literals or `insta`
  snapshots (`dstack/cc-eventlog`, `dstack/dstack-attest/tests/`). Fixture provenance gets its own
  README (`sev_snp_fixture.README.md`). When changing an encoding, add a regression test
  proving old and new outputs match (#603).
- **Test names are snake_case behavior statements**: `enforces_ttl`,
  `returns_empty_before_first_set`, `http_transport_honors_requested_method`.
