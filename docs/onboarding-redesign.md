# dstack onboarding redesign

**Status:** design / planning (no implementation yet)
**Tracking issue:** [#699](https://github.com/Dstack-TEE/dstack/issues/699)
**Scope:** cut "time to first dstack app" from ~22 manual steps to a single command, for a self-hoster on their own TDX+SGX host.

This document is the canonical design. The issue tracks task status; this file explains the *why* and the *shape*.

---

## 1. Problem

Following the deployment guide end-to-end today takes roughly **22 ordered steps across two repos** before a `docker-compose.yaml` is reachable in a browser. The sharp edges:

- A chicken-and-egg dance with the KMS `mrAggregated` allowlist on first bootstrap.
- Three deploy scripts that use the "exit 1, edit the `.env`, run me again" pattern.
- "Copy-paste this hash, then type `y`" gates that the script could do itself.
- Three foreground processes, no systemd, manual restarts after config edits.
- A domain + DNS + ACME token required even to see the dashboard.
- `vmm.toml` URLs read only at startup, so bring-up means edit → restart → deploy → edit → restart.

## 2. Goals & non-goals

**Goals**
- One command to stand up the host stack; one command to deploy an app.
- No domain, no DNS, no ACME for the first app.
- The full security model still applies: real TDX attestation, KMS in a CVM, real per-app key derivation.
- Smooth on a server that already has another instance/workload running.

**Non-goals (for the quickstart path)**
- Running on hosts without SGX (we fail fast — see §6).
- Multi-node KMS replication (single-node only; replication stays an advanced topic).
- On-chain governance for the first run (`auth-eth` is the documented upgrade).

## 3. Principles

- If it can be done in one script run, don't ask for two.
- If config can be generated, don't ask the user to write it.
- Pull prebuilt, reproducible artifacts; don't compile from source on first boot.
- Default to the simplest, most secure access path; make exposure opt-in.

## 4. Two-tier onboarding

**Tier 1 — first app (default).** `vmm` + single-node KMS (in a CVM) + your app, reachable via a **direct host:port** mapping. No gateway, no domain, no DNS, no ACME. This is the headline quickstart.

**Tier 2 — managed HTTPS + routing (opt-in, separate).** Set up the gateway when you want `https://<id>-<port>.<domain>` URLs, automatic Let's Encrypt certs, and load-balanced routing. All the domain/DNS/ACME complexity lives here, so Tier 1 never blocks on it.

The single decision that unblocks "deploy without a domain" is making the gateway opt-in: the domain complexity is entirely gateway-side.

## 5. What we validated (on real TDX+SGX hardware)

1. **Hands-off single-node KMS bootstrap works.** With `enforce_self_authorization = false` + a set `auto_bootstrap_domain`, a KMS CVM bootstraps unattended (~30 s): generates its CA + k256 root keys *inside the TEE* and serves `KMS.GetMeta` — no browser, no measurement pre-registration, no manual step.
2. **Necessary but not sufficient — bootstrap needs a genesis quote.** `Keys::generate` → `attest_keys` requires a TDX quote from the guest agent, so a *completed* bootstrap only happens **inside a CVM** (a bare host fails at "Failed to get quote" regardless of the flag). The flag removes the *authorization* round-trip; it does not remove the *attestation* requirement.
3. **The flag does not weaken app security.** App boot still goes through `bootAuth/app` (compose-hash allowlist), and `GetAppKey`/`SignCert` still verify each app's own TDX quote. The `mrAggregated` allowlist only does real work for KMS→KMS replication, which single-node never hits.
4. **Coexistence on a busy server is fine** — a new KMS CVM came up alongside an existing VM without disturbing it (CID auto-allocated by scanning live VMs). Friction surfaced: manual host-port selection, undefined image source on a clean box, and two-VMM contention (see §7.3 — the answer is to attach to the one VMM, not spawn a second).
5. **Browser secure-context constraint.** The web deploy UI uses `crypto.subtle` (AES-256-GCM for env encryption, SHA-256 for the compose hash), which is gated to secure contexts. Verified in a real browser: plain HTTP on a non-loopback IP **breaks** it; **`http://localhost` (loopback) works** (secure context); self-signed HTTPS after clicking through the warning **works**. The Rust `dstack run` path encrypts natively and never touches `crypto.subtle`.
6. **Prebuilt, reproducible images already exist.** `dstacktee/dstack-kms` (+ `-gateway`, `-verifier`) on Docker Hub, versioned tags, built with `SOURCE_DATE_EPOCH` + pinned `DSTACK_REV` and a build-provenance attestation pushed to the registry — so the published digest is independently rebuildable from source.

## 6. Decisions (locked)

| # | Decision |
|---|----------|
| Two-tier | KMS-first (mandatory for the real experience); gateway is an opt-in Tier-2 step. |
| Hardware | **SGX required.** `dstackup install` refuses on non-SGX hosts with a clear message; no silent degrade to host-mode KMS. |
| TLS / access | **Dashboard binds `localhost` by default** (secure context over plain HTTP via SSH tunnel / on-box → no cert needed). `--expose <ip>` is the opt-in that binds the IP and mints a self-signed cert (SAN = that IP). Real-domain certs only in Tier 2. |
| Process / packaging | **systemd-native**, installed as an OS package (deb first, rpm next). The package owns install/uninstall (`apt remove`); `dstackup` does deployment bring-up/teardown. |
| CLI shape | **Two binaries** (see §7.1): `dstackup` (host setup, local + privileged) and `dstack` (client, local or remote). `dstack init` = scaffold an app project. |
| Image source | **Pull the prebuilt, pinned, reproducible images** from Docker Hub — not the dev build-from-source compose. Keep the pin current (the in-repo `deploy-to-vmm.sh` digest is stale at 0.5.5 vs latest 0.5.11). |
| Auth backend (Tier 1) | **Reimplement the simple JSON-allowlist webhook in Rust** (drop the `bun`-based `auth-simple`). Webhook → compose-hash allowlist + `enforce_self_authorization = false`. `auth-eth` (on-chain) stays the documented upgrade. |
| Teardown | `dstackup destroy`/`reset` keeps KMS keys by default (re-init against the same identity); `--purge` wipes everything. |
| vmm-cli.py | Wrap-then-deprecate — keep it working during a deprecation window while `dstack` supersedes it. |
| meta-dstack | Keep the two repos separate for now; may merge host artifacts into the package later. |

## 7. Architecture

### 7.1 Binaries & command taxonomy

Precedent: kubeadm/kubectl, rustup/cargo — a privileged setup tool vs an everyday client.

**`dstackup`** — host setup & lifecycle. **Local + privileged only** (touches `/dev/sgx`, systemd, local files, the local `vmm.sock`).
- `dstackup install` — the bring-up pipeline (§7.3). Idempotent.
- `dstackup status` — health of the host stack.
- `dstackup destroy [--purge]` — teardown.
- `--expose <ip>` — opt-in network exposure of the dashboard (mints a self-signed cert).

**`dstack`** — the client. **Local or remote** (defaults to the local `vmm.sock`; `--host <url> --token <t>` for a remote VMM over TLS).
- `dstack run <compose>` — deploy an app (§7.4).
- `dstack ls` / `logs` / `info` / `upgrade` — day-to-day ops.
- `dstack init` — scaffold a new app project (`app-compose.yaml` + `.env` template). The conventional meaning of `init`.

### 7.2 Local vs remote

- **Setup commands** (`dstackup *`) are local-only and privileged.
- **Client commands** (`dstack *`) work locally (unix socket) or against a remote VMM (TLS + token, using the VMM's existing `[auth] tokens`).

### 7.3 `dstackup install` pipeline

Talks to the VMM's existing `Vmm` prpc service over `vmm.sock` (reusing the `ra-rpc` client + the `vmm-rpc` proto crate — not a rewrite). Phases:

0. **Preflight** — SGX gate (refuse on non-SGX); detect the primary routable host IP; **detect an existing VMM and attach to it** (the fix for two-VMM contention) rather than spawning a second. CID allocation is already VMM-managed.
1. **Render configs** — `vmm.toml`, `kms.toml`, `auth-allowlist.json`. Dashboard bound to `localhost` by default; `--expose <ip>` mints a self-signed cert (`ra-tls` `CertRequest`, SAN = the IP) and enables `[tls]` on the dashboard listener.
2. **systemd units** — `dstack-vmm`, `dstack-auth` (the Rust webhook), `dstack-key-provider` (Gramine), with `After=`/`Requires=` ordering.
3. **Gramine key-provider** — write `sgx_default_qcnl.conf`, bind `0.0.0.0:3443`, `docker compose up -d`, poll `:3443` until healthy. (Automates the three manual gates in the current tutorial.)
4. **KMS-in-CVM bootstrap** — deploy the KMS CVM from the **pinned published image** with `enforce_self_authorization = false` + `auto_bootstrap_domain = <host-ip>`; **auto-pick free host ports** (the VMM does not auto-allocate host ports — `dstackup` bind-tests and assigns them); poll `KMS.GetMeta` for readiness; wire `kms_urls` **per-deploy via the RPC (no VMM restart)**.
5. **Report** — print the dashboard URL and KMS-ready confirmation.

Each phase checks state first and resumes; re-running converges.

### 7.4 `dstack run`

Wraps compose + register + deploy into one step: compute the compose hash (`Vmm.GetComposeHash`), add it to the auth allowlist, **encrypt env vars natively in Rust** (no browser `crypto.subtle`), `Vmm.CreateVm` with an auto-allocated host port, and report `http://<host>:<port>`. This retires the "edit `.env`, re-run" and "copy the hash, type `y`" dances; the deploy scripts fold into subcommands.

### 7.5 Auth webhook (Rust)

A small host service (`dstack-auth.service`) reimplementing the `auth-simple` JSON-allowlist webhook in Rust: `bootAuth/app` checks the app's compose hash against an allowlist; `bootAuth/kms` is unused for single-node (KMS self-bootstrap is hands-off via `enforce_self_authorization = false`). Reachable from CVMs at `10.0.2.2:<port>` under user-mode networking. Removes the `bun` runtime dependency.

### 7.6 Dashboard access model

- **Default:** `http://localhost:9080` via SSH tunnel or on-box — a secure context, so the browser deploy UI's `crypto.subtle` works with no TLS and no cert.
- **Opt-in:** `dstackup install --expose <ip>` binds the IP and serves self-signed HTTPS (click-through); the cert SAN matches the IP exactly, so the optional "install the CA to silence the warning" path also works.
- The `dstack run` CLI path is unaffected either way (native crypto).

## 8. Directory / crate structure

The workspace has ~40 crates, mostly at the repo root. **Decision: introduce a single `crates/` directory and move all Rust crates into it** (libraries *and* binaries together), preserving each component's nesting.

We deliberately do **not** split libraries vs binaries into separate top-level dirs (`crates/` vs `bin/`): the repo already keeps each component's binary and its library together and splits them at the *sub-crate* level — `kms` (bin) + `kms/rpc` (lib), `vmm` + `vmm/rpc`, `gateway` + `gateway/rpc`, `supervisor` + `supervisor/client`, `dstack-mr` (lib) + `dstack-mr/cli` (bin). A top-level lib/bin split would scatter those pairs across two trees and has no clean home for crates that are both. Binaries are identified by their `[[bin]]` targets / `cargo run -p`, not by directory.

Target layout (existing components keep their shape, just relocated):

```
crates/
  vmm/   vmm/rpc/          # (and the rest of the current root crates, moved as-is)
  kms/   kms/rpc/
  gateway/ gateway/rpc/
  ...
  dstack-cli/              # NEW: client crate (binary: `dstack`)
  dstackup/                # NEW: setup binary   -> `dstackup`
  dstack-cli-core/         # NEW: shared lib for the two CLIs (vmm prpc client, config render, port alloc)
  dstack-auth/             # NEW: Rust JSON-allowlist webhook (binary: `dstack-auth`)
```

`sdk/` keeps its own grouping (it spans Rust + JS + Python + Go); only its Rust members relocate if/when convenient.

**Migration is cheap mechanically, expensive to coordinate.** In-repo the fixups are concentrated: the root `Cargo.toml` (`members` + the 28 `path = "..."` entries in `[workspace.dependencies]`), exactly **one** inter-crate `../` path dep (survives a together-move), and **4** CI workflow files (`kms-release`, `gateway-release`, `docker-build-check`, `vmm-ui`). `include_str!`/fixtures are all within-crate and unaffected. `git mv` preserves history. The real cost is coordination — the reproducible image build contexts (`kms/dstack-app/builder`, `gateway/dstack-app/builder`), the separate **meta-dstack** repo, and conflicts with every open PR.

**Sequencing:** the new onboarding crates go into `crates/` from day one (so the root never grows). The bulk move of the existing 40 crates is done **atomically in its own dedicated PR** (not in the onboarding branch), timed for a low-PR window and coordinated with CI / reproducible-builds / meta-dstack.

Changes to existing crates (no new root crates):
- `vmm/` — bind the dashboard to `localhost` by default; add an opt-in `[tls]` path for `--expose` (self-signed cert via `ra-tls`).

## 9. KMS modes — quickstart target

Three independent axes get conflated in the docs:

- **Boot mode:** Non-KMS (ephemeral) / Local-Key-Provider (SGX-sealed, how the KMS itself runs) / **KMS Mode** (deterministic per-app keys, upgradeable — what apps should run in).
- **Auth backend:** auth-mock (demo) / **auth-simple-style allowlist** (single-operator — our Rust webhook) / auth-eth (on-chain upgrade).
- **Where the KMS runs:** host (no real attestation) / **in a CVM with Gramine** (real TDX attestation).

**Quickstart target:** KMS Mode (apps) + KMS-in-CVM-with-Gramine + the Rust allowlist webhook. Full security story minus the blockchain.

## 10. Implementation roadmap

Dependency-ordered; the critical path to Tier 1 is 1–6. Status tracked in [#699](https://github.com/Dstack-TEE/dstack/issues/699).

1. **Hands-off single-node KMS bootstrap** — ✅ validated on hardware (§5).
2. **systemd units** (`dstack-vmm`, `dstack-auth`, `dstack-key-provider`).
3. **Gramine key-provider bring-up automation.**
4. **CLI crates + prpc client** — `dstack` (client) + `dstackup` (setup); ship read-only `dstack ls`/`logs` first.
5. **`dstackup install`** — the §7.3 pipeline.
6. **`dstack run`** — §7.4.
7. **`dstackup destroy`/`reset`** — teardown (keep keys + `--purge`).
8. **OS package** (deb first, rpm next).
9. **Tier-2 `dstack gateway` (opt-in).**
10. **Docs: two-tier quickstart rewrite.**

## 11. Open questions

- Cross-CVM KMS reachability under user-mode networking: `kms_urls` must use the guest-visible host address (`10.0.2.2:<port>`), not `127.0.0.1` — nail down during #5.
- Behavior when a *foreign* (non-dstack) VMM already owns `vmm.sock`/ports: adopt vs warn-and-abort.
- Auth webhook home (`kms/auth-rs` crate vs `dstackup` subcommand) and `cli/core` timing (see §8).
