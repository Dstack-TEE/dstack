# Release-candidate testing runbook

What to do, in order, to exercise a dstack release candidate on real TEE
hardware — and the specific things that cost time the last round, so they cost
nothing the next one.

Written after testing 0.6.0-rc0 on an Intel TDX host and an AMD SEV-SNP host.
Assumes fresh machines: nothing here depends on state left behind by that run.

---

## 1. Confirm the host can actually do what you think

Get this wrong and you will scope the whole test around a capability you have,
or skip one you don't.

### Intel TDX host

```bash
cat /sys/module/kvm_intel/parameters/tdx      # expect: Y
grep -o -m1 tdx_host_platform /proc/cpuinfo   # expect: tdx_host_platform
systemctl is-active qgsd pccs                 # expect: active active
```

**`/dev/tdx_guest` does not exist on a TDX host and its absence means nothing.**
That device is the *guest*-side attestation interface; it appears inside a TD,
not on the machine running them. Checking for it will tell you a perfectly good
TDX host has no TDX. Use the KVM module parameter and the CPU flag.

`qgsd` is what turns a TD's attestation request into a signed quote, and `pccs`
caches the Intel collateral used to verify it. Without both, CVMs boot but
cannot obtain keys.

### AMD SEV-SNP host

```bash
cat /sys/module/kvm_amd/parameters/sev_snp    # expect: Y
grep -o -m1 sev_snp /proc/cpuinfo             # expect: sev_snp
ls -l /dev/sev                                # must exist AND be accessible
qemu-system-x86_64 -object help | grep sev-snp-guest
lsmod | grep -E '^vhost_vsock|vmw_vsock_vmci'
```

Three host-level problems each blocked us for a while:

- **`vhost_vsock` not loaded.** The VMM binds its host API on vsock CID 2 and
  fails with `Cannot assign requested address (os error 99)`. Fix: `sudo modprobe
  vhost_vsock`. Does not survive reboot — add `/etc/modules-load.d/` to persist.

- **VMware's vsock transport hijacking the stack.** If `vmw_vsock_vmci_transport`
  is loaded (it often is, by default), it claims the vsock transport and CID 2
  binding still fails even with `vhost_vsock` present. Fix: `sudo modprobe -r
  vmw_vsock_vmci_transport vmw_vmci`. It comes back on reboot — blacklist to
  persist. This one is easy to misdiagnose as a dstack bug.

- **`/dev/sev` is `root:root 0600` out of the box** and your user is probably not
  in `kvm`. QEMU then fails with `Could not access KVM kernel module: Permission
  denied`. Fix: `sudo usermod -aG kvm $USER` and `sudo chown root:kvm /dev/sev &&
  sudo chmod 660 /dev/sev`. The chmod does not survive reboot; a udev rule does.

**After fixing group membership, restart the supervisor.** `dstack-vmm` starts
`supervisor` detached, and a supervisor started before the `usermod` keeps the old
group set. QEMU is forked from it, so it still cannot open `/dev/kvm` even though
your shell can. Symptom: `id` shows `kvm`, QEMU still says permission denied.
Check with `grep ^Groups /proc/$(pgrep -f bin/supervisor)/status`.

### QEMU version

dstack computes measurements against an ACPI compatibility profile keyed on the
QEMU major version (`dstack/crates/qemu-acpi/src/profile.rs`). 8.x, 9.x and 10.x
are all mapped. Check the version resolves to a supported profile *before*
installing anything, or you will build an environment that cannot produce correct
measurements.

---

## 2. Pick your disks deliberately

Check the mount that will actually hold the data, not `/`:

```bash
df -h /home ~/.dstack /var/lib/docker
```

On one host `/` had 12 GB free while `/home` sat on a 7 TB array. Looking only at
`/` produced a wrong "we are too tight on disk to use the documented `--disk 50G`"
conclusion and a plan built around shrinking things unnecessarily.

Keep the VMM's `run_path`, `temp_dir` and the image directory on the large
volume. CVM disks and temp files land there, and `/tmp` on a small root
filesystem will fill up mid-test.

---

## 3. Two traps that can reach outside the test

**`~/.dstack-vmm/config.json` may point `vmm-cli.py` at a production VMM.** It is
the CLI's default `--url`. On both machines used last time it pointed at a live
deployment with credentials, so any `deploy` that omitted `--url` would have
landed there. **Pass `--url http://127.0.0.1:<port>` on every single invocation.**

**Component tags publish to Docker Hub.** `kms-v*`, `gateway-v*`, `verifier-v*`
and friends trigger release workflows that push to `${DOCKERHUB_ORG}` and cut
GitHub releases. If you only want images in a private registry, build locally and
push by hand — do not push those tags.

---

## 4. Cutting the release

- Version lives in **four** places with no tool keeping them in sync:
  `dstack/Cargo.toml` (`workspace.package.version`), `os/mkosi/versions.env`
  (`DSTACK_VERSION`), `os/mkosi/mkosi.conf` (`ImageVersion`), and
  `os/yocto/.../dstack.conf` (`DISTRO_VERSION`). Regenerate `Cargo.lock` after.
  Only the first two are cross-checked (by `os/mkosi/tests/acceptance.sh`); the
  Yocto one is checked by nothing.
- **Commit messages must be conventional commits** — `prek.toml` enforces it at
  commit-msg stage. The historical `Bump version to X` style now fails.
- `release/**` branches are protected against **deletion and non-fast-forward**.
  Rebase-and-force will be rejected. Merge instead. This also means the branch
  name is claimed permanently once pushed.
- **The container Dockerfiles clone from GitHub and check out `DSTACK_REV`** —
  they do not use your working tree. Push the commit before building images, or
  you will build something other than what you are testing.
- Pre-run the release job's own validation locally before tagging:

  ```bash
  TAG=mkosi-os-v<version>
  echo "$TAG" | grep -Eq '^mkosi-os-v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$'
  source os/mkosi/versions.env && [ "${TAG#mkosi-os-v}" = "$DSTACK_VERSION" ]
  ```

  The release job also requires `metadata.json`'s `git_revision` to equal the
  tagged commit and rejects a `-modified` suffix, so the tag must sit on the exact
  commit that was built from a clean tree.

---

## 5. Bring-up order

KMS first, then gateway, then the app. Each needs the previous one's identity.

1. **VMM.** Copy `dstack/vmm/vmm.toml` and edit: `address` **and** `port` (the
   `check-config` subcommand requires both at top level), `run_path`, `temp_dir`,
   `[image] path` (it is commented out by default), `platform = "tdx"` or
   `"amd-sev-snp"`, a `cid_start` that avoids running VMs, `[supervisor]` paths,
   and `[cvm.port_mapping]` — **enabled, with a range covering every port you
   intend to map.** A port outside the range fails the deploy with `Port mapping
   is not allowed for tcp:<port>`. Validate with `dstack-vmm -c <cfg>
   check-config` before starting.

2. **KMS as a CVM** with `--local-key-provider` (needs a
   gramine-sealing-key-provider on the host, default `127.0.0.1:3443`). The
   simplest authorization that releases keys without a chain is
   `[core.auth_api] type = "dev"` with `gateway_app_id = "any"` — no extra
   containers, unlike the on-chain compose which needs a Helios light client.
   Keep `[core.image] verify = true`.

3. **Gateway as a CVM** with `--kms`. Internal ports are RPC 8000, admin 8001,
   WireGuard 51820/udp, proxy 443.

4. **App CVM** with `--kms --gateway`.

### Certificate identity across hosts

If CVMs on more than one machine will talk to the KMS, give it a DNS name rather
than an IP. The RPC certificate's only SAN is `auto_bootstrap_domain`, and a
local CVM dialing `10.0.2.2` while a remote one dials the public IP cannot both
match. A wildcard A record covering `kms.<domain>` and `gw.<domain>` solves it in
one step.

### ACME is configured at runtime, not in a file

In 0.6.0 certbot config lives in the gateway's KvStore, reached through the admin
API — `Admin.SetCertbotConfig`, `Admin.CreateDnsCredential`,
`Admin.AddZtDomain`. The `CF_API_TOKEN` and `ACME_STAGING` variables in
`gateway/dstack-app/deploy-to-vmm.sh` are **vestigial and unused**; setting them
does nothing.

**Set `acme_url` to staging explicitly.** The default is Let's Encrypt
*production*, and the rate limits there are unforgiving of a test loop:

```
https://acme-staging-v02.api.letsencrypt.org/directory
```

`AddZtDomain` kicks off issuance asynchronously and takes a lock. A subsequent
explicit `RenewZtDomainCert` returns `{"renewed":false}` immediately while that
is in flight — that is the lock, not a failure. Watch the gateway container log
instead of the return value.

---

## 6. Gateway cluster

Worth doing: it exercises WaveKV replication, which a single node never touches
even though sync is running.

**Sync turns itself on when `NODE_ID > 0`** (`entrypoint.sh`:
`SYNC_ENABLED=$([ "$NODE_ID" -gt 0 ] && ...)`). A single node with `NODE_ID=1` is
therefore already running WaveKV as local storage — you will see `WaveKV:
detected certificate changes` in its log — but nothing has ever replicated. Do
not read those lines as evidence that clustering works.

### Every node must deploy under the same `--name`

Cluster members authenticate each other over RA-TLS and **require the peer's
`app_id` to equal their own** (`gateway/src/kv/https_client.rs`). That is
deliberate: it keeps WaveKV replication inside instances of one authorized
compose rather than letting any CVM join.

`app_id` is the compose hash, and **`name` is part of it**. Deploying a second
node under a different name produces:

```
bootnode discovery retry failed: failed to fetch peers from bootnode
  app_id mismatch: expected c90cc75a6ceb…, got aa04b7bd7875…
```

which looks like a networking or trust problem and is neither. Per-node values —
`NODE_ID`, `WG_IP`, `WG_RESERVED_NET`, `WG_CLIENT_RANGE`, `WG_ENDPOINT`,
`MY_URL`, `BOOTNODE_URL`, `ADMIN_API_TOKEN` — belong in `--env-file`, whose
**values are encrypted at deploy time and are not part of the compose hash**;
only the key names are recorded, as `allowed_envs`.

So: same `--docker-compose`, same `--name`, different `--env-file`. Confirm
before deploying —

```bash
sha256sum node1-app-compose.json node2-app-compose.json   # must match
```

### Allocate per-node resources

WireGuard subnets follow `SUBNET_INDEX`: node *n* gets `10.8.<n*64>.0/18`, so
index 0 is `10.8.0.0/18` and index 1 is `10.8.64.0/18`. Overlapping them breaks
routing in ways that are tedious to unpick. Each node also needs its own RPC,
admin, proxy and WireGuard ports, and its own `MY_URL` hostname — a wildcard A
record covers `gw.<domain>` and `gw2.<domain>` without extra DNS work.

`BOOTNODE_URL` only speeds up discovery; peers are also found through incoming
connections.

### What proves the cluster actually works

Peer lists agreeing is the weakest of the three checks. Do all of them:

```bash
# 1. Both nodes list both peers
curl -H "Authorization: Bearer $TOK" .../prpc/Admin.Status?json | jq '.nodes'

# 2. The app registered on node1 appears on node2 — registration state replicated
curl -H "Authorization: Bearer $TOK2" .../prpc/Admin.Status?json | jq '.hosts'

# 3. node2 serves the wildcard certificate it never requested — cert replicated
echo | openssl s_client -connect 127.0.0.1:<node2-proxy> \
  -servername "<instance>-80.<domain>" | openssl x509 -noout -issuer -subject

# 4. Traffic through node2 reaches an app whose tunnel terminates on node1
curl -k --connect-to "<instance>-80.<domain>:<node2-proxy>:127.0.0.1:<node2-proxy>" \
  "https://<instance>-80.<domain>:<node2-proxy>/"
```

The fourth is the one that matters: it shows what replicated is usable routing
state, not just metadata that happens to agree.

## 7. What to verify, and what each check actually proves

| Check | Why it is worth doing |
|---|---|
| `sha256sum -c sha256sum.txt`, then `sha256(sha256sum.txt) == digest.txt` | Confirms the artifact matches its own manifest |
| `dstack-mr tdx-measurement-cbor <dir> \| cmp - measurement.tdx.cbor` | Confirms the published measurements are *derivable from the image*, not merely asserted |
| Boot all three CVMs to `boot_progress: done` | `done` is only reachable after `GetAppKey` succeeds, so it implies attestation worked |
| `Admin.Status` lists the app with a WireGuard IP | Gateway verified the CVM's RA-TLS quote |
| **A rejected quote in the KMS log** | The one check that proves verification is not a no-op |
| `curl` through the proxy to the app | End to end, but only for one of several proxy modes — see below |
| `/prpc/v1/Info` and `/prpc/Worker.Info` both answer | v1 works and pre-0.6 clients are not broken |
| `dstack-verifier --verify` on a captured attestation, then again on a one-byte-flipped copy | Verification is checked by something other than the KMS, and the crypto is live rather than short-circuited |

That fifth row is the one people skip. A run where every quote is accepted cannot
distinguish "verification passed" from "verification never ran". Last time the
AMD CVMs supplied it for free — 6 grants and 7 rejections in the same KMS log —
but if everything passes, arrange a failure deliberately.

The last row is the cheapest way to arrange one. `dstack-verifier --verify
req.json`, with `req.json` holding `{"attestation": "<hex>"}` captured from
`/v1/Attest`, gives a full result offline. Flip one byte and re-run: a flip
inside the report signature or the launch measurement must come back
`VEK does not sign the attestation report`. Choose the byte deliberately —
flipping into the outer CBOR framing instead fails at decode, which proves only
that the parser works.

### One `curl` does not cover the proxy

Ingress maps as `<id>[-[<port>][s|g]].<base_domain>`, and the suffixes select
genuinely different code paths:

| Suffix | Mode | Path |
|---|---|---|
| none | TLS terminated, forwarded as TCP | the common case |
| `s` | TLS passthrough | `proxy/tls_passthough.rs`, SNI-routed, needs a `_dstack-app-address` TXT record |
| `g` | HTTP/2 with TLS termination | gRPC |

The 0.6.0-rc0 round exercised only the no-suffix path, single-node and then
across a cluster. Passthrough and gRPC were never tried, and neither was anything
beyond a small request — no sustained transfer, long-lived connection or
streaming. If those matter for the release, test them explicitly; a green
no-suffix `curl` says nothing about them.

Passthrough in particular has its own resolution mechanism: the gateway looks up
`_dstack-app-address.<sni>`, falling back to `_dstack-app-address-wildcard.<parent>`,
for a TXT record of the form `<app_id>:<port>`. Seeing a passthrough-resolution
error while testing the *terminated* path usually means the gateway had no
certificate and fell through to SNI routing — fix the certificate, not the DNS.

**`dstack-mr` binary name collision:** `-p dstack-mr` and `-p dstack-mr-cli` both
produce `target/release/dstack-mr` and overwrite each other. Build only
`-p dstack-mr` for `measure-os` / `inspect-measurement` / `*-measurement-cbor`.

**Guest API v1 takes bare method names.** `/prpc/v1/Info`, not
`/prpc/v1/Worker.Info`. The v0 and legacy mounts use `trim: "Worker."`, which
*accepts* the prefixed form; v1 has no trim, so the prefix 404s. A 404 there is
your URL, not a broken agent.

---

## 8. Reading DNS evidence without fooling yourself

Three ways to misread a DNS result, all of which happened:

- **`dig +short` prints nothing for both NODATA and timeout.** Those are the two
  hypotheses you are usually trying to separate. Use full `dig` output and read
  `status:` and the `SERVER:` line.
- **certbot deletes the challenge TXT record after a successful issuance.** Its
  absence later is cleanup, not a network fault.
- **Cloudflare takes longer than ten seconds to serve a new record from its own
  authoritative edge.** An immediate query after creating a record can legitimately
  return nothing.

When testing whether an external service is reachable from an odd vantage point,
**always run the same request against a known-good target through the same path.**
Four public CORS proxies were tried to get an independent view of AMD KDS; every
one returned the identical error for `github.com` as for the target. Without the
control, those errors read as evidence about AMD.

---

## 9. AMD SEV-SNP

An AMD run was completed end to end: guest SEV-SNP attestation, KMS key release,
independent quote verification, gateway registration and public traffic. Host
prerequisites are in section 1; what follows is everything after the host boots.
None of it is guessable from the code.

### 9.1 The settings an AMD run needs

One of these must change or the run cannot succeed; the rest are listed because
their defaults are the ones you want and it is useful to know that before you
start changing things.

| Setting | File | Default | For an AMD run |
|---|---|---|---|
| `[cvm] platform` | `vmm.toml` (host) | `"auto"` | `"auto"` picks SEV-SNP when the host CPU flags contain `sev_snp`; set `"amd-sev-snp"` to be explicit and to fail loudly on the wrong host |
| `sev_snp_key_release` | `kms.toml`, `[core]` | `false` | **`true`**, or no AMD guest ever gets a key |
| `aws_nitro_tpm_key_release` | `kms.toml`, `[core]` | `false` | leave off; listed because it is the only other gate of this shape |
| `[core.attestation.urls] amd_kds` | `kms.toml`, `dstack-verifier.toml` | `https://kdsintf.amd.com/vcek/v1` | override only to point at a cache or mirror |
| `[core.attestation.root_ca] sev_snp_milan` / `_genoa` / `_turin` | same | unset — vendor ARK compiled in | leave unset unless you are testing against a non-production root |
| `insecure_allow_external_trust_anchors` | same, `[core.attestation]` | `false` | must be `true` if *any* `root_ca` path above is set |

The KMS side, in full, is two lines:

```toml
[core]
sev_snp_key_release = true
```

Setting a `root_ca` path without the escape hatch is a startup failure, not a
silent fallback:

```
external attestation trust anchors are configured but
insecure_allow_external_trust_anchors is false
```

The whole `[core.attestation]` block has the same shape in `kms.toml` and
`dstack-verifier.toml`, so a KDS mirror or a test root configured for one can be
copied verbatim into the other.

### 9.2 What the release gate looks like when it is off

`sev_snp_key_release` defaults to `false`, and a guest that trips it reboots in a
loop with

```
Request failed with status=400 Bad Request, error={
  "error": "amd sev-snp key release is not enabled"
}
```

The gate sits *after* full quote verification (`ensure_key_release_allowed`), so
a perfectly good quote still yields nothing — the message is about local policy
and says nothing about the attestation. Only two variants are gated this way:
`dstack-amd-sev-snp` and `dstack-aws-nitro-tpm`. TDX, GCP TDX and Nitro Enclave
have no such switch, which is why nobody notices the gate until the first AMD
boot. The stated reason for NitroTPM is that it is not confidential compute at
all — the AWS hypervisor is inside the TCB — so both need an explicit operator
opt-in on top of whatever the external auth policy decides.

### 9.3 Do not edit a running KMS's compose to flip that flag

The local key provider seals to
`SHA-256(SGX sealing key || MRTD || RTMR0 || RTMR1 || RTMR2 || RTMR3)`, and
**RTMR3 carries the compose hash**. Changing one line of a bootstrapped KMS's
config gives it a different sealing key, and its root CA is gone with the disk.

Use onboarding instead: deploy a second KMS with `auto_bootstrap_domain = ""`,
then

```
curl -X POST http://<new-kms>/prpc/Onboard \
  -H 'Content-Type: application/json' \
  -d '{"source_url":"https://<old-kms>","domain":"<domain>"}'
curl -X POST http://<new-kms>/prpc/Finish -d '{}' -H 'Content-Type: application/json'
```

The new KMS inherits the root key, so apps it serves are still trusted by a
gateway registered against the old one. **Compare the CA public key, not the CA
certificate** — the onboarded KMS re-issues its own cert, so the PEM differs
while `openssl x509 -pubkey` is identical. A KMS that bootstrapped independently
differs in both.

### 9.4 KDS is on the critical path, and stays there

Verification needs the ASK and VCEK certificates. They come from
`https://kdsintf.amd.com`, a **single global endpoint with no mirror**, rate
limited to roughly one identical request per 10s, and unreachable for an entire
test round — TCP timeouts and 100% ICMP loss from five vantage points across four
autonomous systems and two continents, while every other external service
answered normally and DNS stayed healthy throughout.

The rate limit is the one that will bite you mid-test: back-to-back verifications
of the same chip return `HTTP status client error (429)` on the VCEK URL, which
reads exactly like a verification failure until you notice the status code. Space
them ~25s apart.

Caching is in-process only. `AmdKdsClient` keeps a `moka` cache of 16 CA chains
and 1024 VCEKs, capacity-bounded, no TTL, no persistence — warm for the life of
one KMS or verifier process and cold in every one-shot `dstack-verifier --verify`.
There is no KDS cache service in this repo; `[core.attestation.urls] amd_kds`
would accept a mirror, but nothing implements one. (Compare `nvidia-attest-proxy`,
the persistent on-disk cache the NVIDIA collateral got and AMD did not.)

Do not plan on serving the certificates from the host instead. The verifier side
supports it — `normalize_kernel_cert_table` reads ASK and VCEK from the SNP
extended report's certificate table — and so does the guest, but nothing can put
them there: `sev-snp-guest` in stock QEMU has no `certs-path`-style property, and
the host-side `SNP_SET_EXT_CONFIG` ioctl is not in upstream `psp-sev.h`. Guests
ask via `SNP_GET_EXT_REPORT` and get an empty table, which is why every
verification in this round went to KDS.

A note for whoever touches this code: the ARK is already compiled in, and the ARK
fetched from KDS is discarded (`let (_fetched_ark, ask) = ...`). The network
request exists only to obtain the ASK, which is equally static per product family.
Bundling it would remove the `cert_chain` request entirely, leaving only the
per-chip VCEK.

### 9.5 Reaching the API that holds the keys

`GetKey` and `Attest` are **not** on the guest agent's external port. That
listener serves `Info`, `Version` and `Health` only, by design — anyone who can
route to the CVM reaches it. Everything else lives on
`/var/run/dstack.sock` inside the guest, mounted at `/`, `/v0` and `/v1` with
**no `/prpc` prefix**: the internal path is `/v1/GetKey`, not `/prpc/v1/GetKey`.

To reach it from the host during a test, add a socat sidecar to the app compose:

```yaml
  sockproxy:
    image: alpine/socat
    command: TCP-LISTEN:8091,fork,reuseaddr UNIX-CONNECT:/var/run/dstack.sock
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    ports:
      - "8091:8091"
```

That exposes app key material to the host, so it belongs in a lab and nowhere
else.

One more encoding trap, shared with `dstack-verifier --verify`: `bytes` fields in
these JSON bodies are **hex strings**, not base64 and not byte arrays. Base64
fails with `Invalid character 'w' at position 5`, which names the symptom and not
the cause.

---

## 10. Fixed in 0.6.0-rc0 testing — do not re-diagnose

- **KMS image had no CA certificates** and could not start at all
  ([#1128](https://github.com/Dstack-TEE/dstack/pull/1128)). Failed at
  `AttestationVerifier::load` with `No CA certificates were loaded from the
  system`, because `reqwest` builds its clients eagerly and the AMD KDS client is
  constructed even on an Intel-only host.
- **ACME issuance failed outright** ([#1129](https://github.com/Dstack-TEE/dstack/pull/1129)).
  Let's Encrypt now offers `dns-persist-01` alongside `dns-01`; it carries no
  `token`, and `instant-acme` 0.7.2 required that field, so the whole
  authorization failed to deserialize and took the usable challenge with it.
- **DNS self-check could never pass on some zones**
  ([#1130](https://github.com/Dstack-TEE/dstack/pull/1130)). The check queried the
  record immediately after creating it, cached the resulting NXDOMAIN at the
  recursive resolver for the zone's SOA minimum (1800s is common), and then
  retried inside a 300s budget against that cache.
- **`prek` CI failed on any newly created `release/**` branch**
  ([#1127](https://github.com/Dstack-TEE/dstack/pull/1127)). A branch-creating
  push reports an all-zero `before` SHA, making the diff range invalid.

If you hit any of these on a build that predates the fixes, that is why.

---

## 11. Housekeeping

- **Keep an inventory as you go**: CVMs, ufw rules, DNS records, host module and
  permission changes, registry tags. Comment ufw rules so they can be found later
  (`ufw allow 9350/tcp comment "dstack rc test"`).
- Host changes from section 1 (`/dev/sev` mode, `vhost_vsock`, the VMware vsock
  blacklist) **revert on reboot**. Decide whether to persist them; either is fine,
  but know which you chose.
- Remove test ZtDomains and stray `_acme-challenge` TXT records when finished.
- A cluster run leaves a WireGuard interface per node and a second set of ufw
  rules and ports; both outlive the CVMs.
- An AMD run adds a KMS per release-gate variation. Each is a full CVM with its
  own disk and port; the ones that only served as a stepping stone are safe to
  delete once the onboarded KMS works, but nothing cleans them up for you.
- **Do not poll with `pgrep -f` on a pattern your own commands contain.** A
  waiter looping on `pgrep -f "build-image.sh ..."` never exits while you check
  progress with a command whose own command line includes that string — checking
  keeps it waiting. The same self-match reports a finished build as still
  running, and a bare `pgrep -af qemu-system` matches the grep itself. Check for
  the artifact (`docker image inspect`, a file, a port) rather than the process.
- When doing an A/B across dependency versions, **restore `Cargo.lock` along with
  `Cargo.toml`.** Editing the manifest and running cargo rewrites the lockfile;
  restoring only the manifest leaves them inconsistent. CI will not catch it
  unless a step passes `--locked`.
- Run any A/B with both arms on the current build. Reusing an earlier failure log
  as the control is tempting and usually invalid — the image, the credentials and
  the certificate state have all moved since.
