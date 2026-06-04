<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->
# GCP Private Deployment — End-to-End Guide

Air-gapped-style private deployment of dstack on GCP: the customer runs the
**KMS** inside a TDX Confidential VM with **no inbound public access**, while the
**vendor** controls authorization (root key, code whitelist, instance count,
time bounds) cryptographically. The CLI is an untrusted courier between the two.

This guide reflects the configuration that has been **verified end-to-end** on a
GCP TDX VM (real TDX+vTPM attestation, HPKE root delivery, AuthBundle signature
verification). Where something is still a placeholder/stub it says so explicitly
(see [§8 Security status](#8-security-status)).

---

## 1. Architecture

```
            VENDOR side (internet)                     CUSTOMER VPC (no inbound)
┌───────────────────────────────────┐        ┌──────────────────────────────────────┐
│  vendor authority  (FastAPI :8083) │        │  TDX Confidential VM (dstack-cloud OS) │
│   • per-user root keys (P-256+k256)│        │   ┌────────────┐   ┌────────────────┐ │
│   • signs AuthBundle (Ed25519)     │        │   │ dstack-kms │   │  key-broker    │ │
│   • HPKE-seals root to KMS         │        │   │  :8000 TLS │◀──│ :8001 courier  │ │
│   ────────────► dstack-verifier    │        │   │            │   │:8002 mTLS keys │ │
│        :8080  (dcap-qvl + vTPM +   │        │   └─────┬──────┘   └───────┬────────┘ │
│        RTMR replay + os_image_hash)│        │      reads keyset     guest agent      │
└───────────────────────────────────┘        │      /kms/certs       /var/run/dstack  │
                ▲                              └──────────────┬───────────────────────┘
                │   challenge / provision                     │  courier/init,install
                │   (HTTPS)                                   │  (via IAP tunnel)
          ┌─────┴───────────────────────────────────────────┴─────┐
          │  CLI  kms_ctl.py  (courier — untrusted, only relays)   │
          └────────────────────────────────────────────────────────┘
```

- **Vendor authority** (`authority/`): per-user root keys, Ed25519-signed
  AuthBundles, HPKE-seals the root to the KMS's attested transport key. Delegates
  TDX attestation checks to **dstack-verifier**.
- **dstack-verifier** (repo's `verifier/`): verifies the TDX quote (dcap-qvl) +
  GCP vTPM quote + RTMR replay + os_image_hash (UKI from the event log).
- **dstack-kms**: stock; boots from the keyset the key-broker writes, serves RPC.
- **key-broker** (`key-broker/`): courier endpoints, AuthBundle sig verify, HPKE
  unseal → writes the KMS keyset, auth webhook, mTLS image-keyring delivery + lease/quota.
- **launcher** (`launcher/`): in a workload CVM — fetches the image keyring over mTLS, pulls
  the JWE-encrypted image by digest, decrypts, runs (see [§7](#7-workload-launcher-ocicrypt)).

### Ports

| Service       | Port | Exposure                                   |
|---------------|------|--------------------------------------------|
| dstack-kms    | 8000 | TLS RPC (in-VPC / via IAP tunnel)          |
| key-broker    | 8001 | courier + auth webhook (bastion/IAP)       |
| key-broker    | 8002 | mTLS image-keyring delivery (launcher)     |
| vendor authority | 8083 | operator/admin API (CLI)                 |
| dstack-verifier | 8080 | internal to the authority compose network |

---

## 2. Prerequisites

- A **GCP TDX Confidential VM** running a dstack-cloud OS image
  (`confidentialInstanceType=TDX`, `/dev/tdx_guest` present). It needs **egress**
  to pull images and fetch TDX quote collateral; it must **not** accept inbound
  public traffic. Egress can be locked to a **domain whitelist** (Secure Web
  Proxy / Squid on the NAT) — the KMS CVM only needs: the image registry, the
  time source, and **`api.trustedservices.intel.com`** (Intel PCS — used to
  verify *workload* quotes; GCP quotes embed the PCK chain so no PCCS to run and
  no Intel subscription key). No separate PCCS VM is required.
- Access via **IAP** (`roles/iap.tunnelResourceAccessor`) — no public IP needed.
  An SSH key registered on the dstack OS (a GitHub key) for `gcloud compute ssh`.
- A firewall rule allowing the IAP range to the KMS ports, e.g.
  `--source-ranges=35.235.240.0/20 --rules=tcp:8001,tcp:8002 --target-tags=<vm>`.
- On the **vendor host**: Docker + docker compose, Python 3 (`fastapi uvicorn
  cryptography requests pyhpke`), `skopeo` (for image encryption).
- **key-broker / launcher / dstack-verifier** are built from this repo
  (`docker build -f on-prem/<svc>/Dockerfile -t <tag> .`, `rust:1.92-slim-bookworm`);
  **dstack-kms** uses the stock/official image (`dstacktee/dstack-kms` — mainline's
  ra-tls already emits IP-SAN certs, no rebuild). All are then **synced into the
  customer's GCP Artifact Registry** so the no-internet CVMs pull over Private
  Google Access:
  ```bash
  gcloud artifacts repositories create dstack-private --repository-format=docker --location=<region>
  gcloud artifacts repositories add-iam-policy-binding dstack-private --location=<region> \
      --member="serviceAccount:<vm-SA>" --role=roles/artifactregistry.reader
  scripts/sync-image.sh <ext-registry>/<image>  <repo:tag>   # skopeo, by digest
  ```
  The CVM authenticates to AR with its own SA metadata token (prelaunch does
  `docker login -u oauth2accesstoken`).

---

## 3. Quick start

The customer-side CVMs are created with the **`dstack-cloud`** CLI
(`new` → `prepare` → `deploy`); the vendor stack is docker-compose.

```bash
# 0) (one-time) GCP Artifact Registry + sync the images the CVMs will pull
cd on-prem/gcp/scripts && cp config.env.example config.env && $EDITOR config.env
./sync-image.sh cr.kvin.wang/dstack-kms:latest   dstack-kms:latest
./sync-image.sh cr.kvin.wang/key-broker:latest   key-broker:latest

# 1) vendor stack (authority + verifier) — prints the authority pubkey
cd .. && docker compose -f docker-compose.authority.yml up -d --build
curl -s http://localhost:8083/api/v1/authority-pubkey

# 2) KMS CVM — copy the committed template, then fill only app.json/user_config.
#    The vendor has already filled literal image digests + AUTHORITY_PUBKEY in compose.
cp -a deploy-templates/kms deploy/kms-prod
cd deploy/kms-prod && dstack-cloud prepare && dstack-cloud deploy

# 3) provision (courier attest) — over an IAP tunnel to key-broker:8001
dstack-cloud fw allow 8001 8002        # IAP ingress to the courier/mTLS ports
python3 ../../authority/kms_ctl.py attest --user-id <id> \
    --kms-url http://localhost:8001 --authority-url http://localhost:8083
```

The sections below explain each step. **Note the deployment model changed**: the
KMS now runs as a `dstack-cloud` app (created from scratch via `deploy`), not by
hand-editing `/dstack/docker-compose.yaml` on a pre-existing VM.

---

## 4. Vendor authority stack

`docker-compose.authority.yml` runs **authority + dstack-verifier** on vendor infra.

```bash
cd on-prem
REQUIRE_ATTESTATION=true \
EXPECTED_OS_IMAGE_HASH=<approved-uki-hash> \
AUTHORITY_NONCE_SECRET=<shared-secret> \
AUTHORITY_ADMIN_TOKEN=<admin-token-or-empty> \
  docker compose -f docker-compose.authority.yml up -d --build
curl -s http://localhost:8083/api/v1/authority-pubkey      # → base64 Ed25519 pubkey
```

Key env (see `.env.authority.example`):

| Var | Meaning |
|-----|---------|
| `REQUIRE_ATTESTATION` | reject provisions without a quote (MUST be `true` in prod) |
| `EXPECTED_OS_IMAGE_HASH` | vendor-approved KMS image UKI hash; verifier compares it to the event-log value |
| `AUTHORITY_SIGNING_KEY` / `…_FILE` | **persistent** Ed25519 signing key (stable pubkey across restarts; default file `/data/signing.key`) |
| `AUTHORITY_NONCE_SECRET` | HMAC secret for stateless challenge nonces (share across workers) |
| `AUTHORITY_ADMIN_TOKEN` | set → multi-user mode (admin API + per-user API keys) |
| `VERIFIER_URL` | `http://verifier:8080` (compose-internal) |

> The verifier image is built from this repo (`verifier/Dockerfile`) and includes
> the QEMU-based `dstack-acpi-tables` helper needed to compute RTMR0. The official
> reproducible image `dstacktee/dstack-verifier:<ver>` is an alternative
> (`VERIFIER_IMAGE=…`).

### Multi-user (optional)

With `AUTHORITY_ADMIN_TOKEN` set, create tenants (each gets its own independent
root key + an API key shown once):

```bash
python3 authority/kms_ctl.py create-user --user-id acme --authority-url $AUTHORITY_URL --admin-token $TOK
python3 authority/kms_ctl.py list-users  --authority-url $AUTHORITY_URL --admin-token $TOK
```

Operators then pass `AUTHORITY_API_KEY=<that key>` to `attest`. A user can only act
on its own root (cross-tenant → 403).

---

## 5. Customer KMS + key-broker (TDX CVM)

The KMS runs as a **`dstack-cloud` app**. Start from the committed template in
`deploy-templates/kms/`, copy it into the ignored per-customer `deploy/kms-prod/`
directory, then `prepare` + `deploy`:

```bash
dstack-cloud new kms-prod --key-provider local --os-image dstack-cloud-nvidia-0-6-1
# copy deploy-templates/kms/* here
# edit app.json: gcp_config.project/bucket, machine_type (c3-* = TDX)
# create user_config with DSTACK_REGISTRY/SWP_PROXY, or let registry derive from metadata
cd kms-prod && dstack-cloud prepare && dstack-cloud deploy
```

**Three rules that make the KMS self-bootstrap and keep `compose_hash`
customer-independent:**

1. **`key_provider: tpm`** (on GCP) — a `kms` key-provider app would ask a KMS for
   its own disk/env keys at boot; this KMS *is* the KMS, so it derives them from
   the **GCP vTPM** instead (no external KMS). (`local` is for hosts without a
   usable TPM.)
2. **Security pins are literal** — `AUTHORITY_PUBKEY` and every image
   `@sha256:<digest>` are written directly in `docker-compose.yaml`, never via
   `${...}`:
   ```yaml
   image: ${DSTACK_REGISTRY}/key-broker@sha256:<literal-digest>
   environment:
     - AUTHORITY_PUBKEY=EIgvRPk5lyrmaDNT+K89Rt2IIEvvHauZGXqu8qn7AWw=   # literal
   ```
   Bonus: the literal becomes part of the measured **`compose_hash`**, so the
   pubkey that gates AuthBundle verification is tamper-evident via attestation.
   (When the authority signing key or an image digest changes, update the
   template + re-`prepare`.)
3. **Customer values stay runtime-only** — the compose keeps literal
   `${DSTACK_REGISTRY}` / `${SWP_PROXY}`. `prelaunch.sh` validates the resolved
   registry/proxy with anchored regexes, writes `/dstack/.env`, and never
   rewrites `docker-compose.yaml`. Docker compose reads that `.env` at `up` time,
   after dstack has already measured `app-compose.json`.

The app's `docker-compose.yaml` (see `deploy-templates/kms/docker-compose.yaml`):

- `kms` + `key-broker`, `network_mode: host`, sharing a `kms-data` volume at `/kms`;
  key-broker binds `/var/run/dstack.sock` (TDX Attest).
- images pulled from **`${DSTACK_REGISTRY}/...@sha256:<literal-digest>`**;
  prelaunch logs docker in with the VM's SA metadata token (works air-gapped over PGA).
- `kms.toml` inlined via compose `configs:` (`cert_dir=/kms/certs`,
  `enforce_self_authorization=false`, webhook `http://127.0.0.1:8001` (loopback,
  host networking), `pccs_url=https://api.trustedservices.intel.com`).
- `kms` `depends_on` key-broker **healthy** — so the KMS auto-starts the moment the
  courier provisions the root (key-broker `/healthz` flips `ready`), no manual
  restart.

After `deploy`, key-broker `/healthz` reads `waiting for root key`; the KMS
container stays pending until [§6 provision](#6-provision-courier-attest).

---

## 6. Provision (courier attest)

Open an IAP tunnel to `key-broker:8001`
(`gcloud compute start-iap-tunnel <vm> 8001 --local-host-port=localhost:8001`)
and run `kms_ctl.py attest` — the CLI is the courier, relaying between the
internet-facing authority and the in-VPC key-broker. The KMS auto-starts when the
root lands (it `depends_on` key-broker healthy). The 4-step flow:

1. **challenge** → authority issues a stateless HMAC nonce (bound to `user_id`).
2. **courier/init** → key-broker generates an X25519 transport keypair and asks
   the guest agent for a full **Attest** (GCP = TDX quote **+ vTPM quote** +
   event log), with `report_data = SHA512(nonce ‖ transport_pub ‖ kms_ts)`.
3. **provision** → authority sends `{attestation, vm_config}` to **dstack-verifier**;
   on success it checks `report_data == SHA512(…)` (binds the quote to the
   transport key) and tcb status, then applies the **KMS identity whitelist**
   (below); then **HPKE-seals** the user's root to `transport_pub` and returns
   it + an **Ed25519-signed AuthBundle**.

   **KMS identity whitelist** (`verify_kms_attestation`) — three *stable,
   semantic* checks, deliberately **not** `mr_aggregated`: on GCP
   `mr_aggregated = sha256(PCR0 ‖ PCR2 ‖ runtime_pcr)` and PCR0 (the vTPM
   firmware/launch measurement) changes on every instance, so a `mr_aggregated`
   trust-on-first-use pin would 403 on every redeploy. Instead:
   - **`os_image_hash`** == `EXPECTED_OS_IMAGE_HASH` (vendor-approved OS image);
   - **`key_provider` == `tpm`** — parsed from `app_info.key_provider_info`
     (hex of `{"name","id"}`); `none`/`local-sgx`/`kms` are rejected, so the
     KMS root is only released to a **GCP vTPM-sealed** disk;
   - **`compose_hash`** ∈ the user's whitelist — an explicit
     `allowed_kms_compose_hashes` list. With the parameterized template this
     `compose_hash` is stable across customers; the vendor pre-computes it once
     after filling the literal digests/pubkey and registers it for every tenant.
4. **courier/install** → key-broker **verifies the AuthBundle signature**, checks
   `bundle_seq` monotonicity, HPKE-opens the root, and writes the 8-file KMS
   keyset (`root-ca`/`tmp-ca`/`rpc` + `root-k256.key` + `rpc-domain`). The KMS rpc
   cert **SAN** is the CVM's own internal IP, which the key-broker **auto-detects**
   at install (UDP-connect toward the metadata IP, read `local_addr`) so it always
   matches the address clients dial (`kms_urls`). No `KMS_DOMAIN` config needed on
   either side; the SAN is not a trust anchor (the root CA is). Override for a
   DNS/LB front-end: `kms_ctl.py attest --kms-domain <name>`. The authority's
   `KMS_DOMAIN` is only a last-resort fallback when auto-detect is unavailable.

Then KMS is restarted; `keys_exists()` is true so it skips onboarding and serves
TLS RPC (`endpoint=https://0.0.0.0:8000`).

### Verify

```bash
# KMS serving from the authority-provided root:
curl -sk https://<kms>:8000/prpc/KMS.GetMeta          # → ca_cert (the root CA)
# rpc cert: SAN = the CVM's internal IP (auto-detected), issuer=O=Dstack, CN=Dstack KMS CA
openssl s_client -connect <kms>:8000 </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName
#   → X509v3 Subject Alternative Name: IP Address:<kms-internal-ip>
```

To learn `EXPECTED_OS_IMAGE_HASH` for a new image: run one attest with the
authority in dev mode (`REQUIRE_ATTESTATION` set but `EXPECTED_OS_IMAGE_HASH`
empty) and read the verifier's reported actual UKI hash
(`UKI hash mismatch: ... actual=<hash>`), then pin that as the expected value.

---

## 7. Workload launcher (ocicrypt)

The workload CVM runs the **launcher**, which fetches a **keyring of private
keys** from the key-broker over mTLS and decrypts the image. Image encryption
uses **ocicrypt's native JWE** (asymmetric, EC P-256 / ECDH-ES) — encryption
needs **only the public key**, so the build machine holds no decryption secret:

```bash
# vendor (one-time): mint a GLOBAL image keypair on the authority, save the pubkey
curl -s -X POST $AUTHORITY/api/v1/admin/keys \
    -H "Authorization: Bearer $ADMIN_TOKEN" -d '{"kid":"img-2026q2"}' \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["pub_pem"])' > pub.pem

# vendor: encrypt + publish with the PUBLIC key only (no scheme prefix on decrypt)
skopeo copy --encryption-key jwe:pub.pem docker://<plain-image> docker://<registry>/<repo>:enc
# launcher (runner.rs) writes each leased private key to /run/cek/<kid>.pem and:
#   skopeo copy --decryption-key /run/cek/<kid>.pem ... docker://<repo>@<digest> docker-archive:...
```

The workload CVM also starts from a committed template:
`deploy-templates/workload/`. Its measured compose pins the launcher image as
`${DSTACK_REGISTRY}/launcher@sha256:<literal-digest>` and leaves only
`${DSTACK_REGISTRY}` plus `${KMS_HOST}` for runtime expansion. `prelaunch.sh`
validates those values and writes `/dstack/.env`; it does not edit the compose.
The workload image path is `${DSTACK_REGISTRY}/<workload-name>` and the digest
still comes from the authority's `current_image_digest`.

Key release is gated by the AuthBundle: the launcher's RA-TLS identity must pass
`app_id ∈ app_whitelist ∧ compose_hash ∈ allowed_launcher_digests ∧ os_image ∈
os_images`; it then receives the **global** keyring (vendor-wide — one encrypted
image decrypts for every tenant). Pulling by `@digest` enforces the digest, and
ocicrypt decrypts only if a leased key is the image's recipient (else fails
closed). The vendor pre-computes the workload template's customer-independent
`compose_hash` once and registers it in `allowed_launcher_digests`. The keyring
is **global**; per-tenant isolation is in `root_material`.

> **Status:** verified locally (real skopeo JWE round-trip: pubkey-only encrypt,
> keyring try-each decrypt, rotation, fail-closed) and the launcher wiring builds.
> The full no-internet workload-CVM round-trip is re-validated on GCP — see
> [§8](#8-security-status).

---

## 8. Security status — what is and isn't verified

**Verified end-to-end (real TDX VM):**

- ✅ HPKE root delivery (RFC 9180, X25519/HKDF/AES-256-GCM) — the relaying CLI
  never sees plaintext root.
- ✅ Real **TDX + vTPM attestation** via dstack-verifier; `report_data` binds the
  quote to the session transport key (defeats a CLI substituting its own key).
- ✅ `os_image_hash` measurement (event-log UKI vs vendor-approved value).
- ✅ **KMS identity whitelist** before releasing the root: `os_image_hash` +
  `key_provider == tpm` + `compose_hash` ∈ whitelist (§6). Keyed on stable,
  semantic measurements, **not** `mr_aggregated` (GCP's PCR0 varies per
  instance) — verified by a from-scratch redeploy provisioning with no pin reset.
- ✅ **AuthBundle Ed25519 signature verified** by key-broker (tampered bundle →
  rejected); authority signing key is **persistent** (file/seed, stable pubkey
  across restarts), and the verifying `AUTHORITY_PUBKEY` is a literal in the KMS
  compose → part of the measured `compose_hash` (tamper-evident via attestation).
- ✅ `bundle_seq` monotonicity (anti-rollback of authorization).
- ✅ Multi-user isolation; stateless HMAC nonces.
- ✅ No-internet posture: internal Artifact Registry (PGA), Intel PCS (no PCCS VM),
  `secure_time=false` + GCP kvm-clock so boot doesn't block on public NTP,
  `key_provider=tpm` (GCP vTPM) so the KMS self-bootstraps with no
  KMS-decrypted env dependency. The only runtime `.env` is the non-secret file
  prelaunch writes for compose interpolation.
- ✅ **Egress domain whitelist** (§10): launcher fully locked down (no internet —
  AR via PGA only, verified under egress-deny); KMS reaches Intel PCS only via a
  GCP Secure Web Proxy configured as a **plaintext** endpoint (so the rustls
  client can use it; whitelist proven — Intel allowed, google blocked). Enforced
  by a tag-scoped fail-closed egress firewall.
- ✅ **Real AuthBundle**: per-app `app_id` / `allowed_launcher_digests` (from
  `store.register_app_image`) + a **global image keyring** of `{kid, priv_pem,
  pub_pem}` keypairs (`store.mint_key`); Ed25519-signed, `bundle_seq` monotonic.
- ✅ **Workload launcher E2E**: lease acquired → global key**ring** (private keys)
  released over mTLS → image pulled by digest → `skopeo --decryption-key` JWE
  decrypt → `docker load` → workload runs and serves — all on a no-internet CVM.
- ✅ **No SSH in production** (see DEPLOYMENT_GUIDE_CN.md §6): prelaunch installs `sshd` only
  when deployed with instance metadata `dev-ssh=1`; `DEPLOY_MODE=prod` omits it.
  All CLI↔KMS/app interaction is HTTP: provisioning (`/courier/*`), KMS auth
  webhook (`/bootAuth/{kms,app}`), readiness (`/healthz`,`/version`), the image
  keyring over mTLS (`/lease/*`), and the launcher's read-only `/status`. KMS
  auto-boots from `/kms/_ready` (no SSH `docker restart`). Secrets never leave
  any endpoint except the image private keys over mTLS to an attested,
  authorized launcher (and the key-mint endpoint returns only public keys); no
  introspection/file/exec endpoints; errors may show paths but never key bytes.

**Still placeholder / TODO before production:**

- ⚠️ Authority signing key should be **HSM-backed** (currently file/seed).
- ⚠️ `AUTHORITY_PUBKEY` must reach the key-broker over a trusted channel (the CLI's
  initial setup), not by hand.
- ⚠️ Launcher `GetAppKey` (RA-TLS) is **degraded**: the mTLS key-broker client skips
  server-cert verification (`NoServerVerify`) because the KMS CA from a verified
  `GetAppKey` isn't wired yet — restore full RA-TLS before production.
- ⚠️ KMS egress lockdown (§10b steps 1–4) is **staged, not applied**: the compose
  carries the proxy env but the KMS hasn't been redeployed/tagged yet.

---

## 9. Troubleshooting / gotchas

1. **KMS stuck on the onboarding page** → `kms.toml` not delivered, so KMS ran on
   embedded defaults (`cert_dir=/etc/kms/certs`). The app compose must inline it
   via `configs:` and run `dstack-kms -c /etc/dstack/kms.toml` (see
   `deploy-templates/kms/docker-compose.yaml`).
2. **Auth webhook unreachable** → host networking means the webhook is on
   `http://127.0.0.1:8001`, not the compose service name.
3. **key-broker crash-loop `GLIBC_2.38 not found`** → build with
   `rust:1.92-slim-bookworm` (trixie's `rust:1.92-slim` links glibc 2.38; runtime
   is bookworm/2.36).
4. **`courier/init` returns empty attestation** → the key-broker container must
   bind-mount `/var/run/dstack.sock` (the guest agent).
5. **`bundle_seq not monotonically increasing`** on re-provision → wipe the
   key-broker state (`certs/`, `_ready`, `auth_bundle.json`, `root_key.bin` in the
   `kms-data` volume) and recreate key-broker (it persists the last seq).
6. **verifier `failed to execute dstack-acpi-tables`** → use the verifier image
   built from `verifier/Dockerfile` (bundles the QEMU acpi helper), not a bare
   `cargo build` image.
7. **`os_image_hash` empty / UKI mismatch with `expected=`** → the CVM didn't pin
   an os_image_hash; set `EXPECTED_OS_IMAGE_HASH` on the authority (it injects the
   expected value; the actual comes from the vTPM event log, PCR2 Event 28).
8. **KMS deploy can't read its env / boot hangs on KMS** → the KMS app must use
   `key_provider=tpm` (GCP vTPM; never `kms`). Do not put
   `AUTHORITY_PUBKEY` or image digests in env; they must be literal in the
   compose (§5). The runtime `.env` written by prelaunch is only for non-secret
   compose interpolation (`DSTACK_REGISTRY`, `SWP_PROXY`).
9. **AR pull `Unauthenticated`** → the CVM must `docker login` to AR with its SA
   metadata token (prelaunch). NB: the dstack OS python lacks `json` — parse the
   token with `sed`, not `python3 -c`.
10. **Internal IP changes on `remove`+`deploy`** (breaks `KMS_URL` etc.) → use a
    static internal IP: reserve it (`gcloud compute addresses create <name>
    --region=<r> --subnet=<s> --addresses=<ip>`) and set `gcp_config.private_ip`
    in `app.json`, passed as `--private-network-ip` so the VM keeps the same
    RFC1918 address across redeploys (KMS pinned `10.128.15.220`, launcher
    `10.128.15.230`). **Requires a `dstack-cloud` that honors `private_ip`:** the
    stock `GcpConfig` has no `private_ip` field, so it's silently dropped on load
    (and `prepare`/`deploy` rewrite `app.json` stripping it) and never passed to
    `gcloud` → the VM gets an ephemeral IP and the KMS cert SAN won't match. Patch
    `dstack-cloud`: add `private_ip: str = ""` to `GcpConfig`, and in the instance
    `create_args` add `--subnet=default` (if unset) + `--private-network-ip=<ip>`
    when `private_ip` is set. Re-add `private_ip` to `app.json` if an old build
    already stripped it. (Patch should be upstreamed.)
11. **`provision` 403 `…not in whitelist` after a clean redeploy** → only with
    the *old* `mr_aggregated` pin (GCP PCR0 varies per instance). The current
    whitelist keys on `os_image_hash`+`key_provider=tpm`+`compose_hash` (§6), all
    stable, so a redeploy provisions with no reset. If you see this, the authority
    is running pre-fix code — restart it (`docker restart on-prem-authority-1`,
    `./authority` is bind-mounted) or, for a one-off, clear `expected_mr_aggregated`
    in `/data/users.json`. An **intentional** KMS compose change legitimately
    403s until you add the new `compose_hash` to `allowed_kms_compose_hashes`
    after review.

---

## 10. Egress domain whitelist (hardening)

Goal: the CVMs reach **only** approved destinations. Two enforcement layers,
scoped to the dstack CVMs by the network tag `dstack-cvm` so the rest of the
shared VPC is untouched.

### Destinations

| CVM | needs | path |
|-----|-------|------|
| KMS | `api.trustedservices.intel.com` (Intel PCS) | **internet** → plaintext SWP (whitelist) |
| KMS | `storage.googleapis.com` (state bucket) | Private Google Access |
| launcher | `*.pkg.dev` (Artifact Registry) | Private Google Access |
| both | KMS↔launcher, key-broker, metadata | in-VPC / link-local |

### Layer 1 — Private Google Access (Google APIs, no internet)

`scripts/setup-swp.sh pga` enables PGA on the subnet; `… hosts` pins
`*.googleapis.com` / `*.pkg.dev` to the private VIP `199.36.153.10` via per-VM
`/etc/hosts` (no VPC-wide DNS change). Verified: AR and GCS both return 200 from
internal-only VMs.

### Layer 2a — launcher lockdown (no internet at all)

```bash
scripts/setup-swp.sh lockdown          # tag-scoped egress firewall (fail-closed)
gcloud compute instances add-tags dstack-launcher-prod --tags=dstack-cvm --zone=us-central1-a
gcloud compute instances delete-access-config dstack-launcher-prod \
  --access-config-name=external-nat --zone=us-central1-a
```

Egress rules (target tag `dstack-cvm`): ALLOW 10.128.0.0/9, the PGA VIP range
`199.36.153.8/30:443`, the SWP IP `10.128.0.53:80`, metadata `169.254.169.254`;
DENY 0.0.0.0/0. Verified: AR via PGA = 200; google.com / Intel direct =
timeout; the encrypted-workload E2E still decrypts and runs with **no internet**.

### Layer 2b — KMS egress whitelist (Intel PCS only, via plaintext SWP)

The KMS/dcap-qvl HTTP stack is `reqwest + rustls-tls + webpki-roots`. Key point
about the proxy hop:

- An **HTTPS** (TLS) proxy endpoint requires the client to verify the *proxy's*
  TLS cert. That cert is necessarily self-signed (the proxy is an internal IP —
  no public CA will sign it), and rustls validates against compiled-in
  webpki-roots with **no env knob** to add a custom CA. So a **TLS** SWP can't
  be used by the KMS without a code change.
- GCP Secure Web Proxy can also be created as a **plaintext** endpoint
  (`ports: [80]`, **no** `certificateUrls`). Then the rustls client issues
  `CONNECT` in the clear (no proxy cert to verify) and tunnels real end-to-end
  TLS to Intel inside it; the proxy still enforces the whitelist on the
  SNI/CONNECT host. The client↔proxy hop is plaintext but stays in the VPC.

So the KMS uses the **plaintext SWP** — no separate Squid VM needed. (An earlier
iteration used Squid for the same reason; the plaintext-SWP finding replaced it.)

```bash
scripts/setup-swp.sh gateway   # creates dstack-egress-swp @ 10.128.0.53:80 (no cert)
scripts/setup-swp.sh verify    # from KMS: Intel PCS = 200, google.com = reset (56)
```

**KMS lockdown** — the `kms` service in `deploy-templates/kms/docker-compose.yaml`
carries `HTTP_PROXY/HTTPS_PROXY=http://${SWP_PROXY}` + `NO_PROXY` (in-VPC, PGA,
metadata go direct). After `deploy` + `provision` (§6), lock it down:

1. pin Google-API hosts to the PGA VIP (`/etc/hosts`, as Layer 1).
2. `gcloud compute instances add-tags dstack-kms-prod --tags=dstack-cvm` and
   remove its external IP (egress-deny applies; KMS→SWP allowed by
   `dstack-egress-swp`).
3. Verify: KMS serves; from the CVM `curl -x http://10.128.0.53:80 …intel…` =
   200, direct google = timeout; GCS via PGA = 200.

Because the KMS whitelist keys on `compose_hash` (not `mr_aggregated`, §6), a
`remove`+`deploy` re-provisions **without** any authority-side pin reset.

### Resources created

`swp-proxy-only` subnet (REGIONAL_MANAGED_PROXY); `dstack-egress-swp` gateway
(plaintext, `10.128.0.53:80`, no cert) + `dstack-egress-policy` /
`dstack-egress-allow` url-list / `allow-intel-pcs` rule;
`dstack-egress-{internal,pga,swp,metadata,deny}` egress firewall rules (tag
`dstack-cvm`); PGA on the `default` subnet. (No Squid VM, no TLS cert — the
plaintext SWP replaced both.)
