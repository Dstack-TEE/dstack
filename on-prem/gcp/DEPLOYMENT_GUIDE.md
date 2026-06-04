<!-- SPDX-License-Identifier: Apache-2.0 -->
# dstack Private Deployment Guide (GCP) — role-split, step-by-step

End-to-end deployment into a **customer-owned GCP environment**, split across two
roles throughout:

- **Vendor** — owns the trust root, has internet. Starts the Authority, mints the
  image key, builds and encrypts the images, registers the authorization
  whitelists, and fills the "security pins" (pubkey + image digests) into the
  compose templates. **Never touches the customer's GCP.**
- **Operator** — the customer's GCP operations. Syncs the images into their own
  Artifact Registry, deploys the CVMs, runs the courier, hardens egress. **Never
  holds the vendor's signing private key.**

Every step is tagged **[Vendor] / [Operator]**, with a per-command explanation.
Shell variables are placeholders — substitute as needed.

> A Chinese version of this guide is at [`DEPLOYMENT_GUIDE_CN.md`](DEPLOYMENT_GUIDE_CN.md).
> Just want to deploy fast (not the rationale)? Use the orchestration scripts: [`QUICKSTART.md`](QUICKSTART.md).

---

## Overview: three roles and the trust model

```
         ┌──────────────┐      [Vendor host · internet]
         │  Authority   │      signs AuthBundle, HPKE-seals the root key, verifies KMS attestation
         │  + Verifier  │
         └──────┬───────┘
                │  HTTPS: challenge / provision
                ▼
 ╔══════════════════════════════════════╗   [Operator bastion · UNTRUSTED relay]
 ║  ◆◆◆   C O U R I E R   (CLI)   ◆◆◆    ║   kms_ctl.py — relays cryptographically
 ║                                        ║   **sealed blobs** (sealed root / signed
 ║  challenge → init → provision → install║   AuthBundle / quote) between the vendor
 ║                                        ║   Authority and the in-VPC key-broker;
 ╚══════════════════╤═════════════════════╝   sees no plaintext, KMS needs no inbound
                │  over an IAP tunnel (KMS has no public inbound)
                ▼
         ┌──────────────┐      [Customer GCP · TDX+vTPM Confidential VM · static internal IP]
         │   KMS CVM    │      dstack-kms + key-broker: receives the root → derives per-app keys, leases the image keyring
         └──────┬───────┘
                │  mTLS (in-VPC)
                ▼
         ┌──────────────┐      [Customer GCP · TDX+vTPM Confidential VM]
         │  Workload CVM │      launcher: fetches the image keys → JWE-decrypts the ocicrypt-encrypted image → runs the workload
         └──────────────┘
```

> **The courier (the `kms_ctl.py` CLI) is the keystone of the design, and is
> deliberately UNTRUSTED.** It relays across the vendor and customer trust domains
> so the KMS can be provisioned **with no public inbound at all**. It only forwards
> **cryptographically sealed** data — the root key is HPKE-sealed to the KMS's
> attested transport pubkey, the AuthBundle is Ed25519-signed by the vendor, and the
> quote is verified by the verifier — so even a compromised courier (or the operator
> machine running it) cannot read the plaintext root key or forge authorization.

**Core idea**: the workload image is **layer-encrypted** (ocicrypt native JWE,
asymmetric EC P-256 — encryption needs only the public key). The **private key**
needed to decrypt is leased to the launcher by the KMS *inside the TEE*, only after
remote attestation. Through the Authority the vendor controls *which machine running
which image* can obtain the key — the customer's GCP admins, and GCP itself, never
see the plaintext image or the root key. The image private key is **global** (one
encrypted image artifact serves all tenants); each tenant's app/disk keys are
derived from **its own independent root**, isolated across tenants.

### Who does what

**Initial deployment**

| Responsibility | Vendor | Operator |
|---|---|---|
| Authority / Verifier | ✅ on its own host | — |
| Global image keyring | ✅ mint (private key never leaves the Authority) | — |
| Build / encrypt images | ✅ push to a public registry | — |
| Choose the dstack OS version + read `os_image_hash` from its release | ✅ | — |
| Compute compose_hash + register whitelists (os-image / kms-compose / app) | ✅ (on its own Authority) | — |
| Create tenant / issue per-user API key (multi-tenant) | ✅ | — |
| Compose-template "security pins" (pubkey + digests) | ✅ | — |
| Sync images to AR | — | ✅ sync-image.sh |
| Pull the chosen OS version | — | ✅ `dstack-cloud pull <version>` |
| Network planning: reserve static IPs + set `kms_urls` | — | ✅ |
| Customer values (registry / IP) | — | ✅ user_config |
| Deploy CVMs (KMS + launcher) + courier provision | — | ✅ dstack-cloud |
| Verify (serving + E2E) | — | ✅ |
| Egress hardening | — | ✅ SWP / firewall |

**Day-2 / lifecycle**

| Responsibility | Who |
|---|---|
| Workload version update (encrypt new image → register new `image_digest` → `sync-auth` to push the new bundle) | Vendor |
| Image-key rotation / revoking an app·digest·key (→ sync-auth) | Vendor |
| Keep the Authority online (courier / sync-auth connect to it) | Vendor |
| Re-provision / redeploy CVMs (change IP, change OS version, recovery) | Operator |
| Monitoring: launcher `/status`, usage receipts `usage-receipt` | Operator (watches status) / Vendor (collects receipts) |

### Shared parameters the two sides must agree on first

| Parameter | Decided by | How the vendor uses it | How the operator uses it |
|---|---|---|---|
| **KMS static internal IP** (e.g. `10.128.15.220`) | both | **nothing to configure** (key-broker auto-detects the CVM IP as the cert SAN) | reserve the address + bind via `private_ip` + set `kms_urls`/`KMS_HOST` |
| **AR path** `${REGION}-docker.pkg.dev/${PROJECT}/${AR_REPO}` | operator | — | sync target + `DSTACK_REGISTRY` |
| **dstack OS version** (publicly released, e.g. `dstack-cloud-0.6.0`) | vendor chooses | read `os_image_hash` from the release's `auth_hash.txt` + register it | `dstack-cloud pull <version>` to fetch locally |
| **workload app_id** (40 hex) | vendor | register it + put it in the workload compose | put it in `app.json` |
| **image digests** (key-broker / dstack-kms / launcher / workload image) | vendor (build output) | pin into compose / register | — |
| **AUTHORITY_PUBKEY** | vendor (Authority output) | pin into the KMS compose | — |

> ⚠️ **Bind the KMS to the planned static IP before the first provision.** The KMS
> cert SAN is generated by the key-broker at install time by **auto-detecting the
> CVM's own internal IP**, so as long as the CVM already holds the static IP, the
> SAN automatically equals `kms_urls` (no extra config). **Changing the KMS IP
> later** requires re-provisioning — and with no SSH you can't edit the installed
> cert in place (`provision --reset` wipes `/kms` over SSH and fails; the running
> dstack-kms can't be restarted live). You must `remove` the whole KMS (including
> the data disk) and `deploy` + `provision` again; the SAN then follows the new IP.

---

## Prerequisites

### Tools

| Tool | Vendor | Operator | Notes |
|---|---|---|---|
| `docker` + compose | ✅ | ✅ | Authority stack / image build |
| `skopeo` (≥1.13) | ✅ | ✅ | JWE encrypt / sync |
| `dstack-cloud` | — | ✅ | deploy CVMs (**must support `private_ip`, see below**) |
| `gcloud` | — | ✅ | GCP resources + IAP tunnels |
| `openssl` / `python3` | ✅ | — | keys / JSON |

> ⚠️ **`dstack-cloud` must support binding a static internal IP via
> `gcp_config.private_ip`.** Stock `GcpConfig` has no `private_ip` field → it's
> dropped on load from app.json (and `prepare`/`deploy` rewrite app.json, stripping
> it), and `--private-network-ip` is never passed → the CVM gets an **ephemeral IP**,
> the KMS address is unpredictable, and the cert SAN won't match. Patch: ① add
> `private_ip: str = ""` to `GcpConfig`; ② in the instance create args, `if
> config.private_ip:` append `--subnet=default` (when unset) + `--private-network-ip={private_ip}`.
> Upstreamed as **Dstack-TEE/dstack PR #709**.

### One-time GCP resources (Operator)

```bash
export PROJECT=<your-gcp-project>  REGION=us-central1  ZONE=${REGION}-a
export AR_REPO=dstack-private
export AR=${REGION}-docker.pkg.dev/${PROJECT}/${AR_REPO}
export BUCKET=gs://${PROJECT}-dstack

# Enable APIs (compute=TDX VMs, artifactregistry=private images, networkservices/security=SWP egress hardening)
gcloud services enable compute.googleapis.com artifactregistry.googleapis.com \
  networksecurity.googleapis.com networkservices.googleapis.com --project=$PROJECT
# Private image repo (no-internet CVMs pull from here over Private Google Access)
gcloud artifacts repositories create $AR_REPO --repository-format=docker \
  --location=$REGION --project=$PROJECT
# GCS bucket dstack-cloud deploys with (holds the boot/shared disk images)
gcloud storage buckets create $BUCKET --project=$PROJECT --location=$REGION
```

---

# Part 1 ▶ Vendor

> The vendor completes steps 1–5 on its own internet-connected host, producing the
> deliverables (images @ public registry, filled compose templates, AUTHORITY_PUBKEY,
> registered whitelists), then hands off to the operator.

## Step 1 [Vendor] Start the Authority (+ Verifier)

**Goal**: start the vendor's authorization hub. It persists a **per-tenant
independent root key**, hosts the **global image keyring**, signs the Ed25519
**AuthBundle**, and uses **dstack-verifier** to check the KMS's TDX+vTPM attestation.

```bash
cd on-prem        # where docker-compose.authority.yml lives

# Vendor secrets/config (do not commit). The KMS cert SAN is auto-detected by the
# key-broker from the CVM's internal IP (see step 9); the vendor need not know the
# customer's KMS address, so no KMS-address config is needed here.
cat > .env.authority <<EOF
AUTHORITY_SIGNING_KEY=$(openssl rand -hex 32)     # Ed25519 seed, persisted → stable pubkey
AUTHORITY_NONCE_SECRET=$(openssl rand -hex 32)    # HMAC key for stateless challenge nonces
AUTHORITY_ADMIN_TOKEN=$(openssl rand -hex 16)     # admin API Bearer token (required for multi-tenant)
REQUIRE_ATTESTATION=true                          # MUST be true in prod: provision requires a verifiable quote
ALLOWED_TCB_STATUSES=UpToDate,SWHardeningNeeded
EOF
export ADMIN_TOKEN=$(grep AUTHORITY_ADMIN_TOKEN .env.authority | cut -d= -f2)
export AUTHORITY=http://localhost:8083

# Start authority + verifier. --env-file feeds the env above (changing env needs `up -d`; `restart` won't reload env)
docker compose --env-file .env.authority -f docker-compose.authority.yml up -d --build

# Fetch the signing pubkey — the root of the whole trust chain; the KMS compose pins it
curl -s $AUTHORITY/api/v1/authority-pubkey      # → {"pubkey":"TCIj…NmU="}
```

- `docker compose … up -d`: brings up `authority` (FastAPI :8083) and `verifier`
  (dcap-qvl). `authority` bind-mounts `./authority`, so edits take effect on restart.
- `authority-pubkey`: returns the Ed25519 pubkey. **Record it** (referred to below as
  `$PUBKEY`); step 5 writes it literally into the KMS compose's `AUTHORITY_PUBKEY`.

> ⚠️ **Expose the Authority over TLS for a remote operator.** The Authority listens on
> **plaintext `:8083`** and the operator authenticates every `challenge`/`provision`/
> `sync-auth` with its **tenant API key as a bearer token**. Over the public internet that
> token (and the AuthBundle, whose image keyring travels in cleartext) would be exposed to
> the network. So when the operator is remote, **front the Authority with TLS** (a reverse
> proxy / HTTPS LB) and set `AUTHORITY_URL=https://…`. Plaintext `http://` is only for
> same-host or a trusted private network. (What this does *not* expose either way: the KMS
> root — it's HPKE-sealed end-to-end — and bundle forgery — it's Ed25519-signed.)

## Step 2 [Vendor] Mint the global image key (get the pubkey)

**Goal**: generate a "use-for-a-while" global image-encryption key (EC P-256). The
private key goes into the Authority's global keyring and never leaves the API; only
the **public key** is returned, for encrypting images.

```bash
curl -s -X POST $AUTHORITY/api/v1/admin/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"kid":"vendor-2026h1"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["pub_pem"])' > pub.pem
cat pub.pem      # -----BEGIN PUBLIC KEY-----  this is the jwe:pub.pem used in step 3
```

- `POST /admin/keys {kid}`: mints a key into the **global** keyring (vendor-wide, not
  per-user). `kid` is the key name (goes into the image annotation). Returns `pub_pem`
  (public key); the private key is never returned.
- The public key is not sensitive, can live in CI; **a build machine holds only the
  public key — leaking it decrypts nothing**.
- Rotation: mint a new `kid` (e.g. `vendor-2026h2`); the old kid stays in the keyring
  until its images are retired. Revoke with `DELETE /admin/keys/<kid>`.

## Step 3 [Vendor] Build images + JWE-encrypt the workload image + push to the public registry

**Goal**: build the dstack component images and encrypt the workload image so it
"won't run without the private key", then push everything to the vendor's **public
registry** (e.g. `cr.kvin.wang`). The encrypted layers carry no plaintext, so a
public registry is fine.

```bash
export PUBREG=cr.kvin.wang        # vendor public registry

# 1) Build the component images (build context = repo root). dstack-kms can use the official dstacktee/dstack-kms.
docker build -f on-prem/key-broker/Dockerfile -t $PUBREG/key-broker:latest .
docker build -f on-prem/launcher/Dockerfile   -t $PUBREG/launcher:latest   .
docker push $PUBREG/key-broker:latest
docker push $PUBREG/launcher:latest
# dstack-kms: docker pull dstacktee/dstack-kms:latest && docker tag … $PUBREG/dstack-kms:latest && push

# 2) JWE-encrypt the workload image with the global pubkey → push to the public registry
skopeo copy --encryption-key jwe:pub.pem \
  docker://<your-app:tag> \
  docker://$PUBREG/<your-app>-enc:latest

# 3) Record each image digest (step 5 pins them literally; after the operator syncs, the AR digest matches)
for img in key-broker launcher dstack-kms <your-app>-enc; do
  echo "$img: $(skopeo inspect docker://$PUBREG/$img:latest --format '{{.Digest}}')"
done
```

- `docker build … key-broker/launcher`: an in-image `cargo build --release`, producing
  dependency-free runtime images.
- `skopeo copy --encryption-key jwe:pub.pem`: encrypts each layer with the public key
  (ocicrypt native JWE). **Note the `jwe:` prefix is encryption-only**; decryption uses
  `--decryption-key <priv.pem>` with no prefix.
- `skopeo inspect --format '{{.Digest}}'`: the manifest digest. `skopeo copy` is
  deterministic, so the AR digest after the operator syncs is **unchanged** — the
  vendor can pin this digest set directly.

## Step 4 [Vendor] Compute compose_hash + register the authorization whitelists

**Goal**: register in the Authority *which OS, which KMS compose, which app +
launcher/workload digest* are allowed. `compose_hash` is identical across customers
(customer values live in `${VAR}`/user_config and aren't measured), so the vendor
**computes it once and registers it once**.

First fill the step-3 digests + step-1 pubkey into the compose templates and compute
the hashes (see step 5; this assumes `deploy/kms` and `deploy/launcher` are filled):

```bash
# compose_hash = sha256(app-compose.json) (the authoritative algorithm = dstack-util sha256_file)
dstack-cloud -C deploy/kms      prepare >/dev/null
dstack-cloud -C deploy/launcher prepare >/dev/null
KMS_COMPOSE_HASH=$(sha256sum deploy/kms/shared/app-compose.json      | cut -d' ' -f1)
LN_COMPOSE_HASH=$( sha256sum deploy/launcher/shared/app-compose.json | cut -d' ' -f1)

export USER_ID=acme
export APP_ID=<workload-app-id-40hex>     # vendor-chosen workload app id
export OS_IMAGE_HASH=<the value in auth_hash.txt of the chosen OS release>  # the dstack OS image UKI hash
export IMAGE_DIGEST=sha256:<step-3 workload image digest>

# (a) Create the tenant (for multi-tenant, hand the returned API key to that customer's operator)
curl -s -X POST $AUTHORITY/api/v1/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"user_id\":\"$USER_ID\"}"

# (b) Register the allowed OS-image hash (checked at bootAuth + key lease; empty = deny)
curl -s -X POST $AUTHORITY/api/v1/admin/os-images \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"hash\":\"$OS_IMAGE_HASH\"}"

# (c) Register the allowed KMS compose hash (one of the KMS-provision identity checks)
curl -s -X POST $AUTHORITY/api/v1/admin/kms-compose-hashes \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"hash\":\"$KMS_COMPOSE_HASH\"}"

# (d) Register the workload app + the two digest gates + the current image version pointer
curl -s -X POST $AUTHORITY/api/v1/admin/users/$USER_ID/images \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"app_id\":\"$APP_ID\",
       \"allowed_launcher_digests\":[\"$LN_COMPOSE_HASH\"],
       \"image_digest\":\"$IMAGE_DIGEST\"}"
```

- `prepare` + `sha256sum app-compose.json`: dstack stores `docker-compose.yaml`
  **verbatim** (with `${VAR}` literal) inside `app-compose.json`; its sha256 is the
  `compose_hash` the CVM's cert will carry. Customer values live in user_config and
  don't enter this file, so the hash is identical across customers.
- `os-images` / `kms-compose-hashes`: global policy, used at KMS provision to check the
  KMS's own identity (os + key_provider=tpm + compose). `os_image_hash` comes from the
  vendor-**chosen publicly-released dstack version** — `dstack-cloud pull <version>` (or
  extract the release tar), then read `~/.dstack/images/<version>/auth_hash.txt`; **no
  deploy and no measure needed**.
- `users/$USER_ID/images`: registers the workload app. `allowed_launcher_digests` = the
  allowed launcher compose hashes (a hard gate); `image_digest` → set as both
  `allowed_workload_digests` and `current_image_digest` (the version pointer the
  launcher pulls by). **The decryption private key comes from the global keyring and is
  not registered here.**

## Step 5 [Vendor] Fill the compose templates (security pins) + hand off

**Goal**: write the "security pins" (pubkey + each image digest + app_id + workload
image path name) literally into the compose templates. Customer-related registry/IP
stay as `${VAR}`, injected at runtime by the operator's user_config. This keeps the
templates **measured-identically and reusable across customers**.

```bash
# Copy from the committed templates and fill the pins (or hand the filled templates to the operator)
cp -a deploy-templates/kms      deploy/kms
cp -a deploy-templates/workload deploy/launcher
```

In the KMS compose (`deploy/kms/docker-compose.yaml`) fill:
- `key-broker` image → `${DSTACK_REGISTRY}/key-broker@sha256:<step-3 key-broker digest>`
- `dstack-kms` image → `${DSTACK_REGISTRY}/dstack-kms@sha256:<step-3 dstack-kms digest>`
- `AUTHORITY_PUBKEY=<step-1 $PUBKEY literal>` (**never from a variable**; enables AuthBundle signature verification)
- keep `${DSTACK_REGISTRY}` / `${SWP_PROXY}` literal

> ### What `AUTHORITY_PUBKEY` is, and what abuse it prevents
>
> It is the **vendor Authority's Ed25519 public key**. Every time the key-broker
> receives an AuthBundle it verifies the bundle's signature against it
> (`verify_auth_bundle`) and **accepts only bundles signed by the vendor's private
> key**. The AuthBundle carries the entire authorization policy: `app_whitelist`
> (allowed launcher / workload digests), `os_images`, the **global image keyring**,
> `slot_quota`, `bundle_seq`. It is written **literally** into the KMS compose → enters
> `compose_hash` → is measured by TDX+vTPM attestation.
>
> **Threat model: the operator is semi-trusted** — it runs the infrastructure and can
> call the key-broker's `/courier/install` directly, but must not be able to authorize
> itself to extract the image keyring or run unauthorized code with KMS-derived keys.
> Pinning this pubkey blocks two abuses:
>
> 1. **The operator forges its own authorization.** Without the pin, the operator (or a
>    compromised courier CLI) could craft its own AuthBundle — slipping a malicious
>    launcher digest / attacker image / fake keyring into the whitelist — `install` it
>    into the KMS, and so steal the image keyring. With the pin, the key-broker rejects
>    **any non-vendor-signed** bundle.
> 2. **The operator swaps the trust root for its own key.** Because `AUTHORITY_PUBKEY`
>    is **literal in the measured compose**, swapping it for the operator's own pubkey
>    (to make a self-signed bundle pass) changes `compose_hash` → at KMS provision the
>    `compose_hash` isn't in the vendor's pre-registered `allowed_kms_compose_hashes` →
>    rejected outright, and the root key is never delivered.
>
> So it **must be literal, never from a variable / user_config**: a runtime variable
> would let the operator replace the trust anchor. Nailing it into the measured compose
> makes the fact "this KMS trusts only the vendor's signing key" itself attested by
> TDX+vTPM — unbypassable even by an operator who fully controls the deployment.
> (The companion `bundle_seq` monotonic counter separately prevents replaying an old
> bundle.)

In the workload compose (`deploy/launcher/docker-compose.yaml`) fill:
- `launcher` image → `${DSTACK_REGISTRY}/launcher@sha256:<step-3 launcher digest>`
- `APP_ID=<$APP_ID literal>`, `WORKLOAD_IMAGE=${DSTACK_REGISTRY}/<your-app>-enc` (no tag; the digest comes from the Authority's `current_image_digest`)
- keep `${KMS_HOST}` literal (`KMS_URL`/`KEY_BROKER_URL=https://${KMS_HOST}:8000|8002`)

**Hand off to the operator**: ① the 4 images in the public registry; ② the two
pin-filled compose templates (+ prelaunch.sh); ③ `AUTHORITY_PUBKEY`; ④ the whitelists
already registered in the Authority. The Authority stays online (the courier connects
to it).

---

# Part 2 ▶ Operator

> The operator completes steps 6–12 on its own GCP. It only fills customer values
> (registry/IP) and never touches the vendor's signing private key.

## Step 6 [Operator] Sync the images into AR

**Goal**: sync the 4 images from the vendor's public registry into your own private
AR, so the no-internet CVMs can pull them over PGA.

```bash
# scripts/config.env must contain AR_LOCATION/AR_PROJECT/AR_REPO
for img in dstack-kms key-broker launcher <your-app>-enc; do
  scripts/sync-image.sh "cr.kvin.wang/$img:latest" "$img:latest"
done
```

- `sync-image.sh`: `skopeo copy --all` moves each layer by digest, using
  `gcloud auth print-access-token` as the AR credential. Encrypted layers are copied
  verbatim and the **digest matches the public registry** (same as the vendor's pinned
  digest).
- The last line prints `<AR-ref>@<digest>`, which you can cross-check against the
  step-3/5 digests.

## Step 7 [Operator] Reserve the static IP + prepare the deploy dirs + user_config

**Goal**: realize the agreed KMS static IP, drop the vendor-delivered templates into
the instance dirs, fill customer values, and point dstack-cloud at our KMS.

```bash
# Reserve static internal IPs for KMS / launcher (address stays put across remove/deploy → stable cert SAN/kms_urls)
gcloud compute addresses create dstack-kms-ip      --region=$REGION \
  --subnet=default --addresses=10.128.15.220 --project=$PROJECT
gcloud compute addresses create dstack-launcher-ip --region=$REGION \
  --subnet=default --addresses=10.128.15.230 --project=$PROJECT

# Pull the vendor-chosen dstack OS version (public release; ships disk.raw + auth_hash.txt; prepare/deploy need the local image)
dstack-cloud pull <os-version>      # e.g. dstack-cloud-0.6.0

# Drop in the vendor-delivered templates (with the pins); deploy/ is gitignored per-customer state
cp -a <vendor-delivered>/kms      deploy/kms
cp -a <vendor-delivered>/workload deploy/launcher

# Fill the GCP fields of app.json (these do NOT enter compose_hash)
#   kms:      project/zone/bucket, private_ip=10.128.15.220, key_provider=tpm
#   launcher: same, private_ip=10.128.15.230, app_id=<$APP_ID>, key_provider=kms

# Customer values (plaintext JSON, shipped via the shared disk to /dstack/.host-shared/.user-config)
cat > deploy/kms/.user-config <<EOF
{ "DSTACK_REGISTRY": "$AR", "SWP_PROXY": "10.128.0.53:80" }
EOF
cat > deploy/launcher/.user-config <<EOF
{ "DSTACK_REGISTRY": "$AR", "KMS_HOST": "10.128.15.220" }
EOF

# Point dstack-cloud's global kms_urls at our KMS (else it defaults to public kms.tdxlab.dstack.org)
dstack-cloud config-edit      # services.kms_urls = ["https://10.128.15.220:8000"]
```

- The reserved address = the planned KMS static IP (`10.128.15.220`). dstack-cloud
  (with the #709 patch) binds it via app.json's `private_ip`; the IP the key-broker
  later auto-detects is exactly this → the cert SAN matches automatically.
- `.user-config`: prelaunch reads it inside the CVM, validates it, and writes
  `/dstack/.env` for compose `${VAR}` expansion. **Paths/IPs only, no digests**
  (injection guard).
- `kms_urls`: the workload CVM's guest-agent uses it for GetAppKey (key_provider=kms).
  The host `10.128.15.220` must equal the KMS cert SAN.

## Step 8 [Operator] Deploy the KMS CVM

**Goal**: create the KMS's TDX Confidential VM on GCP, bound to the static IP, pulling
key-broker + dstack-kms from AR.

```bash
dstack-cloud -C deploy/kms prepare        # generate shared/ (app-compose, sys-config, .instance_info)
dstack-cloud -C deploy/kms deploy         # create the TDX VM, bind private_ip=10.128.15.220
dstack-cloud -C deploy/kms fw allow 8001 8002   # allow IAP → key-broker (courier 8001 / mTLS 8002)
```

- `prepare`: normalizes compose/prelaunch into `app-compose.json` (the source of
  compose_hash), and generates sys-config (internal IP / OS hash etc.).
- `deploy`: uploads the boot/shared disk images and creates the instance. **Confirm the
  output `Internal IP: 10.128.15.220`** (binding succeeded).
- `fw allow`: opens IAP inbound to the courier/mTLS ports (no public IP, IAP-only).

## Step 9 [Operator] Courier-provision the KMS

**Goal**: securely deliver the root key into the KMS via the courier (the CLI relays
Authority ↔ in-VPC key-broker). Works even though the KMS has no internet.

```bash
# provision (the script wraps the IAP tunnel + 4-step courier).
# The OS-image hash was already obtained from the release and registered by the vendor in
# step 4; the image dir pulled in step 7 ships auth_hash.txt, so the CVM pins its own
# os_image_hash at boot — no measure needed here.
scripts/provision-kms.sh        # = kms_ctl.py attest
```

The 4-step courier: ① **challenge** (Authority issues an HMAC nonce) → ② **courier/init**
(key-broker emits a TDX+vTPM attestation, `report_data=SHA512(nonce‖transport_pub‖kms_ts)`
binds this courier session's transport key) → ③ **provision** (Authority verifies the
quote via the verifier + the **KMS identity whitelist**, then HPKE-seals the root key +
signs the AuthBundle) → ④ **courier/install** (key-broker verifies the signature,
HPKE-opens the root, materializes the keyset).

> **KMS identity whitelist** (the three stable checks before releasing the root — note
> it deliberately does NOT use `mr_aggregated`, since GCP's PCR0 changes per instance):
> ① `os_image_hash` ∈ os-images; ② `key_provider==tpm`; ③ `compose_hash` ∈
> `allowed_kms_compose_hashes`. All three are stable across redeploys.
>
> **At install the key-broker auto-detects the KMS rpc cert SAN**: it takes the CVM's
> own internal IP (the `local_addr` of a UDP socket "connected" toward `169.254.169.254`)
> as the SAN → automatically equals the operator's `kms_urls`; neither the authority nor
> either side configures any KMS address.
>
> After install the key-broker writes `/kms/_ready`, and the KMS container's wait loop
> auto-`exec`s dstack-kms — **no SSH restart needed**.

## Step 10 [Operator] Verify the KMS is serving

**Goal**: confirm the KMS booted from the delivered root, serves TLS, and that the cert
SAN = the static IP (else workload CVMs can't connect).

```bash
gcloud compute start-iap-tunnel dstack-kms 8000 --local-host-port=localhost:18000 \
  --project=$PROJECT --zone=$ZONE &
curl -sk https://localhost:18000/prpc/KMS.GetMeta | head -c 80   # → {"ca_cert":"-----BEGIN CERT…
echo | openssl s_client -connect localhost:18000 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName                     # → IP Address:10.128.15.220
```

- `GetMeta` returning `ca_cert`/`k256_pubkey` means the KMS is serving.
- The cert SAN **must be `IP Address:10.128.15.220`** (= the CVM IP the key-broker
  auto-detected at install; ra_tls emits an IP SAN automatically). If it's
  `DnsName:kms.local`, auto-detect fell back to the default — check the CVM actually
  bound the static IP (`deploy`'s Internal IP should == the reserved address; otherwise
  check the `dstack-cloud` `private_ip` patch).

## Step 11 [Operator] Deploy the workload CVM

**Goal**: start the launcher; inside the TEE it fetches the image private keys,
JWE-decrypts, and runs the workload — all with no internet.

```bash
dstack-cloud -C deploy/launcher prepare
dstack-cloud -C deploy/launcher deploy    # confirm Internal IP: 10.128.15.230
```

Boot chain (automatic): guest-agent `key_provider=kms` → GetAppKey from the KMS
(`10.128.15.220:8000`, cert SAN matches) for the app keys + the KMS-derived CA → the
launcher calls guest-agent `get_tls_key` for a **KMS-signed RA-TLS client cert with the
app_info extension** → connects to the key-broker (`10.128.15.220:8002` mTLS) to request
a **key lease** (the key-broker verifies the chain + reads app_id/compose_hash/os_image
from the extension, checks the whitelists, and returns the **global image keyring**) →
the launcher writes the private keys to tmpfs, feeds them to `skopeo --decryption-key`,
decrypts by digest → `docker load` → compose-up. The lease has a TTL; if it can't be
renewed past the grace period, the launcher stops the workload.

## Step 12 [Operator] Verify E2E

```bash
gcloud compute start-iap-tunnel dstack-launcher 9100 --local-host-port=localhost:19100 \
  --project=$PROJECT --zone=$ZONE &
curl -s http://localhost:19100/status | python3 -m json.tool
```

Expected:
```json
{ "app_id": "<$APP_ID>", "workload_image": "…/<your-app>-enc",
  "running_digest": "sha256:<workload image digest>",  ← what runs after JWE decrypt is the registered image
  "lease_active": true, "workload_running": true, "bundle_seq": <N>, "last_error": null }
```

`lease_active` + `workload_running` = true means the whole chain works. Without SSH you
can also pull container logs via guest-agent `:8090` (when `public_logs:true`).

---

# Part 3 ▶ Egress domain-allowlist hardening (Operator, recommended)

**Goal**: let the two CVMs reach only approved destinations — the workload CVM has no
internet at all, the KMS reaches only Intel PCS. A network tag `dstack-cvm` scopes this
to just these two.

- **① Private Google Access**: enable PGA on the subnet; the CVM pins
  `*.googleapis.com`/`*.pkg.dev` to the private VIP `199.36.153.10` via `/etc/hosts`.
  AR/GCS go over Google's private network.
- **② Lock down the workload CVM**: `dstack-cvm` tag + remove the external IP +
  egress-deny (allow only internal / PGA VIP:443 / SWP / metadata). AR via PGA, KMS via
  internal network.
- **③ KMS reaches Intel PCS via a plaintext SWP**: dcap-qvl's rustls **does not trust** a
  self-signed proxy cert and has nowhere to add a CA, so build the GCP **Secure Web
  Proxy as a plaintext endpoint** (`ports:[80]`, no cert); rustls uses a plaintext
  `CONNECT` tunnel with end-to-end TLS to Intel, and the SWP allowlists by SNI. The
  allowlist must include **both** Intel domains: `api.trustedservices.intel.com` **and**
  `certificates.trustedservices.intel.com` (missing one yields a `tunnel error` when the
  KMS verifies a workload CVM's quote). The KMS compose sets `HTTP_PROXY=http://${SWP_PROXY}`.

> One-shot script `scripts/setup-swp.sh` (pga / gateway / hosts / lockdown / verify
> stages). Verify: inside the CVM `curl -x http://<SWP_IP>:80 https://api.trustedservices.intel.com/...`
> = 200, while a direct `https://www.google.com` times out.

---

# Part 4 ▶ Day-2: update the workload version (Vendor + Operator)

**Goal**: ship a new version of the business image to already-deployed CVMs **without
rebuilding them**. The workload image digest is **not** measured (only its *name* and
`app_id` are), so a version bump is a **hot rolling update** — no new `compose_hash`, no
CVM redeploy. (Changing the launcher compose, the image *name*, or `app_id` *is* measured
→ that needs a cold redeploy, see Steps 5–11.)

The trust is preserved end-to-end: the vendor is the only party that can admit a new
digest (it must enter `allowed_workload_digests`, **G11**), and a downgrade is rejected
(`bundle_seq` is strictly monotonic, **G8**).

### Step 13 [Vendor] Cut the new version + register it

```bash
cd on-prem/gcp/scripts
# 1) re-encrypt the new upstream image to the SAME measured name (new digest) + refresh
#    the release manifest. (WORKLOAD_SRC in config.env points at the new version.)
./vendor-release.sh
# 2) for EACH live tenant, register the new digest (appends to allowed_workload_digests
#    and moves current_image_digest forward — old digests stay valid for rollback).
./vendor-add-tenant.sh <user_id>
```

`vendor-release.sh` rebuilds/encrypts and rewrites `deploy/.release-manifest.env` with the
new `WORKLOAD_IMAGE_DIGEST`; `vendor-add-tenant.sh` (re-runnable on an existing tenant)
reads that manifest and calls `POST /admin/users/<id>/images`. Tell each operator a new
version is available.

### Step 14 [Operator] Mirror the image + push the refreshed bundle

```bash
cd on-prem/gcp/scripts
./operator-deploy.sh update         # = sync (mirror images PUBREG→AR) + sync-auth (push bundle)
# or the two halves separately:
#   ./operator-deploy.sh sync        # mirror the new encrypted image into AR (no-internet CVM pulls here)
#   ./operator-deploy.sh sync-auth   # relay the vendor's refreshed AuthBundle into the running KMS
```

`sync-auth` (wrapper `refresh-auth.sh`) opens an IAP tunnel to the KMS key-broker and runs
the bundle-only courier exchange: `usage-receipt ← key-broker → authority /sync-auth`
(re-sign, bump `bundle_seq`) `→ /courier/install` (verify Ed25519 sig vs the pinned
`AUTHORITY_PUBKEY` + `bundle_seq` strictly increasing). The **root key is not
re-provisioned** — only the authorization data is swapped.

### Step 15 — automatic rolling update (launcher, no action)

Each launcher polls the key-broker `/version` (every `poll_interval`). When
`current_image_digest` changes it:

1. `lease/acquire` for the new digest — admitted only if it's in `allowed_workload_digests`
   (**G11**), re-running every gate against the live bundle;
2. pulls + JWE-decrypts the new image with the leased keyring;
3. `docker compose up` **rolling**, waits ~60 s for the health check, and **auto-rolls-back**
   to the previous digest if it doesn't come up healthy.

Verify on the launcher `/status` (Step 12): `running_digest` advances to the new digest and
`bundle_seq` increments.

### Related day-2 actions (same `sync-auth` push)

- **Key rotation** — mint a new keyring `kid`, encrypt future images to its pubkey; the old
  `kid` stays in the keyring until its images are retired. Push with `sync-auth`.
- **Revoke a version** — remove the digest from `allowed_workload_digests` (or add it to
  `revocations.image_digests`), then `sync-auth`; afterwards that digest fails **G11**.
