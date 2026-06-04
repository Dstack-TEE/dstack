<!-- SPDX-License-Identifier: Apache-2.0 -->
# Quickstart (GCP private deployment)

Orchestration scripts collapse the deployment to a **single-digit number of
commands**. For the rationale / what each step does, see
[`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md).

> 中文: [`QUICKSTART_CN.md`](QUICKSTART_CN.md)

## Key: most commands are NOT run per deployment

| Frequency | Who | Command |
|---|---|---|
| **once** | Vendor | `./deploy-authority.sh` (start Authority + Verifier) |
| **once per release** | Vendor | `./vendor-release.sh` (build/encrypt/push images + compute hashes + register global policy + fill templates) |
| **once per new customer** | Vendor | `./vendor-add-tenant.sh <user_id>` (create tenant + register app, reusing the global hashes) |
| **once per environment** | Operator | `./setup-swp.sh` (optional egress hardening); IP reservation (done inside the deploy script) |
| **per deployment** | Operator | `./operator-deploy.sh all` |

The parameterized compose makes the os/compose/app hashes **identical across
customers**, so onboarding a new customer is just one `vendor-add-tenant.sh`.

## Prerequisites (once per machine)

From a clean machine (Debian/Ubuntu; swap the package manager elsewhere):

```bash
# 1) system tools
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssl python3 python3-pip \
    skopeo docker.io docker-compose-v2

# 2) python deps (kms_ctl.py uses requests; dstack-cloud env encryption uses cryptography)
pip3 install --break-system-packages requests cryptography

# 3) gcloud: install the SDK (https://cloud.google.com/sdk/docs/install), then log in + set the project
gcloud auth login                      # or: gcloud auth activate-service-account --key-file=…
gcloud config set project <PROJECT>

# 4) dstack-cloud — a single-file Python CLI; put it on PATH (e.g. /usr/local/bin) + chmod +x.
#    It MUST include the private_ip-binding patch (Dstack-TEE/dstack #709): once merged, take it
#    from the dstack repo's scripts/bin/dstack-cloud, otherwise apply #709 yourself. It needs the
#    cryptography pip dep above.

# 5) get the repo + fill the config
git clone <dstack-repo> && cd dstack/on-prem/gcp/scripts
cp config.env.example config.env && "$EDITOR" config.env
```

**Which config.env fields each side fills:**
- **Vendor** (vendor-release / add-tenant): `AUTHORITY_URL`, `AUTHORITY_ADMIN_TOKEN`,
  `PUBREG`, `IMAGE_KID`, `APP_ID`, `WORKLOAD_SRC`, `WORKLOAD_NAME`, `OS_VERSION`. Run
  `docker login "$PUBREG"` first (pushing images needs auth).
- **Operator** (operator-deploy): `GCP_PROJECT`, `GCP_ZONE`,
  `AR_LOCATION/AR_PROJECT/AR_REPO`, `PUBREG`, `WORKLOAD_NAME`, `OS_VERSION`, `KMS_IP`,
  `LAUNCHER_IP`, `USER_ID`, `AUTHORITY_URL`, optional `SWP_PROXY`. `OS_VERSION` is the
  **dotted** release name (e.g. `dstack-cloud-nvidia-0.6.1`); the scripts derive the
  dashed app.json/dir name automatically.

> One-time GCP resources (AR repo + GCS bucket + enabled APIs): see
> [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) "Prerequisites". `operator-deploy.sh`
> bootstraps dstack-cloud's global config (`~/.config/dstack-cloud/config.json`:
> `image_search_paths` / `gcp` / `kms_urls`) automatically. Image sync (`sync`) needs
> only gcloud auth.

## Vendor (on its own internet-connected host)

```bash
cd on-prem/gcp/scripts
./deploy-authority.sh                 # once: start Authority+Verifier, prints AUTHORITY_PUBKEY
./vendor-release.sh                   # per release: produce images @ PUBREG + pin-filled deploy/ templates + register global policy
./vendor-add-tenant.sh acme           # per customer: create tenant acme + register app (prints its API key)
```

**Hand off to that operator**: ① the 4 images in `$PUBREG`; ② the pin-filled
`deploy/kms/` and `deploy/launcher/`; ③ `AUTHORITY_PUBKEY`; ④ the tenant API key.
Keep the Authority online (the courier connects to it).

## Operator (on its own GCP)

Drop the vendor-delivered `deploy/kms` and `deploy/launcher` in place, fill
`config.env` (`KMS_IP`/`LAUNCHER_IP`/`OS_IMAGE`/`PUBREG`/`AR_*`/`USER_ID`/`AUTHORITY_URL`/
optional `SWP_PROXY`), then:

```bash
cd on-prem/gcp/scripts
./operator-deploy.sh all              # sync images→AR + pull OS + deploy KMS(+provision+verify) + deploy launcher(+verify)
# or step by step:
#   ./operator-deploy.sh sync         # sync images + pull the OS version
#   ./operator-deploy.sh kms          # deploy KMS CVM + courier provision + verify serving/SAN
#   ./operator-deploy.sh launcher     # deploy workload CVM + verify E2E /status
./setup-swp.sh                        # optional: egress domain-allowlist hardening
```

`operator-deploy.sh` automatically: reserves the static IPs, fills app.json's GCP
fields, writes `.user-config`, sets `kms_urls`, runs `prepare`/`deploy`/`fw`/`provision`,
and verifies (KMS GetMeta + cert SAN, launcher `/status`).

## Day-2

- **Workload version update / key rotation** (vendor): re-run `./vendor-release.sh`,
  then for each live tenant `./vendor-add-tenant.sh <user_id>` + `kms_ctl.py sync-auth`
  to push the new bundle; the operator runs `./operator-deploy.sh sync` for the new image.
- **Redeploy / change IP / change OS** (operator): edit `config.env` and re-run
  `./operator-deploy.sh kms|launcher`.
- **Monitoring**: launcher `/status`, Authority `usage-receipt`.
