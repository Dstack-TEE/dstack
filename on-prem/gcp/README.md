# on-prem/gcp — GCP-specific deployment

The GCP implementation of the [on-prem](../README.md) deployment: deploy the KMS
and workload CVMs into a customer's no-internet GCP VPC (TDX+vTPM Confidential
VMs), reachable only over IAP, pulling images from a private Artifact Registry
over Private Google Access, with egress hard-limited by a Secure Web Proxy.

## Contents

| Path | What |
|------|------|
| `QUICKSTART.md` / `QUICKSTART_CN.md` | **start here** — deploy in a handful of commands via the orchestration scripts |
| `DEPLOYMENT_GUIDE.md` / `DEPLOYMENT_GUIDE_CN.md` | step-by-step guide — what each step does (EN / 中文) |
| [`../PROTOCOL.md`](../PROTOCOL.md) / `../PROTOCOL_CN.md` | **protocol at a glance** (cloud-agnostic core) — every message + what's verified at each hop |
| `design.md` | design rationale / history |
| `scripts/` | deploy + provision toolkit (gcloud / IAP / Artifact Registry / SWP) |
| `scripts/setup-swp.sh` | Secure Web Proxy egress whitelist (Intel PCS only) |
| `scripts/sync-image.sh` | mirror an (encrypted) image into the customer's Artifact Registry |
| `docker-compose.kms.yml` + `.env.example` | KMS-CVM stack (key-broker + dstack-kms) |
| `kms.toml` | dstack-kms config for the KMS CVM |
| `deploy/` | per-instance working configs — **gitignored** (env-specific) |

## What's GCP-specific here (vs cloud-agnostic core)

- **Secure Web Proxy** for domain-whitelisted egress (Intel `api.` +
  `certificates.trustedservices.intel.com`).
- **Artifact Registry** + Private Google Access for air-gapped image pulls;
  auth via the instance metadata token (`launcher/src/cloud.rs`).
- **IAP** tunnels for SSH-free operator access (courier, `/status`, `/logs`).
- **dstack-cloud CLI** (from the `meta-dstack` repo) to create the CVMs;
  `private_ip` reserved as static so `kms_urls` stays stable.

Prereqs: `gcloud` authenticated, an Artifact Registry repo + GCS bucket, and the
dstack OS image. Copy `scripts/config.env.example` → `scripts/config.env` and the
`.env*.example` templates, then follow `DEPLOYMENT_GUIDE_CN.md`.
