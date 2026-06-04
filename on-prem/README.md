# on-prem — vendor-controlled private deployment of dstack

Deploy dstack into a **customer-controlled environment** (their cloud account or
datacenter, typically air-gapped) while the **vendor retains authorization
control** via an offline KMS and encrypted images. The customer's cloud admin —
and the cloud provider — never see plaintext images or root keys.

## Roles (trust model)

```
┌─────────────┐  vendor host (has internet)
│  Authority   │  signs Ed25519 AuthBundles, holds per-user roots + a GLOBAL
│             │  image-decryption keyring, verifies KMS quotes via dstack-verifier
└──────┬──────┘
       │ courier (untrusted CLI relay)
┌──────┴──────┐  customer TEE (TDX+vTPM)
│   KMS CVM   │  dstack-kms + key-broker: receive HPKE-sealed root, derive app
│             │  keys, lease the image private-key keyring over mTLS
└──────┬──────┘
       │ mTLS (in-VPC)
┌──────┴──────┐  customer TEE
│ workload CVM│  launcher: RA-TLS to KMS, lease keyring, JWE-decrypt image, run
└─────────────┘
```

## Layout — cloud-agnostic core vs cloud-specific

Everything at this level is **cloud-agnostic**; provider-specific glue lives under
[`gcp/`](gcp/).

| Path | What | Cloud-specific? |
|------|------|-----------------|
| `authority/` | authorization service (FastAPI): roots, global JWE keyring, AuthBundles | no |
| `key-broker/` | key-broker (Rust): courier, HPKE unseal, mTLS keyring lease | no |
| `launcher/` | workload-CVM agent (Rust): RA-TLS, lease, JWE decrypt, run | no¹ |
| `verifier/` | `dstack-verifier` container build (TDX+vTPM quote verify) | no |
| `docker-compose.authority.yml` + `.env.authority.example` | vendor-host stack | no |
| `gcp/` | GCP deploy: Secure Web Proxy, Artifact Registry, IAP, dstack-cloud CLI, guides | **yes** |

¹ The launcher's only cloud-specific code is `launcher/src/cloud.rs` — registry
auth (GCP Artifact Registry token today). Another cloud adds a branch there.

## Image encryption (ocicrypt native JWE, asymmetric)

The vendor mints a **global** EC P-256 keypair on the authority and encrypts each
image to the **public key** (`skopeo --encryption-key jwe:pub.pem`) — the build
machine holds no decryption secret. The **private keys** ride in every tenant's
AuthBundle and are leased to attested launchers, so one encrypted image decrypts
for every authorized deployment. Per-tenant isolation lives in the KMS root
material, not the image keyring.

## Deploy

Core services are cloud-neutral; the runnable deployment is currently GCP:

- **GCP**: see [`gcp/DEPLOYMENT_GUIDE_CN.md`](gcp/DEPLOYMENT_GUIDE_CN.md) (step-by-step, 中文) and
  [`gcp/DEPLOYMENT.md`](gcp/DEPLOYMENT.md) (architecture + security status).
- The vendor-host authority runs anywhere: `docker compose --env-file .env.authority
  -f docker-compose.authority.yml up -d` (see `.env.authority.example`).

## Security model (summary)

Default-deny everywhere; no insecure bypass switches. The only secret egress is
the image keyring over mTLS to an attested, authorized launcher; the key-mint
API returns public keys only. See `gcp/DEPLOYMENT.md` §8 for what is and isn't
verified end-to-end.
