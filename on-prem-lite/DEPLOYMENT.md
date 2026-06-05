<!-- SPDX-License-Identifier: Apache-2.0 -->
# on-prem-lite deployment guide

A role-split walkthrough for the **KMS-less single-CVM** profile: the vendor runs
an Authority and ships an encrypted workload + a measured launcher compose; the
operator deploys one workload CVM and licenses it over an IAP courier hop. See
[DESIGN.md](DESIGN.md) for the protocol and the fail-closed gate table.

All commands run from `on-prem-lite/scripts/`. Copy `config.env.example` →
`config.env` and fill it before starting.

> **vendor==operator simplification (this test):** the vendor and operator are the
> same host, so `vendor-release.sh` derives the registered workload image ref from
> the operator's `AR_*` fields. A true vendor/operator split would instead resolve
> the registry operator-side (out of scope here).

---

## Vendor

The vendor owns the License-signing key, the image-encryption keyring, and the
policy whitelists. Everything the vendor pins is **measured** into the launcher's
`compose_hash`, so a tampered launcher is refused at the Authority.

### Prerequisites

- docker + docker compose, skopeo, `dstack-cloud`, python3, curl.
- internet egress (the Authority's verifier fetches Intel TDX quote collateral).
- `config.env`: `AUTHORITY_URL=http://localhost:8084`, `AUTHORITY_ADMIN_TOKEN`,
  `PUBREG`, `IMAGE_KID`, `WORKLOAD_SRC`, `WORKLOAD_NAME`, `USER_ID`,
  `OS_VERSION`, and the operator `AR_*` fields (for the image-ref derivation).

### 1. deploy the Authority

```bash
./deploy-authority.sh
```

Brings up the authority + `dstack-verifier` from `docker-compose.authority.yml`
on **:8084** and prints `AUTHORITY_PUBKEY` (also saved to `.authority-pubkey`).
The pubkey is **stable across restarts** (the Ed25519 signing key is persisted in
the authority volume).

### 2. cut a release

```bash
./vendor-release.sh        # run ONCE per workload release
```

This single command:

1. **mints the global image key** (`IMAGE_KID`, EC P-256) and saves its public PEM
   — images are JWE-encrypted to it; the private key is the per-image CEK and is
   never published.
2. **publishes the lite-launcher** to `$PUBREG/lite-launcher:latest` (pull+retag
   from `LITE_LAUNCHER_SRC`, or build from `launcher/Dockerfile` when blank).
3. **JWE-encrypts the workload** (`skopeo copy --encryption-key jwe:…`) to
   `$PUBREG/$WORKLOAD_NAME:latest`.
4. **creates the tenant** (`USER_ID`) — printing its api key once — and **the app**
   (the Authority assigns a 40-hex `app_id` when `APP_ID` is blank).
5. **fills `deploy/workload/`** from the template, pinning the three **measured**
   values into the compose: the `lite-launcher` digest, the literal base64
   `AUTHORITY_PUBKEY`, and the `app_id`; and writing `app_id` + `os_image` into
   `app.json`.
6. **computes the launcher `compose_hash`** (`dstack-cloud … prepare`, then sha256
   of `shared/app-compose.json`).

It then registers the policy the Authority gates on:

- the **launcher compose_hash** → `allowed_launcher_digests` (G6 — which launcher
  build may run). Because `AUTHORITY_PUBKEY` and `app_id` are baked into the
  compose, this hash measures *which authority and which app* the launcher trusts.
- the **workload digest** (`sha256:…`, with its `image` ref and `kid`) under the
  app → `allowed_workload_digests` (G7 — which encrypted image the License may
  authorize).

Finally it writes `deploy/.release-manifest.env` (`APP_ID`,
`LAUNCHER_COMPOSE_HASH`, `WORKLOAD_IMAGE_DIGEST`, `LITE_LAUNCHER_DIGEST`,
`AUTHORITY_PUBKEY`, `WORKLOAD_IMAGE`).

### 3. deliver to the operator

- the 2 images in `$PUBREG` (`lite-launcher`, `$WORKLOAD_NAME`);
- the filled `deploy/workload/` template and `deploy/.release-manifest.env`;
- the tenant **api key** (set it as the operator's `AUTHORITY_API_KEY`).

---

## Operator

The operator deploys one CVM and runs the courier. The operator is **untrusted**:
it relays opaque blobs between the Authority and the launcher and is never a trust
anchor.

### Prerequisites

- `gcloud` (authenticated; IAP + Artifact Registry access), skopeo,
  `dstack-cloud`, python3 (`requests`), curl.
- the vendor-delivered `deploy/workload/` + `deploy/.release-manifest.env`.
- `config.env`: `GCP_PROJECT`, `GCP_ZONE`, `AR_LOCATION/AR_PROJECT/AR_REPO`,
  `PUBREG`, `OS_VERSION`, `WORKLOAD_IP`, `WORKLOAD_NAME`, `USER_ID`,
  `AUTHORITY_URL` (reachable from the operator host), `AUTHORITY_API_KEY`.

### deploy + license

```bash
./operator-deploy.sh all        # sync → deploy → license
```

or run the stages individually:

- **`sync`** — mirrors `lite-launcher` + the encrypted workload from `$PUBREG`
  into the operator AR (so the no-internet CVM pulls over Private Google Access),
  and pulls the dstack OS image.
- **`deploy`** — reserves `WORKLOAD_IP`, fills `app.json` (project/zone/bucket/
  private_ip/`instance_name=dstack-lite-workload`/os_image), writes
  `.user-config` (`DSTACK_REGISTRY`), then `prepare` + `deploy`, and opens the
  courier port (`fw allow 9000`). dstack-cloud is configured **without
  `kms_urls`** — the lite profile has no KMS.
- **`license`** — opens an IAP tunnel to `dstack-lite-workload:9000` → localhost
  `:19000`, waits for `/healthz`, then runs the courier
  (`cli/license-ctl.py attest`): the launcher attests (TDX+vTPM), the Authority
  verifies and returns `{license, sealed_cek}`, and the launcher HPKE-opens the
  CEK, decrypts the workload, and runs it. It then polls `/status` until
  `workload_running: true`.

---

## Day-2

Re-run the courier to issue a fresh License — a higher `seq`, a later
`expires_at`, and optionally a new workload digest (rolling update):

```bash
./operator-deploy.sh update          # = re-run the license stage
# or directly:  cli/license-ctl.py renew
```

The launcher persists the highest installed `seq` and refuses any `seq ≤` it
(anti-rollback), and pins `AUTHORITY_PUBKEY` to verify the signature (G8).

**Expiry stops the workload.** Each License carries `expires_at +
grace_period_secs`; a launcher watchdog stops the workload once
`now > expires_at + grace`. So a lapsed/unrenewed License simply lets the current
one run out — stopping the courier can't extend it, and a still-valid License
can't be forged or stretched (it's Ed25519-signed). For an evaluation that never
needs renewal, set a very large `LICENSE_TTL_SECS` on the Authority.
