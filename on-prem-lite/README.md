<!-- SPDX-License-Identifier: Apache-2.0 -->
# on-prem-lite — KMS-less single-CVM licensed workload

A simpler profile of [`on-prem`](../on-prem): **no KMS CVM, no key-broker**. One workload
CVM runs the *lite launcher*, which terminates the courier, attests (TDX+vTPM), and gets
back **one image CEK + one signed License** for exactly the workload it asks for. The disk
is vTPM-sealed (`key_provider=tpm`), so no KMS is needed to derive keys; the License has an
expiry and the launcher stops the workload when it lapses. See **[DESIGN.md](DESIGN.md)**
for the full protocol, the License schema, and the fail-closed gate table.

## Directory map

| Path | What |
|---|---|
| `authority/` | vendor Authority (FastAPI): `/challenge`, `/license`, admin; reuses the `on-prem` HPKE + Ed25519 + `dstack-verifier` conventions |
| `cli/license-ctl.py` | operator courier CLI: `attest`/`issue`, `renew`, `status`, `healthz` |
| `launcher/` | the lite launcher (Rust): courier HTTP server, attest, License verify + CEK unseal, decrypt + run workload, expiry watchdog |
| `deploy-templates/workload/` | single-CVM compose + `app.json` (`key_provider=tpm`) with `AUTHORITY_PUBKEY` + `app_id` pinned literal |

This profile reuses `on-prem`'s **image-encryption** (skopeo / ocicrypt JWE, asymmetric
EC P-256 keyring) and the **HPKE (RFC 9180 DHKEM-X25519) + Ed25519** wire conventions —
the Python signer and the Rust launcher verifier interop on canonical JSON (sorted keys,
compact separators) exactly as in `on-prem`.

## Quick flow

**Vendor (once per release / workload):**

1. Run the Authority (`authority/`); it generates / loads its Ed25519 signing key and
   prints `AUTHORITY_PUBKEY` (base64).
2. Mint a global image key (`kid`, EC P-256) for the keyring — reused across workloads.
3. Encrypt the workload container (skopeo JWE to the keyring public key) and push it to the
   registry; note its `sha256:` digest.
4. Create the tenant and the app (`app_id`, 40 hex) on the Authority.
5. Register the workload digest under that app's `allowed_workload_digests` (and the
   launcher build under `allowed_launcher_digests`).
6. Pin `AUTHORITY_PUBKEY`, the `lite-launcher` digest, and `app_id` into
   `deploy-templates/workload/docker-compose.yaml` (these are **measured** into the
   launcher's `compose_hash`).

**Operator (per deployment):**

1. Fill the per-deployment placeholders in `deploy-templates/workload/app.json` (project,
   zone, bucket, instance name, private IP) and deploy the **single workload CVM**.
2. License it:

   ```bash
   cli/license-ctl.py attest \
     --launcher-url http://localhost:9000 \   # over an IAP tunnel to the CVM
     --authority-url https://authority.example.com \
     --user-id acme --app-id <APP_ID_40_HEX> \
     --workload-digest sha256:… --api-key <TENANT_API_KEY>
   ```

   The launcher attests, the Authority verifies and returns `{license, sealed_cek}`, the
   launcher opens the CEK, decrypts the image, and runs the workload.
3. **Renew / update** by re-running the same call — `license-ctl.py renew` (or `attest`)
   issues a fresh License with a higher `seq`, a later `expires_at`, and optionally a new
   `--workload-digest` for a rolling update. Check liveness with `license-ctl.py status`.

For evaluation, set a very long `LICENSE_TTL_SECS` on the Authority so no renewal is needed
during the trial.
