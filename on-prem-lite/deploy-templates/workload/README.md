<!-- SPDX-License-Identifier: Apache-2.0 -->
# Lite Workload Deploy Template (single CVM, no KMS)

A single-CVM template that boots **only the lite launcher**. The launcher pulls and
runs the encrypted workload image itself *after* a License is installed
(`license-ctl attest`) — that's why the workload image is **not** in this compose.

The disk is sealed by the CVM's vTPM (`key_provider: tpm`); there is no KMS CVM and
no `kms_urls`.

Vendor fills once for this workload (these become **measured** values in the launcher's
`compose_hash`):

- `docker-compose.yaml`: replace `<PINNED_LITE_LAUNCHER_DIGEST>` with the literal
  `lite-launcher` image sha256 hex digest.
- `docker-compose.yaml`: set `LITE_AUTHORITY_PUBKEY=<PINNED_LITERAL_BASE64_AUTHORITY_PUBKEY>`
  — the vendor Authority's Ed25519 License-signing **public** key, base64, as a literal
  (the launcher pins it to verify License signatures; G8).
- `docker-compose.yaml` + `app.json`: replace `<WORKLOAD_APP_ID_40_HEX>` with the app id
  (40 hex) the Authority assigned this app. The launcher checks `License.app_id == its own`
  (G6b) and the Authority scopes `allowed_workload_digests` under it.

Operator fills per deployment in `app.json` (not measured): `<GCP_PROJECT>`,
`<GCP_ZONE>`, `instance_name`, `<DSTACK_BUCKET>`, `<WORKLOAD_INTERNAL_IP>`.

Runtime values are not written into the measured compose. `prelaunch.sh` resolves only
`DSTACK_REGISTRY` (validated with an anchored regex) and writes `/dstack/.env` without
touching `docker-compose.yaml`. `LITE_PORT` (9000) is the plain-HTTP courier port the
operator's `license-ctl` reaches over an IAP tunnel; `LITE_STATE_DIR` holds the installed
License `seq` high-water for anti-rollback.

Example `user_config` JSON:

```json
{
  "DSTACK_REGISTRY": "us-central1-docker.pkg.dev/acme-prod/dstack-private"
}
```

If `DSTACK_REGISTRY` is omitted, prelaunch derives it from GCP metadata:
`<region>-docker.pkg.dev/<project>/<ar-repo>`, where `ar-repo` defaults to `dstack-private`.
