# KMS Deploy Template

This template is committed because `on-prem/gcp/deploy/` is per-customer state.

Vendor fills once before publishing the template:

- `docker-compose.yaml`: replace `<PINNED_KEY_BROKER_DIGEST>` and `<PINNED_DSTACK_KMS_DIGEST>` with literal sha256 hex digests.
- `docker-compose.yaml`: replace `<PINNED_LITERAL_BASE64_AUTHORITY_PUBKEY>` with the literal authority Ed25519 public key.
- `app.json`: set OS image, bucket, machine type, and any fixed non-customer defaults.

Customer/runtime values are not written into the measured compose. `prelaunch.sh`
resolves `DSTACK_REGISTRY` and `SWP_PROXY`, validates them with anchored regexes,
and writes `/dstack/.env` without modifying `docker-compose.yaml`. Docker compose reads that `.env` when
`app-compose.sh` later runs `docker compose up` from `/dstack`.

Example `user_config` JSON:

```json
{
  "DSTACK_REGISTRY": "us-central1-docker.pkg.dev/acme-prod/dstack-private",
  "SWP_PROXY": "10.128.0.53:80"
}
```

If `DSTACK_REGISTRY` is omitted, prelaunch derives it from GCP metadata:
`<region>-docker.pkg.dev/<project>/<ar-repo>`, where `ar-repo` defaults to
`dstack-private`.
