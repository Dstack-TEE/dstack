# Workload Deploy Template

This template is committed because `on-prem/gcp/deploy/` is per-customer state.

Vendor fills once for this workload:

- `docker-compose.yaml`: replace `<PINNED_LAUNCHER_DIGEST>` with the literal launcher image sha256 hex digest.
- `docker-compose.yaml`: replace `<WORKLOAD_APP_ID_40_HEX>` and `<WORKLOAD_IMAGE_NAME>` with the workload's stable app id and image path suffix.
- `app.json`: use the same `<WORKLOAD_APP_ID_40_HEX>` and set fixed deployment defaults.

Customer/runtime values are not written into the measured compose. `prelaunch.sh`
resolves `DSTACK_REGISTRY` and `KMS_HOST`, validates them with anchored regexes,
and writes `/dstack/.env` without modifying `docker-compose.yaml`. Docker compose reads that `.env` when
`app-compose.sh` later runs `docker compose up` from `/dstack`.

Example `user_config` JSON:

```json
{
  "DSTACK_REGISTRY": "us-central1-docker.pkg.dev/acme-prod/dstack-private",
  "KMS_HOST": "10.128.15.220"
}
```

If `DSTACK_REGISTRY` is omitted, prelaunch derives it from GCP metadata:
`<region>-docker.pkg.dev/<project>/<ar-repo>`, where `ar-repo` defaults to
`dstack-private`.
