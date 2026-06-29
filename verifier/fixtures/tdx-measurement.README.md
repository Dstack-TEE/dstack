# TDX measurement-mode attestation fixture

This fixture was captured from the local meta-dstack e2e stack using TDX
`tdx_attestation_variant = "measurement"`. It covers the KMS/verifier path that
verifies the OS image from `vm_config.tdx_measurement`, without downloading the
image and without running the QEMU ACPI table helper.

Files:

- `tdx-measurement-attestation.json`: verifier input that mimics the KMS
  `GetAppKey` flow. It contains a stripped `attestation` plus the explicit
  `vm_config` carrying `tdx_measurement`.
- `tdx-measurement-getquote.json`: raw guest-agent `GetQuoteResponse` captured
  via `GetAttestationForAppKey`, including quote, event log, vm_config, and the
  full versioned attestation.

Captured with:

```bash
E2E_APP_TIMEOUT=900 ./e2e/run.sh up \
  --image dstack-0.6.0 \
  --apps 1 \
  --force \
  --kms-image-verify \
  --kms-no-qemu
```

Important fixture properties:

- `vm_config.tdx_attestation_variant = "measurement"`
- `vm_config.memory_size = 2147483648` (2 GiB)
- `vm_config.os_image_hash = 457c385537cfbc8cca617b672ef395ae0aabb88f0fff1bc53ca887b46475dcc0`
- The stripped attestation keeps the three RTMR0 `ACPI DATA` digests needed by
  the measurement verifier plus RTMR3 runtime events.

To verify without image download, use a config whose download URL is unreachable;
the measurement-mode verifier should still pass:

```toml
address = "127.0.0.1"
port = 0
image_cache_dir = "/tmp/dstack-verifier-tdx-measurement-fixture-cache"
image_download_url = "http://127.0.0.1:9/should-not-download/{OS_IMAGE_HASH}.tar.gz"
image_download_timeout_secs = 1
```

Then run:

```bash
dstack-verifier --config verifier-no-download.toml \
  --verify verifier/fixtures/tdx-measurement-attestation.json
```

Expected result: `Valid: true`, with quote, event log, and OS image hash all
verified.
