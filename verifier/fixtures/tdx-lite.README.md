# TDX lite attestation fixture

This fixture was captured from the local meta-dstack e2e stack using TDX
`tdx_attestation_variant = "lite"`. It covers the KMS/verifier path that
verifies the OS image from `vm_config.tdx_measurement`, without downloading the
image and without running the QEMU ACPI table helper.

Files:

- `tdx-lite-attestation.json`: verifier input that mimics the KMS
  `GetAppKey` flow. It contains a stripped `attestation` plus the explicit
  `vm_config` carrying `tdx_measurement`.
- `tdx-lite-getquote.json`: raw guest-agent `GetQuoteResponse` captured
  via `GetAttestationForAppKey`, including quote, event log, vm_config, and the
  full versioned attestation.

Captured with:

```bash
E2E_APP_TIMEOUT=900 ./e2e/run.sh up \
  --image-dir images \
  --image dstack-0.6.0 \
  --apps 1 \
  --force \
  --kms-image-verify \
  --kms-no-qemu
```

Important fixture properties:

- `vm_config.tdx_attestation_variant = "lite"`
- `vm_config.memory_size = 2147483648` (2 GiB)
- `vm_config.os_image_hash = 66dbf8143cdc3b3505a0a1c0b7c6add55bddbd86ef65b1c9eb9ecbab880d736c`
- The top-level `event_log` and stripped attestation keep the three RTMR0
  `ACPI DATA` digests and marker payloads needed by the lite verifier, plus
  RTMR3 runtime events.

To verify without image download, use a config whose download URL is unreachable;
the lite verifier should still pass:

```toml
address = "127.0.0.1"
port = 0
image_cache_dir = "/tmp/dstack-verifier-tdx-lite-fixture-cache"
image_download_url = "http://127.0.0.1:9/should-not-download/{OS_IMAGE_HASH}.tar.gz"
image_download_timeout_secs = 1
```

Then run:

```bash
dstack-verifier --config verifier-no-download.toml \
  --verify verifier/fixtures/tdx-lite-attestation.json
```

Expected result: `Valid: true`, with quote, event log, and OS image hash all
verified.
