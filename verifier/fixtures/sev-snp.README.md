# SEV-SNP verifier fixture

This fixture exercises the dstack-verifier AMD SEV-SNP path with the current
split image-measurement material format.

Files:

- `sev-snp-attestation.json`: verifier input containing a self-contained
  `attestation`. The embedded `vm_config` carries `sev_snp_measurement` with
  `checksum_file` and `measurement` as JSON base64 byte strings.

The fixture is derived from the real SEV-SNP attestation under
`dstack-attest/tests/`:

- the signed 1184-byte SNP report and MrConfigV3 document are unchanged;
- the embedded config is normalized to the current
  `sha256sum.txt + measurement.snp.cbor` schema;
- the pinned ASK/VCEK PEMs are embedded in the attestation `cert_chain`, so the
  verifier test is fully offline and does not call AMD KDS.

To verify manually without image download:

```toml
address = "127.0.0.1"
port = 0
image_cache_dir = "/tmp/dstack-verifier-sev-snp-fixture-cache"
image_download_url = "http://127.0.0.1:9/should-not-download/{OS_IMAGE_HASH}.tar.gz"
image_download_timeout_secs = 1
```

```bash
dstack-verifier --config verifier-no-download.toml \
  --verify verifier/fixtures/sev-snp-attestation.json
```

Expected result: `Valid: true`, with quote, event log/app info, and OS image
hash all verified. The cache directory should not be created.
