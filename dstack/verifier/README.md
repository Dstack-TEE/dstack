# dstack-verifier

A HTTP server that provides dstack quote verification services using the same verification process as the dstack KMS.

## API Endpoints

### POST /verify

Verifies a dstack attestation or quote with the provided data and VM configuration. The body can be grabbed via [getQuote](https://github.com/Dstack-TEE/dstack/blob/next/sdk/curl/api.md#3-get-quote) (Intel TDX only, and not the full evidence on GCP) or [attest](https://github.com/Dstack-TEE/dstack/blob/next/sdk/curl/api.md#7-attest) (any platform).

**Request Body:**
Provide either `attestation` or (`quote` + `event_log` + `vm_config`).

```json
{
  "quote": "hex-encoded-quote",
  "event_log": "hex-encoded-event-log",
  "vm_config": "json-vm-config-string",
}
```
or
```json
{
  "attestation": "hex-encoded-attestation"
}
```

For challenge-response verification, the relying party embeds its own challenge
in the certificate's `report_data` (or the NitroTPM `nonce`) and checks it
against the returned evidence.

**Response:**
```json
{
  "is_valid": true,
  "details": {
    "quote_verified": true,
    "event_log_verified": true,  // See "Verification Process" for semantics
    "os_image_hash_verified": true,
    "acpi_tables_verified": true,         // true only when TDX ACPI table contents are verified
    "os_image_is_dev": false,             // true=dev image, false=prod, null=unknown/N/A
    "os_image_version": "0.5.10",         // dstack OS version, null if unknown
    "tee_variant": "dstack-tdx",   // dstack-tdx | dstack-gcp-tdx | dstack-nitro-enclave | dstack-amd-sev-snp | dstack-aws-nitro-tpm
    "report_data": "hex-encoded-64-byte-report-data",
    "tcb_status": "UpToDate",
    "advisory_ids": [],
    "key_provider": { "name": "kms", "id": "hex-string" },  // decoded; null if absent
    "app_info": {
      "app_id": "hex-string",
      "compose_hash": "hex-string",
      "instance_id": "hex-string",
      "device_id": "hex-string",
      "mrtd": "hex-string",
      "rtmr0": "hex-string",
      "rtmr1": "hex-string",
      "rtmr2": "hex-string",
      "rtmr3": "hex-string",
      "mr_system": "hex-string",
      "mr_aggregated": "hex-string",
      "os_image_hash": "hex-string",
      "key_provider_info": "hex-string"
    },
    "boot_info": {
      "teeVariant": "dstack-aws-nitro-tpm",
      "mrAggregated": "hex-string",
      "osImageHash": "hex-string",
      "mrSystem": "hex-string",
      "appId": "hex-string",
      "composeHash": "hex-string",
      "instanceId": "hex-string",
      "deviceId": "hex-string",
      "keyProviderInfo": "hex-string",
      "tcbStatus": "UpToDate",
      "advisoryIds": []
    }
  },
  "reason": null
}
```

### GET /health

Health check endpoint that returns service status.

**Response:**
```json
{
  "status": "ok",
  "service": "dstack-verifier"
}
```

## Configuration
You usually don't need to edit the config file. Just using the default is fine, unless you need to deploy your cunstomized os images.

### Configuration Options

- `host`: Server bind address (default: "0.0.0.0")
- `port`: Server port (default: 8080)
- `image_cache_dir`: Directory for cached OS images (default: "/tmp/dstack-verifier/cache")
- `image_download_url`: URL template for downloading OS images (default: dstack official releases URL)
- `image_download_timeout_secs`: Download timeout in seconds (default: 300)
- `attestation.urls.pccs`: PCCS URL (default: production PCCS)
- `attestation.urls.amd_kds`: AMD KDS URL (default: AMD production KDS)

### Example Configuration File

```toml
host = "0.0.0.0"
port = 8080
image_cache_dir = "/tmp/dstack-verifier/cache"
image_download_url = "https://download.dstack.org/os-images/mr_{OS_IMAGE_HASH}.tar.gz"
image_download_timeout_secs = 300
[attestation.urls]
# pccs = "https://pccs.phala.network"
# amd_kds = "https://kdsintf.amd.com/vcek/v1"
```

## Usage

### Running with Cargo

```bash
# Run with default config
cargo run --bin dstack-verifier

# Run with custom config file
cargo run --bin dstack-verifier -- --config /path/to/config.toml

# Set via environment variables
DSTACK_VERIFIER_PORT=8080 cargo run --bin dstack-verifier
```

### Verify An RA-TLS Endpoint Certificate

To bind a network endpoint to attestation, verify the endpoint's RA-TLS
certificate instead of trusting DNS, load balancer identity, or a normal Web PKI
certificate alone:

```bash
cargo run --bin dstack-verifier -- --verify-cert endpoint-cert.pem
```

The input may be PEM or DER. On success, the verifier prints JSON and writes the
same result next to the input as `endpoint-cert.pem.ratls-verification.json`.
The verification checks that:

1. the certificate contains a dstack RA-TLS attestation extension;
2. the embedded attestation verifies against the platform root, including AWS
   NitroTPM documents for EC2;
3. the attestation `report_data` is
   `QuoteContentType::RaTlsCert(SubjectPublicKeyInfo)`, so the verified
   attestation is bound to this exact TLS public key; and
4. the reported `app_info.os_image_hash` is bound to the attested boot
   measurement, surfaced as `app_info.os_image_hash_verified`. This binding is
   self-contained (no image download) for AWS NitroTPM, SEV-SNP, Nitro Enclave,
   GCP TDX, and TDX lite. It is reported as `false` for the TDX legacy
   full-image path, which needs an image download that this cert mode does not
   perform — use `/verify` for that path. Only trust `os_image_hash` when
   `os_image_hash_verified` is `true`.

Clients, gateways, or release validators should combine this certificate-level
check with the policy fields emitted by `/verify`: accepted OS image,
`teeVariant`, `mrAggregated`, app compose hash, KMS identity, a
`report_data` challenge, and any deployment-specific endpoint allowlist.

### Running with Docker Compose

```yaml
services:
  dstack-verifier:
    image: dstacktee/dstack-verifier:latest
    ports:
      - "8080:8080"
    restart: unless-stopped
```

Save the docker compose file as `docker-compose.yml` and run `docker compose up -d`.

### Request verification

Grab an attestation or quote from your app. It's depends on your app how to grab it.

```bash
# Grab an attestation from the demo app
curl https://712eab2f507b963e11144ae67218177e93ac2a24-3000.test0.dstack.org:12004/Attest?report_data=0x1234 -o attest.json
```

Send the attestation to the verifier.

```bash
$ curl -s -d @attest.json localhost:8080/verify | jq
```

```bash
# Grab a quote from the demo app
curl https://712eab2f507b963e11144ae67218177e93ac2a24-3000.test0.dstack.org:12004/GetQuote?report_data=0x1234 -o quote.json

```

Send the quote to the verifier.

```bash
$ curl -s -d @quote.json localhost:8080/verify | jq
{
  "is_valid": true,
  "details": {
    "quote_verified": true,
    "event_log_verified": true,
    "os_image_hash_verified": true,
    "acpi_tables_verified": true,
    "report_data": "12340000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "tcb_status": "UpToDate",
    "advisory_ids": [],
    "app_info": {
      "app_id": "e631a04a5d068c0e5ffd8ca60d6574ac99a18bda",
      "compose_hash": "e631a04a5d068c0e5ffd8ca60d6574ac99a18bdaf0417d129d0c4ac52244d40f",
      "instance_id": "712eab2f507b963e11144ae67218177e93ac2a24",
      "device_id": "ee218f44a5f0a9c3233f9cc09f0cd41518f376478127feb989d5cf1292c56a01",
      "mrtd": "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
      "rtmr0": "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",
      "rtmr1": "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
      "rtmr2": "dbf4924c07f5066f3dc6859844184344306aa3263817153dcaee85af97d23e0c0b96efe0731d8865a8747e51b9e351ac",
      "rtmr3": "5e7d8d84317343d28d73031d0be3c75f25facb1b20c9835a44582b8b0115de1acfe2d19350437dbd63846bcc5d7bf328",
      "mr_system": "145010fa227e6c2537ad957c64e4a8486fcbfd8265ddfb359168b59afcff1d05",
      "mr_aggregated": "52f6d7ccbee1bfa870709e8ff489e016e2e5c25a157b7e22ef1ea68fce763694",
      "os_image_hash": "b6420818b356b198bdd70f076079aa0299a20279b87ab33ada7b2770ef432a5a",
      "key_provider_info": "7b226e616d65223a226b6d73222c226964223a223330353933303133303630373261383634386365336430323031303630383261383634386365336430333031303730333432303030343139623234353764643962386161363434366439383066313336666666373831326563643663373737343065656230653238623130643536633063303030323861356236653539646365613330376435383362643166373037363965396331313664663262636662313735386139356438363133653764653163383438326330227d"
    }
  },
  "reason": null
}
```

## Verification Process

The verifier performs the following verification steps:

1. **Quote Verification**: Validates the platform quote using the platform verifier: DCAP for TDX, AMD SNP report verification for SEV-SNP, NSM for Nitro Enclaves, and AWS NitroTPM attestation-document verification for EC2 NitroTPM.
2. **Event Log Verification**: Replays event logs to ensure RTMR/PCR values match and extracts app information. For RTMR3 and AWS NitroTPM PCR14 launch measurements, both the digest and payload integrity are verified. For TDX RTMR 0-2 boot-time measurements, only the digests are verified; the payload content is not validated as dstack does not define semantics for these payloads.
3. **OS Image Hash Verification**:
   - Treats `vm_config` and any attached measurement material as untrusted inputs until they are bound to the hardware quote
   - For the full-image TDX path, downloads or loads the image identified by `os_image_hash`, checks the image checksum manifest, uses dstack-mr to compute expected MRTD/RTMR0-2, and compares them against the verified measurements from the quote
   - For TDX lite, AMD SEV-SNP, and GCP TDX, verifies that `os_image_hash = sha256(sha256sum.txt)`, where `sha256sum.txt` is the image build's checksum manifest (`<sha256>  <relative-file-name>` lines for image files), that the manifest entry for `measurement.tdx.cbor`, `measurement.snp.cbor`, or `measurement.gcp.cbor` matches the supplied measurement material, and that the measurement material replays to the quote's hardware-signed measurements or GCP TPM UKI event
   - For AWS NitroTPM, requires `vm_config.aws_measurement` and verifies that `os_image_hash = sha256(sha256sum.txt)` matches the measurement material and that its `boot_pcr_digest = sha256(PCR4 || PCR7 || PCR12)` matches the attested boot PCRs
4. **Policy Input Construction**: Emits `details.boot_info`, the canonical auth-policy payload shape used by dstack KMS `/bootAuth/app` and `/bootAuth/kms`. This object is only present on successful verification.
5. **Endpoint Certificate Verification**: In `--verify-cert` mode, verifies the
   dstack RA-TLS certificate extension and checks that the attestation
   `report_data` is bound to the certificate SubjectPublicKeyInfo. This is the
   production path for preventing an admin-controlled DNS/LB/proxy endpoint from
   impersonating an attested workload with a different TLS key. It also binds
   `app_info.os_image_hash` to the attested boot measurement and reports the
   result as `app_info.os_image_hash_verified` (self-contained for all platforms
   except the TDX legacy full-image path, which reports `false`).

`details.acpi_tables_verified` is `true` for both TDX paths, which recompute the ACPI table contents and check them against the quote. It is `false` only for non-TDX platforms, where ACPI table verification is not applicable.

All verification steps must pass for the verification to be considered valid.

### TDX ACPI table verification

RTMR0 covers three ACPI blobs QEMU hands to OVMF (`acpi-loader`, `acpi-rsdp`,
`acpi-tables`); `acpi-tables` carries the DSDT, which is AML the guest kernel
executes. Both TDX paths regenerate those blobs from the VM shape declared in
`vm_config` (vCPU count, RAM size, PCI topology, QEMU version) and require the
recomputed digests to equal the ones the quote's event log reports, before
rebuilding the expected RTMR0 from the recomputed values.

Verification fails closed in both directions:

- **digest mismatch** — the tables are not the ones this VM shape produces.
- **cannot generate** — the shape is one the ACPI generator does not model
  (`swtpm = true`, or a QEMU older than 8.0). There is nothing to compare
  against, so the attestation is rejected rather than accepted as unverified.

The second case is deliberate. `swtpm` and `qemu_version` are host-declared
fields that no other measurement independently constrains, so accepting an
unverifiable shape would let a host opt out of the check by declaring one.
CVMs using the TPM key provider (`swtpm = true`) therefore cannot be verified
on either TDX path, which is the pre-existing behavior of the full-image path.

QEMU versions newer than the newest ACPI profile the verifier models are
generated with that profile, so a QEMU upgrade that leaves the ACPI ABI alone
keeps verifying; one that changes it surfaces as a digest mismatch.

### Identifying the deployment

Beyond pass/fail, the result carries a few descriptive fields so a relying party can apply its own policy:

- **`os_image_is_dev`** — `true` for a development OS image, `false` for production. Dev images are built for local testing and are not hardened for production use, so a relying party generally wants to reject them.
- **`os_image_version`** — the dstack OS version (e.g. `0.5.10`), useful for enforcing a minimum version.
- **`tee_variant`** — the TEE variant that produced the verified quote, serialized as `TeeVariant`: `dstack-tdx`, `dstack-gcp-tdx`, `dstack-nitro-enclave`, `dstack-amd-sev-snp`, or `dstack-aws-nitro-tpm`.
- **`acpi_tables_verified`** — whether TDX ACPI table contents were verified. This is useful for relying parties that require `requirements.tdx_measure_acpi_tables = true`.
- **`key_provider`** — the decoded `app_info.key_provider_info` (`{name, id}`); `name` is e.g. `kms` or `local`. A `local` key provider means the CVM is not KMS-backed, which is itself a dev/insecure posture signal. The raw bytes remain in `app_info.key_provider_info`.
- **`boot_info`** — the policy object a relying party should feed to its auth/governance layer. For AWS EC2 NitroTPM this includes `teeVariant = dstack-aws-nitro-tpm`, PCR4/7/12-derived `osImageHash`, PCR14-bound `mrAggregated`, app identity, instance/device identity, and a `tcbStatus` normalized to `UpToDate`.

`os_image_is_dev` and `os_image_version` are read from the image's `metadata.json`, which is part of `sha256sum.txt` and therefore bound to the `os_image_hash` that step 3 verifies against the quote — so they are as trustworthy as the os-image-hash check itself. They are `null` when the platform does not expose them (e.g. GCP TDX / Nitro Enclave) or when the image predates the field (images without `is_dev` are always production).
