# TDX lite attestation fixture

This fixture was captured from the local meta-dstack e2e stack using TDX
`tdx_attestation_variant = "lite"`. It covers the KMS/verifier path that
verifies the OS image from `vm_config.tdx_measurement` (`sha256sum.txt` bytes
plus `measurement.tdx.cbor` bytes), without downloading the image. The ACPI
tables are regenerated in-process from the VM shape, so no QEMU is involved.

Files:

- `tdx-lite-attestation.json`: verifier input that mimics the KMS
  `GetAppKey` flow. It contains a stripped `attestation` whose embedded
  `vm_config` carries `tdx_measurement`.
- `tdx-lite-getquote.json`: raw guest-agent `GetQuoteResponse`, including
  quote, event log, and vm_config -- the shape `DstackGuest.GetQuote` returns.
  `GetQuoteResponse` is Intel TDX only and carries no versioned attestation;
  use `Attest` for the platform-adaptive form.

Recaptured for measurement document version 4, which replaced the command-line
digest with the command line itself. The original capture predates that, and a
digest cannot be turned back into the string the new document needs, so these
two files were retaken from a fresh boot rather than re-encoded.

The image is a pre-normalization one, taken as built: the build system
hardcodes `kernel_header_normalized: true` and fails when the OVMF patch does
not apply, so it can no longer produce the image this pair exercises. Only its
derived `measurement.tdx.cbor`, `sha256sum.txt` and `digest.txt` were
regenerated with the current `dstack-mr`, which is why `os_image_hash` moved.

```bash
# 1. regenerate the derived measurement material in a copy of the image dir
dstack-mr tdx-measurement-cbor "$IMAGE_DIR" > "$IMAGE_DIR/measurement.tdx.cbor"
#    then refresh that file's sha256sum.txt line and digest.txt

# 2. boot it, with an app-compose prelaunch script that calls the guest agent
dstack-vmm -c vmm.toml
vmm-cli.py compose --key-provider none --prelaunch-script capture.sh ...
vmm-cli.py deploy --image "$IMAGE_NAME" --vcpu 2 --memory 2G ...

# 3. capture.sh, inside the guest
curl -s --unix-socket /var/run/dstack.sock "http://localhost/GetQuote?report_data=$RD"
curl -s --unix-socket /var/run/dstack.sock "http://localhost/Attest?report_data=$RD"
```

`report_data` is 64 bytes of `0x42`, matching `tests/e2e/attestation`.

Important fixture properties:

- `vm_config.tdx_attestation_variant = "lite"`
- `vm_config.memory_size = 2147483648` (2 GiB), `vm_config.cpu_count = 2`
- `vm_config.os_image_hash = 1440bbf5b3a79bcef4bb6013d82d52c12d53fe8d19c21c65fb6b636865179ca1`
- `vm_config.tdx_measurement.measurement` is a version 4 document, and its
  `image.kernel_header_normalized` is absent, i.e. false.
- `vm_config.tdx_measurement.{checksum_file,measurement}` are JSON base64 byte
  strings.
- The raw top-level `event_log` and stripped attestation keep the three named
  RTMR0 `ACPI DATA` digests (`acpi-loader`, `acpi-rsdp`, `acpi-tables`) and
  marker payloads needed by the lite verifier, plus RTMR3 runtime events.
- When `attestation` is present, dstack-verifier ignores top-level
  `quote`/`event_log`/`vm_config`; the attestation's embedded config is the
  single source of truth. The raw quote path should omit `attestation` and pass
  `quote` + `event_log` + `vm_config` instead.

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

Expected result: `Valid: true`, with quote, event log, OS image hash, and ACPI
tables all verified. The ACPI digests are regenerated in-process from the
fixture's VM shape (2 vCPUs, 2 GiB, QEMU 8.2.2) and must equal the ones the
captured CVM reported.

## Normalized kernel header fixture

`tdx-lite-normalized-attestation.json` covers the other kernel measurement.
Images whose OVMF normalizes the Linux setup header declare
`"kernel_header_normalized": true` in `metadata.json`, which is mirrored into
the measurement document, and their RTMR[1] is the plain Authenticode hash of the shipped
`bzImage`. The two fixtures above cover the pre-normalization behavior, which
every image built before that landed still has.

Both normalized fixtures keep their original captures. Their measurement
documents were re-encoded to version 4 in place: the command line that rebuilt
them was confirmed by reproducing the version 3 digest exactly, and the quote,
event log and every RTMR are untouched, because the measured command line did
not change. `sha256sum.txt` and `os_image_hash` moved with the document.

`tdx-lite-normalized-qemu-10-2-attestation.json` is the **same image** captured
on **QEMU 10.2.1**, a version that does *not* rewrite the header. The pair is
the point of the whole change:

| | QEMU 8.2.2 | QEMU 10.2.1 | |
| --- | --- | --- | --- |
| MRTD | `78cb3ad7...` | `8ed3f63f...` | differ -- page-add ordering |
| RTMR0 | `68102e7b...` | `131221a6...` | differ -- generated ACPI tables |
| **RTMR1** | `60db95c7...` | `60db95c7...` | **identical** |
| RTMR2 | `f873ce9b...` | `f873ce9b...` | identical |

8.2.2 is the load-bearing one: it *does* rewrite the header, so that capture
only passes if the firmware actually undid the rewrite rather than merely
agreeing with itself. 10.2.1 then shows the digest did not move.

- quote, event log and RTMR3 runtime events come from one boot of that CVM
- the event log replays to exactly the RTMR values in the quote
- `dstack-mr measure --cpu 1 --memory 2G --qemu-version 8.2.2` over that image
  directory reproduces MRTD, RTMR[0], RTMR[1] and RTMR[2]. It reads
  `kernel_header_normalized` from the image's `metadata.json`, so pointing it at
  a pre-normalization image is expected to give a different RTMR[1]:

```
MRTD  78cb3ad7...316606fb
RTMR0 68102e7b...f07ffe96
RTMR1 60db95c7...8f79d200   <- Authenticode SHA-384 of the shipped bzImage
RTMR2 f873ce9b...05793535
```

Captured with `tools/vm-runner` against an image whose `ovmf.fd` carries
`0007-OvmfPkg-QemuKernelLoaderFsDxe-normalize-setup-header.patch`. The CVM ran
with no key provider (`kms_enabled` and `local_key_provider_enabled` both
false), which makes the guest mint temporary app keys and boot all the way
through without any external service, and a `pre_launch_script` handed the quote
and the event log back over `notify-host` -- the host-shared 9p mount is
read-only inside the guest.
