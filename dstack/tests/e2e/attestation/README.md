# Attestation Docker Compose E2E

This test runs the complete attestation flow in privileged Docker containers,
without starting a VM:

```text
dstack-tee-simulator -> dstack-util attest -> dstack-verifier
```

The simulator and verifier use development trust anchors derived from the same
test seed. Verification still follows the normal production verification paths;
there is no mock-certificate bypass in the verifier.

## Covered platforms

The Compose suite runs these six cases:

- dstack TDX, legacy attestation selector
- dstack TDX, lite attestation selector
- GCP TDX with a simulated vTPM
- AMD SEV-SNP
- AWS Nitro Enclave
- AWS NitroTPM

Every case must produce all of the following results:

```text
is_valid=true
quote_verified=true
event_log_verified=true
os_image_hash_verified=true
```

## Requirements

- Linux host
- Docker with the Compose plugin
- Permission to run privileged containers
- Host kernel modules available through `/lib/modules`
- A kernel providing:
  - FUSE and CUSE support
  - `tpm_vtpm_proxy` (`CONFIG_TCG_VTPM_PROXY`) for the GCP vTPM case

The script loads `tpm_vtpm_proxy` on demand. The Docker daemon therefore needs
access to a `/lib/modules` tree matching the running host kernel.

## Run the complete suite

From the `dstack/` directory:

```bash
./tests/e2e/attestation/run.sh
```

The wrapper builds the local image, runs all six services sequentially, and
removes Compose resources afterward.

## Run one case

From this directory:

```bash
cd tests/e2e/attestation
docker compose build
docker compose run --rm dstack-tdx-legacy
docker compose run --rm dstack-tdx-lite
docker compose run --rm gcp-tdx
docker compose run --rm amd-sev-snp
docker compose run --rm aws-nitro-enclave
docker compose run --rm aws-nitro-tpm
```

To clean up manually:

```bash
docker compose down --remove-orphans
```

## What the test configures

`run-platform.sh` creates a temporary sys-config inside each container. It
selects the simulator platform and supplies the corresponding image measurement
material:

| Case | Image binding material |
| --- | --- |
| TDX legacy/lite | `tdx_measurement`, VM parameters, and the CCEL ACPI event digests |
| GCP TDX | `gcp_measurement` bound to the UKI Authenticode event and vTPM PCRs |
| AMD SEV-SNP | `sev_snp_measurement` and `mr_config`, bound to report `MEASUREMENT` and `HOST_DATA` |
| Nitro Enclave | NSM-signed PCR0/1/2 |
| NitroTPM | `aws_measurement` bound to NSM-signed PCR4/7/12 |

The TDX simulator exposes the repository CCEL fixture through the normal TSM
configfs ABI. The GCP case exposes a TPM event log through
`/sys/kernel/security/tpm0/binary_bios_measurements` and replays it into
`swtpm`, so the quoted PCRs and event log remain consistent.

The NitroTPM case exposes a kernel vTPM device backed by `swtpm`. Its proxy
implements AWS's NSM vendor command on the TPM wire protocol; the attestation
client therefore follows the same EK, salted session, authenticated NV buffer,
and vendor-command path used on real NitroTPM hardware. It does not expose or
fall back to `/dev/nsm`.

Development root certificates are written as files and configured in
`verifier.toml`. The test explicitly enables
`insecure_allow_external_trust_anchors`; production defaults remain unchanged.

## Troubleshooting

### `modprobe: FATAL: Module tpm_vtpm_proxy not found`

Install modules matching the running kernel or enable
`CONFIG_TCG_VTPM_PROXY` in the host kernel.

### `/dev/nsm` is not created

Ensure the host kernel has CUSE support and that the container is privileged.
The test creates the device node from `/sys/class/cuse/nsm/dev` because no udev
daemon runs inside the container.

### FUSE/configfs permission errors

Confirm that privileged containers are allowed. Rootless Docker is not
supported by this test because it mounts configfs/securityfs and creates device
nodes.

### Inspecting a failure

The per-container working directory is `/run/attestation-e2e`. Before the
container exits, the useful files are:

```text
simulator.log
collateral.log
verifier.log
request.json
request.json.verification.json
verifier.toml
```

For interactive inspection, override the entrypoint and run the platform script
manually:

```bash
docker compose run --rm --entrypoint bash gcp-tdx
TEE_PLATFORM=gcp-tdx /usr/local/bin/run-platform
```
