# dstack ACPI reference image

This directory builds the production QEMU compatibility fork at revision
`9de6fdfff3a84103b83ca6b2e8c4fb8e05cf9195` with its test-only
`DUMP_ACPI_TABLES` mode. The resulting command writes QEMU's 128 KiB
`etc/acpi/tables` blob to standard output and exits without starting a VM.

The image is a differential-test oracle only. Production Rust code does not
depend on it. The source revision and GPL license are recorded as OCI labels;
the corresponding source is available from the repository and revision named
in the labels.

Build locally with:

```sh
docker build -t kvin/dstack-acpi-tables:qemu-11.1 \
  -f dstack/crates/qemu-acpi/reference/Dockerfile .
```
