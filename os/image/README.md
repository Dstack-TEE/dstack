# Common image assembly

`assemble.sh` consumes the versioned manifest in
`../spec/artifact-manifest.schema.json`. It must not inspect a backend build
tree or invoke backend-specific tools such as BitBake.

The assembler creates the partitioned rootfs, metadata, measurement CBOR files,
unified digest, and release archives. Backend exporters may use symlinks for
large local artifacts; all paths recorded in the manifest itself are relative
to the manifest directory.

When a UKI image is built (`ENABLE_UKI_IMAGE=1`), assemble **always** produces:

- `measurement.gcp.cbor` — UKI Authenticode binding for GCP TPM
- `measurement.aws.cbor` — NitroTPM boot binding for AWS EC2
  (`boot_pcr_digest = sha256(PCR4||PCR7||PCR12)`)

Both are listed in `sha256sum.txt`, so
`digest.txt = sha256(sha256sum.txt) = os_image_hash` is fixed at build time.
Deploy tooling (`dstack-cloud prepare`) only **embeds** these files into
`VmConfig`; it must not recompute PCRs (that would change the image identity).

AWS PCR precompute requires a pinned host `nitro-tpm-pcr-compute` binary (Rust,
[aws/NitroTPM-Tools](https://github.com/aws/NitroTPM-Tools)). Set
`NITRO_TPM_PCR_COMPUTE_BIN` or install it on `PATH`, for example with
`cargo install --git https://github.com/aws/NitroTPM-Tools --locked nitro-tpm-pcr-compute`.
If it is missing, UKI assembly fails.

`mk-image-mr.sh <release.tar.gz>` creates the flattened, rootfs-free
`mr_<digest>.tar.gz` bundle consumed by verifier/KMS image-download endpoints.
Because this is release-format post-processing rather than a Yocto operation,
the helper lives beside the common assembler.

`dstack-image-oci.sh` pushes and lists assembled guest-image directories in an
OCI registry. It is likewise independent of the backend that produced the
image.
