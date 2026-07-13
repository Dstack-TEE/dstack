# Common image assembly

`assemble.sh` consumes the versioned manifest in
`../spec/artifact-manifest.schema.json`. It must not inspect a backend build
tree or invoke backend-specific tools such as BitBake.

The assembler creates the partitioned rootfs, metadata, measurement CBOR files,
unified digest, and release archives. Backend exporters may use symlinks for
large local artifacts; all paths recorded in the manifest itself are relative
to the manifest directory.

`mk-image-mr.sh <release.tar.gz>` creates the flattened, rootfs-free
`mr_<digest>.tar.gz` bundle consumed by verifier/KMS image-download endpoints.
Because this is release-format post-processing rather than a Yocto operation,
the helper lives beside the common assembler.

`dstack-image-oci.sh` pushes and lists assembled guest-image directories in an
OCI registry. It is likewise independent of the backend that produced the
image.
