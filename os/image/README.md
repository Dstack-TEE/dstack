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
- `measurement.aws.replay.json` — ordered SHA-384 boot-event digests used by
  the development NitroTPM simulator to reproduce PCR4/7/12

All measurement artifacts are listed in `sha256sum.txt`, so
`digest.txt = sha256(sha256sum.txt) = os_image_hash` is fixed at build time.
Deploy tooling (`dstack-cloud prepare`) only **embeds** these files into
`VmConfig`; it must not recompute PCRs (that would change the image identity).

Dev images additionally carry `measurement.gcp.eventlog.bin`, a GCP firmware
event-log template with the assembled UKI Authenticode digest for the vTPM
simulator. This simulator-only fixture is not generated for release images and
is deliberately excluded from `sha256sum.txt`, so it does not affect the
production `os_image_hash`.

AWS PCR precompute requires a pinned host `nitro-tpm-pcr-compute` binary (Rust,
[aws/NitroTPM-Tools](https://github.com/aws/NitroTPM-Tools)). Set
`NITRO_TPM_PCR_COMPUTE_BIN` or install it on `PATH`, for example with
`cargo install --git https://github.com/aws/NitroTPM-Tools --rev d76d6eeebd4169b00a3c3af9858852d48f40e748 --locked nitro-tpm-pcr-compute`
(aws/NitroTPM-Tools v1.1.2).
The assembler captures that pinned tool's per-event debug trace, converts it
to the replay document, and verifies that replaying the events produces the
tool's reported PCR values. If the tool is missing or the replay does not
match, UKI assembly fails.

`mk-image-mr.sh <release.tar.gz>` creates the flattened, rootfs-free
`mr_<digest>.tar.gz` bundle consumed by verifier/KMS image-download endpoints.
Because this is release-format post-processing rather than a Yocto operation,
the helper lives beside the common assembler.

`dstack-image-oci.sh` pushes and lists assembled guest-image directories in an
OCI registry. It is likewise independent of the backend that produced the
image.

## Kernel build tree

The optional `artifacts.kernel_devel` manifest entry is published as
`<name>-<version>-kernel-devel.tar.gz` beside the image archives. It is not in
`sha256sum.txt`, so it does not affect `os_image_hash`. `kernel-builder/`
builds the matching module-builder container image.

## Kernel setup-header normalization

`assemble.sh` runs `normalize-kernel-header.py` over `bzImage` before it
computes any measurement. The shipped kernel therefore differs from the raw
kernel build output, by design.

QEMU is the boot loader for `-kernel`: it fills in the setup-header fields the
Linux boot protocol expects a boot loader to supply (`type_of_loader`,
`ramdisk_image`/`ramdisk_size`, `heap_end_ptr`, `cmd_line_ptr`, ...) and serves
the result over fw_cfg. OVMF measures those bytes into RTMR[1]. QEMU commit
`a7542a38f399` ("x86/loader: Don't update kernel header for CoCo VMs", first
released in 10.2.0) stopped rewriting the header for confidential guests, so
without normalization the same image measures differently depending on the
host's QEMU version — and the host is the one that declares that version.

The fix has two halves that must stay in sync:

- this script fills in those fields in the kernel we ship, with the values
  QEMU <= 10.1 would write;
- `0007-OvmfPkg-QemuKernelLoaderFsDxe-normalize-setup-header.patch` writes the
  same values in OVMF, before the kernel blob is measured and loaded.

The result is that RTMR[1] is the plain Authenticode hash of `bzImage` as
listed in `sha256sum.txt`, on every QEMU version and at every guest memory
size.

Normalizing to QEMU's layout rather than to zeros is what keeps an earlier
release able to verify these images: `dstack-mr` already computes that layout
(`patch_kernel`) for an image that does not declare the flag, so a 0.5.x KMS
can still onboard a 0.6.0 root with image verification on. Recomputing it needs
the guest RAM size, which limits such a verifier to guests with exactly 2 GiB
or at least 2816 MiB -- the one range QEMU places the initrd differently in,
and the range the no-image-download path already excludes. The values are the
ones QEMU writes above that threshold, and the shipped initrd's size is an
input, since it decides `ramdisk_image`.

`assemble.sh` records this in `metadata.json` as `"kernel_header_normalized":
true`. What makes that declaration true is the OVMF half, which the same build
applies -- `ovmf-build.sh` and the bitbake recipe both fail if the patch does
not apply, so an image cannot ship the flag with firmware that ignores it.
Images
without the field are the ones built before this existed; `dstack-mr` measures
those the old way, against QEMU's rewritten header.

The field set comes from the boot protocol, not from QEMU's behavior: every
field `Documentation/arch/x86/boot.rst` types as `write` is one the boot loader
fills in and the kernel supplies no value for. Fields typed `modify` carry real
kernel-supplied values — `code32_start` is the protected-mode entry point — and
are deliberately left alone.

That is safe for every boot path: these are the values QEMU itself wrote for
every release before 10.2, and on the EFI-stub path the real-mode setup code
never runs at all -- the stub takes the initrd through LoadFile2 and the
command line through its load options. The PE headers sit at 0x40..0x170, so no
setup-header field overlaps them and the EFI entry point is untouched.

To check an image without modifying it:

```bash
./normalize-kernel-header.py --check /path/to/bzImage /path/to/initramfs.cpio.gz
```
