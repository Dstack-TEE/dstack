# Yocto backend for the dstack guest OS (deprecated)

> [!WARNING]
> **This backend is deprecated.** Use the mkosi backend in
> [`../mkosi/`](../mkosi/README.md) (`make os-image`) instead. The Yocto backend
> is kept only so existing Yocto-built images can still be rebuilt and verified,
> and it will be removed. Do not build new images with it, add features to it,
> or treat it as the reference implementation. Its entrypoints print a
> deprecation warning.

> [!CAUTION]
> **Do not delete this directory yet.** The mkosi backend
> still reads files from `os/yocto/layers/` and `os/yocto/tools/` as live build
> inputs: kernel, OVMF and ZFS patches, the initramfs `init` script, several
> systemd units and configuration files, the AWS hardening audit script, and
> the version and parity references checked by `os/mkosi/tests/acceptance.sh`.
> A change to one of those files changes the default mkosi image, and removing
> them breaks it. Move a file into `os/common/` or `os/mkosi/` before retiring
> it from the Yocto tree. `grep -rn yocto os/mkosi` lists the current uses.

This directory contains the Yocto backend imported from `meta-dstack`.
dstack-owned layers live in `layers/`; external layers and BitBake live in
`deps/` as git submodules.

For the repository-wide OS layout and backend contract, see [`../README.md`](../README.md).

## Reproducible build

From the repository root, the legacy one-build entrypoint is:

```bash
make os-image-yocto
```

Use `make os-repro-check-yocto` to build twice and compare release outputs. The full
prerequisite, output, verification, flavor, incremental-build, and
troubleshooting instructions are in the
[guest-OS build guide](../../docs/building-guest-os.md).

For an interactive native build, source `dev-setup` and use this directory's
Makefile, or run the repository entrypoint `./os/build.sh --backend yocto`.

The supported backend script only builds guest images. The backend-specific
`tools/` directory contains only host workarounds needed while building Yocto.
Historical all-in-one host-stack and direct-QEMU helpers are isolated under
[`../../tools/`](../../tools/); they are not added to `PATH` and do not shadow
the supported Rust `dstack` CLI.

## Output boundary

`scripts/export-artifacts.sh` converts BitBake deployment paths to the common
artifact manifest. `mkimage.sh` is a compatibility wrapper that exports the
manifest and calls `../image/assemble.sh`.

## License

The dstack-owned backend code is Apache-2.0. Embedded and third-party
components retain their own license declarations and notices.
