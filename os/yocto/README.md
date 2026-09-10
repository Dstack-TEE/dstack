# Yocto backend for the dstack guest OS

This directory contains the Yocto backend imported from `meta-dstack`.
dstack-owned layers live in `layers/`; external layers and BitBake live in
`deps/` as git submodules.

For the repository-wide OS layout and backend contract, see [`../README.md`](../README.md).

## Reproducible build

From the repository root, the tested one-build entrypoint is:

```bash
make os-image
```

Use `make os-repro-check` to build twice and compare release outputs. The full
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

## CoCo/Kata Kubernetes smoke test

The Yocto rootfs includes the CoCo guest components and Kata agent integration.
See the [CoCo/Kata Kubernetes test guide](../../docs/coco-k8s-testing.md) for a
Kata TDX smoke-test workflow.

## Output boundary

`scripts/export-artifacts.sh` converts BitBake deployment paths to the common
artifact manifest. `mkimage.sh` is a compatibility wrapper that exports the
manifest and calls `../image/assemble.sh`.

## License

The dstack-owned backend code is Apache-2.0. Embedded and third-party
components retain their own license declarations and notices.
