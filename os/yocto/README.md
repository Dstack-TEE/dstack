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

## Output boundary

`scripts/export-artifacts.sh` converts BitBake deployment paths to the common
artifact manifest. `mkimage.sh` is a compatibility wrapper that exports the
manifest and calls `../image/assemble.sh`.

## License

The imported backend retains the Business Source License 1.1 terms in
[`LICENSE`](LICENSE). Embedded components may have their own notices.
