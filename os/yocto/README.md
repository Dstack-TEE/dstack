# Yocto backend for the dstack guest OS

This directory contains the Yocto backend imported from `meta-dstack`.
dstack-owned layers live in `layers/`; external layers and BitBake live in
`deps/` as git submodules.

For the repository-wide OS layout and backend contract, see [`../README.md`](../README.md).

## Reproducible build

Prerequisites: an x86-64 Linux system with Docker installed.

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack
git submodule update --init -- \
  os/yocto/deps/bitbake \
  os/yocto/deps/openembedded-core \
  os/yocto/deps/meta-yocto \
  os/yocto/deps/meta-confidential-compute \
  os/yocto/deps/meta-virtualization \
  os/yocto/deps/meta-openembedded \
  os/yocto/deps/meta-rust-bin \
  os/yocto/deps/meta-security
cd os/yocto/repro-build
./repro-build.sh
```

For an interactive build, source `dev-setup` and use the Makefile, or run the
repository entrypoint `./os/build.sh --backend yocto` from the repository root.

## Output boundary

`scripts/export-artifacts.sh` converts BitBake deployment paths to the common
artifact manifest. `mkimage.sh` is a compatibility wrapper that exports the
manifest and calls `../image/assemble.sh`.

## License

The imported backend retains the Business Source License 1.1 terms in
[`LICENSE`](LICENSE). Embedded components may have their own notices.
