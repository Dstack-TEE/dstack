# Build the dstack guest OS

This guide builds the bootable dstack guest-OS release artifacts from source.
It is for OS developers, release maintainers, and operators who want a custom
image. You do **not** need to build an image for normal self-hosted onboarding:
`dstackup install` downloads and verifies a published guest-OS release by
default.

## What the build produces

The default `prod` build produces:

- a bare-metal/CVM bundle for Intel TDX and, when the SEV firmware artifact is
  available, AMD SEV-SNP;
- a UKI disk-image bundle for the GCP confidential-VM boot path;
- dm-verity rootfs data, launch-measurement material, checksums, and the unified
  `digest.txt` OS identity.

Yocto is currently the only implemented OS backend. Backend-independent rootfs
payload, artifact contract, measurement, and release packaging live outside
`os/yocto/`; see [`../os/README.md`](../os/README.md).

## Prerequisites

Use an x86-64 Linux host with:

- Git;
- Docker Engine, usable by the current user;
- outbound HTTPS access for Git, Yocto source archives, and Rust crates;
- substantial free disk space for Yocto downloads, work directories, and
  shared-state cache.

TEE hardware is not required to build the image. It is required only when you
boot and attest the resulting image on the corresponding platform.

Check the basics before starting:

```bash
docker version
git --version
df -h .
```

## Quick build

From a fresh checkout:

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack
make os-image
```

`make os-image` initializes only the eight Yocto dependency submodules and
runs one complete production image build in the pinned Ubuntu builder
container. It is equivalent to:

```bash
git submodule update --init --depth 1 -- \
  os/yocto/deps/bitbake \
  os/yocto/deps/openembedded-core \
  os/yocto/deps/meta-yocto \
  os/yocto/deps/meta-confidential-compute \
  os/yocto/deps/meta-virtualization \
  os/yocto/deps/meta-openembedded \
  os/yocto/deps/meta-rust-bin \
  os/yocto/deps/meta-security

cd os/yocto/repro-build
./repro-build.sh -n
```

The first build downloads and compiles the complete Yocto toolchain and guest
userspace, so it is much slower than an incremental rebuild. The `-n` option
means “build once”; it does not skip BitBake or image assembly.

## Outputs

Release archives are written under:

```text
os/yocto/repro-build/dist/
├── dstack-<version>.tar.gz
├── dstack-<version>-uki.tar.gz
└── reproduce.sh
```

`reproduce.sh` is emitted when the source tree is clean. The unpacked build
tree and caches remain under `os/yocto/repro-build/build-a/`.

The bare-metal archive includes the kernel, initramfs, OVMF firmware,
partitioned dm-verity rootfs, platform measurement CBOR files,
`sha256sum.txt`, `digest.txt`, and `metadata.json`. The UKI archive
includes the bootable `disk.raw` plus its identity and measurement files.

Inspect and verify an archive with:

```bash
mkdir -p /tmp/dstack-image
tar -xzf os/yocto/repro-build/dist/dstack-<version>.tar.gz \
  -C /tmp/dstack-image
cd /tmp/dstack-image/dstack-<version>
sha256sum -c sha256sum.txt
test "$(sha256sum sha256sum.txt | awk '{print $1}')" = "$(cat digest.txt)"
```

## Build both production and development flavors

Production is the default. To build both variants once:

```bash
cd os/yocto/repro-build
RELEASE_FLAVORS="prod dev" ./repro-build.sh -n
```

The development archive is named `dstack-dev-<version>.tar.gz` and records
`"is_dev": true` in `metadata.json`.

## Check reproducibility

For a release candidate, omit `-n`:

```bash
make os-repro-check
```

This builds independent `build-a` and `build-b` trees and compares the
release-relevant output allowlist. It takes roughly twice the resources of a
single build. Remove both ignored build trees if you specifically need a
from-scratch comparison:

```bash
rm -rf os/yocto/repro-build/build-a \
       os/yocto/repro-build/build-b \
       os/yocto/repro-build/dist
make os-repro-check
```

## Incremental backend development

The reproducible wrapper is the recommended release path. On a host with the
packages listed in `os/yocto/repro-build/Dockerfile.repro`, the generic
backend entrypoint can also be used directly from the repository root:

```bash
./os/build.sh \
  --backend yocto \
  --flavors prod \
  --build-dir "$PWD/os/yocto/bb-build"
```

This keeps the native BitBake cache in `os/yocto/bb-build/` and writes
assembled images under the repository-root `images/` directory. Build both
flavors with `--flavors "prod dev"`.

The generic entrypoint dispatches to `os/<backend>/build.sh`. A future
backend such as mkosi can implement the same artifact-manifest contract without
changing the common assembler or release consumers.

## Troubleshooting

### A dependency directory is empty

Run:

```bash
make os-deps
git submodule status -- os/yocto/deps
```

Every listed dependency should start with a space, not `-`.

### Docker permission is denied

Ensure `docker version` works as the same non-root user that owns the
checkout. Do not run only part of the build as root; mixed ownership in
`build-a/` makes incremental builds difficult to repair.

### A fetch task fails

Yocto fetches many upstream sources. Preserve `build-a/`, confirm outbound
network and DNS access, then rerun `make os-image`; completed downloads and
tasks are reused.

### The disk fills up

The largest disposable directories are:

```text
os/yocto/repro-build/build-a/
os/yocto/repro-build/build-b/
os/yocto/bb-build/
```

They are ignored by Git and can be removed when no build is running. Keep
`dist/` separately if you need the release archives.

### `reproduce.sh` is missing

The image archives are still valid. The wrapper intentionally skips generating
`reproduce.sh` when `git status --porcelain` reports a dirty source tree,
because that script can reproduce only committed source revisions.
