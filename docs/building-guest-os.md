# Build the dstack guest OS

This guide builds the bootable dstack guest-OS release artifacts from source.
It is for OS developers, release maintainers, and operators who want a custom
image. You do **not** need to build an image for normal self-hosted onboarding:
`dstackup install` downloads and verifies a published guest-OS release by
default.

> [!IMPORTANT]
> **mkosi is the default and recommended OS backend.** The Yocto backend under
> `os/yocto/` is **deprecated**. It remains only so existing Yocto images can
> still be rebuilt. Do not use it for new images, new features, or release
> work. See [Deprecated: Yocto backend](#deprecated-yocto-backend).
>
> The mkosi build still reads some patches, units, and scripts from
> `os/yocto/`, so that directory must not be deleted yet; see
> [`../os/README.md`](../os/README.md).

## What the build produces

The default `prod` build produces:

- a bare-metal/CVM bundle for Intel TDX and, when the SEV firmware artifact is
  available, AMD SEV-SNP;
- a UKI disk-image bundle for the GCP confidential-VM boot path;
- dm-verity rootfs data, launch-measurement material, checksums, and the unified
  `digest.txt` OS identity.

The mkosi backend lives in `os/mkosi/`. Backend-independent rootfs payload,
artifact contract, measurement, and release packaging live outside the backend;
see [`../os/README.md`](../os/README.md). Backend internals, the
reproducibility model, and the component cache are described in
[`../os/mkosi/README.md`](../os/mkosi/README.md).

## Prerequisites

Use an x86-64 Linux host with:

- Git;
- Docker Engine, usable by the current user, that can run `--privileged`
  containers (mkosi needs loop devices, device-mapper, and mounts);
- outbound HTTPS access for the pinned Debian snapshot, upstream source
  archives, and Rust crates;
- tens of gigabytes of free disk space on a regular filesystem (not overlayfs)
  for the build directory.

No Rust, Go, C, or C++ toolchain is needed on the host; every compiler is pinned
and runs inside mkosi's build overlay.

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

`make os-image` runs one complete, cold production image build in a container
that pins mkosi and the host tools it drives. It needs no submodules and is
equivalent to:

```bash
./os/mkosi/repro-build/repro-build.sh
```

The build refuses to run from a dirty worktree, because the recorded source
revision would not describe the compiled sources. Commit or stash changes
first. (Native `os/mkosi/build.sh` builds also accept `DSTACK_ALLOW_DIRTY=1`,
which records the revision as `-modified`; the containerized build does not
forward it.)

A cold production build takes roughly 30–45 minutes on a 16-job host,
depending mostly on network speed.

## Outputs

Release artifacts are written under:

```text
os/mkosi/repro-build/build/out/prod/
├── dstack-<version>/
├── dstack-<version>.tar.gz
└── dstack-<version>-uki.tar.gz
```

To use a different build directory, run
`./os/mkosi/repro-build/repro-build.sh -o DIR`. When the build finishes it
prints the `os_image_hash` and the SHA-256 of both archives.

The bare-metal archive includes the kernel, initramfs, OVMF firmware,
partitioned dm-verity rootfs, platform measurement CBOR files,
`sha256sum.txt`, `digest.txt`, and `metadata.json`. The UKI archive
includes the bootable `disk.raw` plus its identity and measurement files.

Inspect and verify an archive with:

```bash
mkdir -p /tmp/dstack-image
tar -xzf os/mkosi/repro-build/build/out/prod/dstack-<version>.tar.gz \
  -C /tmp/dstack-image
cd /tmp/dstack-image/dstack-<version>
sha256sum -c sha256sum.txt
test "$(sha256sum sha256sum.txt | awk '{print $1}')" = "$(cat digest.txt)"
```

## Build both production and development flavors

Production is the default. To build both variants once:

```bash
FLAVORS="prod dev" ./os/mkosi/repro-build/repro-build.sh
```

The development archive is written to `out/dev/dstack-dev-<version>.tar.gz`
and records `"is_dev": true` in `metadata.json`.

## Check reproducibility

For a release candidate:

```bash
make os-repro-check
```

This performs two cold production builds in different build paths and with
different job counts, then compares both release archives byte for byte. It
takes roughly twice the resources of a single build. The first leg's artifacts
remain under `os/mkosi/repro-build/build/a/`.

## Incremental backend development

The containerized build is the recommended release path. On a host with the
pinned mkosi version (see `MKOSI_VERSION` in `os/mkosi/versions.env`) and the
packages reported by `mkosi --directory os/mkosi dependencies`, and with root
privileges (or a working user namespace), the backend can be driven directly:

```bash
./os/mkosi/build.sh lint                                  # static contract, seconds
./os/mkosi/build.sh image "$PWD/os/mkosi/build"           # cached iteration build
./os/mkosi/build.sh --no-cache image "$PWD/os/mkosi/build"  # cold build
./os/build.sh --flavors "prod dev" --build-dir "$PWD/os/mkosi/build"
```

A native `image` build reuses a component-output cache by default and skips the
release tarballs; `disk.raw`, the measurements, and `metadata.json` are still
produced. Pass `--archive` to get the tarballs from a cached build, or
`--no-cache` for a release-equivalent cold build. See
[`../os/mkosi/README.md`](../os/mkosi/README.md) for cache details.

The generic entrypoint `os/build.sh` dispatches to `os/<backend>/build.sh` and
defaults to `mkosi`.

## Troubleshooting

### Docker permission is denied

Ensure `docker version` works as the same non-root user that owns the
checkout. The build container runs privileged and hands ownership of the build
directory back to the calling user when it exits.

### The workspace is on overlayfs

mkosi assembles its build root as an overlayfs, which cannot be stacked on
another overlayfs. Choose a build directory on a regular filesystem with
`./os/mkosi/repro-build/repro-build.sh -o DIR`.

### A fetch fails

Confirm outbound network and DNS access, then rerun the same command. Package
downloads come from an immutable Debian snapshot, so a retry fetches identical
content.

### The disk fills up

The disposable build directories are:

```text
os/mkosi/repro-build/build/
os/mkosi/build/
~/.cache/dstack/mkosi-dev/        # native component cache
```

They are ignored by Git (or live outside the checkout) and can be removed when
no build is running. Copy the release archives elsewhere first if you need
them.

## Deprecated: Yocto backend

> [!WARNING]
> The Yocto backend is deprecated and will be removed. Do not use it for new
> images or releases, and do not add features to it. Every build entrypoint
> prints a deprecation warning. Files under `os/yocto/` that the mkosi build
> still reads remain live inputs of the default image until they are moved.

The Yocto backend is kept only so existing Yocto-built images can still be
rebuilt and verified. Its entrypoints have moved to explicitly named targets:

| Deprecated command | Replacement |
|--------------------|-------------|
| `make os-image-yocto` | `make os-image` |
| `make os-repro-check-yocto` | `make os-repro-check` |
| `make os-yocto` / `./os/build.sh --backend yocto` | `make os` / `./os/build.sh` |
| `make os-deps` | not needed; mkosi uses no submodules |

`make os-image-yocto` initializes the eight Yocto dependency submodules and runs
`os/yocto/repro-build/repro-build.sh -n` in its pinned Ubuntu builder container.
Archives are written to `os/yocto/repro-build/dist/`; use
`RELEASE_FLAVORS="prod dev"` to build both flavors. See
[`../os/yocto/README.md`](../os/yocto/README.md) for the remaining details.
