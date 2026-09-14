# dstack guest OS

The `os/` tree separates the guest-OS contract from the implementation used to
produce it.

```text
os/
├── build.sh                  # backend selector
├── common/rootfs/            # backend-independent guest payload
├── common/scripts/           # checks both backends run
├── image/                    # backend-independent release assembler
├── spec/                     # versioned backend artifact contract
├── mkosi/                    # default, recommended Debian/mkosi backend
└── yocto/                    # DEPRECATED backend; do not use for new work
    ├── deps/                 # external Yocto layers (git submodules)
    ├── layers/               # dstack-owned Yocto layers
    └── tools/                # Yocto-specific host workarounds
```

> [!IMPORTANT]
> **mkosi is the default and recommended backend.** The Yocto backend is
> **deprecated**: it is kept only so existing Yocto images can still be rebuilt,
> and it will be removed. Do not build new images with it, add features to it,
> or port changes to it unless you are maintaining a legacy image.

> [!CAUTION]
> **Do not delete `os/yocto/` yet.** The mkosi backend
> still reads files from `os/yocto/layers/` and `os/yocto/tools/` as live build
> inputs: kernel, OVMF and ZFS patches, the initramfs `init` script, several
> systemd units and configuration files, the AWS hardening audit script, and
> the version and parity references checked by `os/mkosi/tests/acceptance.sh`.
> A change to one of those files changes the default mkosi image, and removing
> them breaks it. Move a file into `os/common/` or `os/mkosi/` before retiring
> it from the Yocto tree. `grep -rn yocto os/mkosi` lists the current uses.

A backend can be added at `os/<backend>/` without moving shared payload or
duplicating release packaging. Both backends implement the same
artifact-manifest and common release-assembly contract; see
[`mkosi/README.md`](mkosi/README.md) for the mkosi backend's scope and
acceptance criteria.

## Build

For a first production build from a fresh checkout, use the repository-level
target:

```bash
make os-image
```

It runs a complete mkosi build inside the pinned builder container; no
submodules are needed. See [Build the dstack guest OS](../docs/building-guest-os.md)
for prerequisites, output verification, flavor selection, reproducibility
checking, incremental development, and troubleshooting.

The lower-level native backend interface remains available and defaults to
mkosi:

```bash
./os/build.sh --build-dir "$PWD/os/mkosi/build"
```

`--flavors "prod dev"` selects image flavors. Native builds require the pinned
mkosi version and its host dependencies; see [`mkosi/README.md`](mkosi/README.md).

The deprecated Yocto backend is reachable only through explicitly named
entrypoints (`make os-image-yocto`, `./os/build.sh --backend yocto`), each of
which prints a deprecation warning.

## Backend contract

Each backend has two boundaries:

1. `os/<backend>/build.sh image [build-dir]` builds native artifacts.
2. The backend exports `os/spec/artifact-manifest.schema.json` version 1 and
   calls `os/image/assemble.sh --manifest <path>`.

Artifact paths in a manifest are relative to the manifest. The common assembler
owns partitioned disk creation, release metadata, TDX/SNP/GCP measurement
material, checksums, and tarballs. Backends own how the kernel, initramfs,
firmware, dm-verity rootfs, and optional UKI are built.

The mkosi backend exports its manifest from `mkosi.postoutput`; the deprecated
Yocto backend does so in `os/yocto/scripts/export-artifacts.sh`. Both hand the
manifest to `../image/assemble.sh` for backend-independent packaging.

## Source boundaries

Neither backend depends on a nested dstack submodule. The mkosi backend mounts
the repository as an ephemeral mkosi build source, so build scripts cannot
mutate the checkout; its component descriptors declare which paths feed each
component's cache key. The deprecated Yocto guest recipe stages only the inputs
it needs:

- `dstack/` for core Rust services,
- `sdk/rust/` for public Rust SDK workspace members,
- `os/common/rootfs/` for OS-owned payload.

## Licensing

The dstack-owned core, SDK, documentation, tools, guest payload, OS backends,
and image-assembly code are Apache-2.0. Individual vendored recipes, patches,
and embedded components may carry their own notices; moving them into this
repository does not relicense them.
