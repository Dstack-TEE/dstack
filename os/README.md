# dstack guest OS

The `os/` tree separates the guest-OS contract from the implementation used to
produce it.

```text
os/
├── build.sh                  # backend selector
├── common/rootfs/            # backend-independent guest payload
├── image/                    # backend-independent release assembler
├── spec/                     # versioned backend artifact contract
└── yocto/                    # the currently implemented backend
    ├── deps/                 # external Yocto layers (git submodules)
    ├── layers/               # dstack-owned Yocto layers
    └── tools/                # Yocto-specific host workarounds
```

A future backend can be added at `os/<backend>/` (for example `os/mkosi/`)
without moving shared payload or duplicating release packaging. No mkosi
backend is implemented today.

## Build

For a first production build from a fresh checkout, use the repository-level
target:

```bash
make os-image
```

It initializes only the Yocto dependency submodules and runs a complete build
inside the pinned builder container. See [Build the dstack guest OS](../docs/building-guest-os.md)
for prerequisites, output verification, flavor selection, reproducibility
checking, incremental development, and troubleshooting.

The lower-level native backend interface remains available:

```bash
make os-deps
./os/build.sh --backend yocto --build-dir "$PWD/os/yocto/bb-build"
```

`--flavors "prod dev"` selects image flavors. Native builds require the host
packages listed in `yocto/repro-build/Dockerfile.repro`.

## Backend contract

Each backend has two boundaries:

1. `os/<backend>/build.sh image [build-dir]` builds native artifacts.
2. The backend exports `os/spec/artifact-manifest.schema.json` version 1 and
   calls `os/image/assemble.sh --manifest <path>`.

Artifact paths in a manifest are relative to the manifest. The common assembler
owns partitioned disk creation, release metadata, TDX/SNP/GCP measurement
material, checksums, and tarballs. Backends own how the kernel, initramfs,
firmware, dm-verity rootfs, and optional UKI are built.

The Yocto compatibility entrypoint `os/yocto/mkimage.sh` demonstrates this
split: `scripts/export-artifacts.sh` handles BitBake paths and
`../image/assemble.sh` handles backend-independent packaging.

## Source boundaries

The guest recipe stages only the inputs it needs:

- `dstack/` for core Rust services,
- `sdk/rust/` for public Rust SDK workspace members,
- `os/common/rootfs/` for OS-owned payload.

It does not copy the entire repository or depend on a nested dstack submodule.

## Licensing

The monorepo contains multiple license scopes. Core, SDK, documentation, tools,
and `os/common/rootfs/` remain Apache-2.0. The imported Yocto implementation and
derived image-assembly code retain the Business Source License 1.1 terms in
`os/yocto/LICENSE`. Individual vendored recipes and patches may carry their own
notices; moving them into this repository does not relicense them.
