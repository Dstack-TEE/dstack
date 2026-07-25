# Experimental mkosi backend

This is an experimental Debian/mkosi implementation of the dstack guest OS.
It is not yet a replacement for the release Yocto backend. Its acceptance
target is functional parity with the Yocto image, not merely release archive
compatibility. `parity.json` is the machine-checked inventory used by a build.

The backend builds the same dstack services plus the pinned Yocto component
set: Linux 6.18, NVIDIA 595.58.03 (open modules, userspace, firmware, Fabric
Manager and NSCQ), nvattest 2026.06.09 with the OCSP-freshness patch, OpenZFS
2.4.0, Sysbox 0.6.7, NVIDIA Container Toolkit, nerdctl, CNI plugins and
stargz-snapshotter 0.18.2.

The kernel tracks the same series as the production Yocto backend
(`PREFERRED_VERSION_linux-yocto` in `meta-dstack`), which `tests/acceptance.sh`
enforces. That is what keeps the component set patch-free: ZFS 2.4.0 declares
`Linux-Maximum: 6.18` and the NVIDIA 595.58.03 open modules build against this
series unmodified, so neither carries an out-of-tree compatibility patch that
production does not also carry.

## Reproducibility model

`versions.env` pins the stable 7.x kernel, Rust 1.92.0 and Go 1.22.2
archives by SHA-256 and selects an immutable Debian snapshot. All components
are compiled by `mkosi.build` inside mkosi's build-package overlay; host
Rust/Go/GCC binaries are never used. C/C++ compilers, linkers, headers and
build systems come from that snapshot, while the Rust and Go distributions are
installed under `/opt/dstack-toolchains` after checksum verification. A mkosi
tools tree built from the same snapshot supplies image-construction tools.
`Cargo.lock`, `--locked`, a fixed `SOURCE_DATE_EPOCH`, normalized file mtimes,
fixed kernel build identity and mkosi's deterministic image construction close
the remaining inputs. `DSTACK_SKIP_RUST=1` exists only for rootfs/kernel
development and does **not** produce a functional guest.

The custom kernel starts from `x86_64_defconfig`, then applies the reviewed
`kernel.config` fragment. This is the practical upstream equivalent of Yocto's
`linux-yocto-tiny` plus explicit features: disabling arbitrary defconfig
symbols without resolving Kconfig dependencies would be less auditable. Both
the TDX DMA patch and the ACPI BadAML/SystemMemory sandbox patch are reused
verbatim from `meta-dstack`; patch fuzz is forbidden. The final `.config` is
checked before compilation.

## Build and acceptance

Host compilation and image-assembly toolchains are not required. mkosi 26
creates the pinned Debian build overlay containing all component compilers and
headers. Its minimized `misc` tools-tree profile plus explicit packages supplies
`lddtree`, squashfs, dm-verity, disk, archive and UKI tools. The repository's
`dstack-mr` and the pinned `nitro-tpm-pcr-compute` revision are compiled by
`mkosi.build`, exported only for `mkosi.postoutput`, and removed from the guest.
The host needs mkosi's own dependencies and root privileges (or a working user
namespace), but no Rust, Go, C or C++ compiler.

```sh
./os/mkosi/build.sh lint
./os/build.sh --backend mkosi --build-dir "$PWD/os/mkosi/build"
./os/mkosi/build.sh repro-check "$PWD/os/mkosi/repro"
# QEMU smoke-test the assembled UKI disk (host OVMF path is distro-specific)
qemu-system-x86_64 -machine q35 -m 2G -nographic \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=virtio,format=raw,file=os/mkosi/build/out/prod/dstack-0.6.0/disk.raw
```

For local iteration only, `dev-image` enables a component-output cache:

```sh
DSTACK_DEV_CACHE_DIR="$HOME/.cache/dstack/mkosi-dev" \
  ./os/mkosi/build.sh dev-image "$PWD/os/mkosi/build-dev"
```

The cache covers dstack Rust, image tools, the container stack, Sysbox, nvattest, the
kernel build tree, NVIDIA, ZFS and both OVMF variants. Its key conservatively
includes the inputs, tools, packages and component dependencies declared by
each descriptor in `components/<name>/<name>.sh`, plus architecture, flavor and
`SOURCE_DATE_EPOCH`. For linked worktrees, `build.sh` records the Git-owned and
untracked source path inventory on the host, while file contents are hashed in
the mkosi build root; Git metadata is never mounted into the sandbox.
`build-components.sh` is intentionally only the ordered component list.
Component install trees are merged with strict non-directory conflict
detection. `image` and `repro-check` never calculate, read or write component
cache keys. Release artifacts, Debian rootfs, dm-verity data and measurements
are never cached.

mkosi's `Incremental=`, `CacheDirectory=` and `BuildDirectory=` cover
whole-image/rootfs and persistent-work-directory reuse; they do not provide
independently keyed output trees for components or reject file collisions when
those trees are installed. The small component layer only supplies those two
missing policies. Source download, build, cache-key inputs and output ownership
remain together under `components/<name>/`; production builds bypass the layer's
archive cache completely.

On a 16-job development host, a clean production work directory takes about
27 minutes with warm package downloads; allow 30--45 minutes with cold network
caches. `repro-check` performs two such builds sequentially.

Acceptance means: the static contract passes; a disk with systemd-boot/UKI
boots on x86_64 QEMU; `/proc/config.gz` contains the checked TDX/SNP, TPM,
ACPI, dm-verity/crypt, virtio, container and hardening options; dstack services
are enabled; and two clean builds compare byte-for-byte. The backend exports
artifact-manifest schema v1 and delegates final assembly to
`os/image/assemble.sh`, exactly like Yocto. Its output contains the same
`dstack-0.6.0/` directory, bare-metal and UKI tarballs, partitioned combined
squashfs/dm-verity image, metadata, measurements, checksums, kernel, initramfs,
OVMF and UKI. Debian supplies the base userspace while the parity checker
requires the Yocto-visible binaries, services, configuration, kernel modules
and production/development separation before assembly is allowed to proceed.

The firmware is not Debian's generic OVMF: `components/ovmf/ovmf-build.sh` builds the same
EDK2 stable-202502 revision and `pre202505` TDX measurement layout selected by
the Yocto recipe. A generic OVMF cannot be substituted because `dstack-mr`
would produce invalid or unparseable TDX measurement material.

## Native mkosi boundary

The distribution snapshot, build-only packages, guest packages, profiles,
source mounts, source-date epoch, tools tree, package cleanup, file removal,
systemd presets, tmpfiles, service masks and the build/postinstall/finalize/
postoutput/clean lifecycle are mkosi-native. The native tar output is replaced
in `mkosi.postoutput` by the identically named Yocto-compatible archive, so no
unrelated mkosi rootfs artifact escapes the staging directory.

Only four project-specific mechanisms remain:

1. `make-release-artifacts.sh` and `os/image/assemble.sh` implement the existing
   combined squashfs/dm-verity layout, initramfs command-line protocol,
   measurements and archive member contract. mkosi's repart/UKI formats would
   change that external interface.
2. The development-only component cache provides independently keyed output
   trees. mkosi's `Incremental=`, `BuildDirectory=` and
   `BuildSourcesEphemeral=buildcache` cache a whole image or mutable build tree,
   not isolated component install outputs.
3. `merge-component-trees.py` rejects conflicting component-owned rootfs paths;
   mkosi's normal tree overlays intentionally use last-writer-wins semantics.
4. `normalize-skeleton-modes.sh` maps regular skeleton files to Git's two
   portable mode classes (0644 or 0755). mkosi correctly preserves source
   modes, but Git worktrees on shared hosts can add group-write bits that are
   not represented in the Git index and would otherwise change the rootfs.

The tiny postinstall hook is also retained because mkosi's native `MachineId=`
supports a UUID, `random`, or `uninitialized`, while the Yocto contract requires
an existing but empty `/etc/machine-id`. Rust and Go distributions are pinned by
version and SHA-256 inside the mkosi build overlay because Debian trixie's Rust
package is too old for this workspace; they never come from the host.
