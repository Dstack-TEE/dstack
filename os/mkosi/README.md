# Experimental mkosi backend

This is an experimental Debian/mkosi implementation of the dstack guest OS.
It is not yet a replacement for the release Yocto backend. Its acceptance
target is functional parity with the Yocto image, not merely release archive
compatibility. `parity.json` is the machine-checked inventory used by a build.

The backend builds the same dstack services plus the pinned Yocto component
set: Linux 7.1, NVIDIA 595.58.03 (open modules, userspace, firmware, Fabric
Manager and NSCQ), nvattest 2026.06.09 with the OCSP-freshness patch, OpenZFS
2.4.0 with upstream Linux 6.19--7.1 compatibility backports, Sysbox 0.6.7,
NVIDIA Container Toolkit, nerdctl, CNI plugins and stargz-snapshotter 0.18.2.

## Reproducibility model

`versions.env` pins the stable 7.x kernel tarball by SHA-256 and selects an
immutable Debian snapshot. `Cargo.lock`, `--locked --offline`, a fixed
`SOURCE_DATE_EPOCH`, normalized file mtimes, fixed kernel build identity and
mkosi's deterministic image construction close the remaining inputs. The two
dstack binaries therefore require an already populated Cargo cache; use a
vendored source tree in hermetic CI. `DSTACK_SKIP_RUST=1` exists only for
rootfs/kernel development and does **not** produce a functional guest.

The custom kernel starts from `x86_64_defconfig`, then applies the reviewed
`kernel.config` fragment. This is the practical upstream equivalent of Yocto's
`linux-yocto-tiny` plus explicit features: disabling arbitrary defconfig
symbols without resolving Kconfig dependencies would be less auditable. Both
the TDX DMA patch and the ACPI BadAML/SystemMemory sandbox patch are reused
verbatim from `meta-dstack`; patch fuzz is forbidden. The final `.config` is
checked before compilation.

## Build and acceptance

Host requirements include mkosi >= 26, systemd tools, C/C++/Go/Rust kernel and
EDK2 build toolchains, `autoconf`, `automake`, `libtool`, `bc`, `bison`,
`flex`, `nasm`, `iasl`, and development headers for OpenSSL, ELF, UUID, udev,
aio, attr, blkid, curl, seccomp and tirpc. BTF generation requires `pahole`
(the `dwarves` package). Runtime build tools include `patch`,
`pax-utils` (`lddtree`), `squashfs-tools`, `cryptsetup`, `gdisk`,
`dosfstools`, `mtools`, `curl`, `xz`, QEMU/KVM and root privileges (or a
working user namespace). Full UKI release assembly also needs the pinned
`nitro-tpm-pcr-compute` described by `os/image/assemble.sh`.

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

The cache covers dstack Rust, the container stack, Sysbox, nvattest, the
kernel build tree, NVIDIA, ZFS and both OVMF variants. Its key conservatively
includes the inputs, tools, packages and component dependencies declared by
each file in `components/`, plus architecture, flavor and
`SOURCE_DATE_EPOCH`. `build-components.sh` is intentionally only the ordered
component list. Component install trees are merged with strict non-directory
conflict detection. `image` and `repro-check` never pass the development-cache
option. Release artifacts, Debian rootfs, dm-verity data and measurements are
never cached.

On a 16-job development host, a clean production work directory takes about
17 minutes (measured 16m45s); allow 20--30 minutes with cold compiler and
network caches. `repro-check` performs two such builds sequentially.

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

The firmware is not Debian's generic OVMF: `build-ovmf.sh` builds the same
EDK2 stable-202502 revision and `pre202505` TDX measurement layout selected by
the Yocto recipe. A generic OVMF cannot be substituted because `dstack-mr`
would produce invalid or unparseable TDX measurement material.
