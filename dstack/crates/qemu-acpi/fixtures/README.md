# QEMU ACPI compatibility fixtures

These binary fixtures are machine-generated `etc/acpi/tables` blobs. They
capture QEMU's externally observable ACPI ABI and contain no QEMU source code.
They must never be regenerated from the Rust implementation.

## Pinned production reference

The fixtures in this directory were generated from:

- repository: <https://github.com/kvinwang/qemu-tdx>
- branch: `dstack-qemu-acpi-11.1-compat`
- revision: `9de6fdfff3a84103b83ca6b2e8c4fb8e05cf9195`
- dstack image inputs: `dstack-0.5.5/ovmf.fd` and
  `dstack-0.5.5/bzImage`

Build the reference in a clean build directory:

```bash
git clone https://github.com/kvinwang/qemu-tdx.git qemu-tdx
cd qemu-tdx
git checkout 9de6fdfff3a84103b83ca6b2e8c4fb8e05cf9195
git apply /path/to/qemu-acpi/scripts/qemu-dump-all-blobs.patch
mkdir build-acpi && cd build-acpi
CFLAGS='-DDUMP_ACPI_TABLES -Wno-builtin-macro-redefined -D__DATE__="" -D__TIME__="" -D__TIMESTAMP__=""' \
LDFLAGS='-Wl,--build-id=none' \
../configure --prefix=/tmp/qemu-acpi-compat-install \
  --target-list=x86_64-softmmu --disable-werror
ninja qemu-system-x86_64
```

Run the complete three-blob differential matrix with:

```bash
../scripts/differential-qemu.sh \
  /path/to/qemu-tdx/build-acpi/qemu-system-x86_64 \
  /path/to/dstack-0.5.5
```

The script compares `etc/acpi/tables`, `etc/table-loader`, and
`etc/acpi/rsdp` byte for byte for normal, NUMA, and NUMA/PXB configurations.
The dump patch is test-only instrumentation and does not change table
construction.

The trimmed `*-base.bin` files are test-only byte oracles. They are never read
by non-test code and are not templates for generation. QEMU's trailing zero
allocation is removed at the first all-zero table signature. The four variants
for each compatibility family cover the Cartesian product of:

- CPU hotplug enabled or disabled; and
- ordinary Q35 or NUMA with one PXB.

`qemu-11.1-q35-one-nic.bin` is an untrimmed byte-for-byte regression fixture.
Fixture names identify the emulated compatibility version, not necessarily the
source tree's release number.

## Compatibility-reference scope

The pinned reference is based on QEMU 9.2.1. Its 10.x and 11.x profiles are a
dstack-maintained compatibility implementation composed from the relevant
upstream ACPI changes. Therefore matching this reference proves compatibility
with the QEMU binary used by dstack production, not by itself with every
unmodified upstream QEMU release. Genuine upstream QEMU cross-validation must
be recorded separately whenever a new compatibility family is added.

## Genuine upstream cross-validation

The following unmodified upstream release revisions were built locally, then
instrumented with `scripts/qemu-upstream-dump.patch`:

- QEMU 10.2.4: `3e0bcba1ca7d6607ca49a988d165f052a3a53323`
- QEMU 11.0.3: `aeec49e8170de7846f476124602cf7acd400c3df`

For each release, `scripts/differential-upstream.sh` compared all three blobs
for normal, NUMA, and NUMA/PXB topologies. All six cases matched byte for byte.
The upstream instrumentation normalizes only values that the production
`DUMP_ACPI_TABLES` patch also normalizes (PM I/O, PCI windows, and MCFG), and
bypasses TDX realization so the comparison can run without a TDX-capable KVM.
It does not backport or alter ACPI generation logic.

Example:

```bash
git clone https://gitlab.com/qemu-project/qemu.git qemu-upstream
cd qemu-upstream
git checkout 3e0bcba1ca7d6607ca49a988d165f052a3a53323
git apply /path/to/qemu-acpi/scripts/qemu-upstream-dump.patch
mkdir build && cd build
../configure --target-list=x86_64-softmmu --enable-kvm --enable-tcg \
  --disable-docs --disable-werror
ninja qemu-system-x86_64
/path/to/qemu-acpi/scripts/differential-upstream.sh \
  ./qemu-system-x86_64 10.2.4
```

There was no genuine upstream QEMU 11.1 release at the time of this audit, so
the `11.1` compatibility profile remains pinned to the production compatibility
fork rather than being described as an upstream release profile.

## Versions past the newest profile

A QEMU version newer than the newest profile here is generated with that
profile (`Compatibility::LATEST`) rather than rejected: most releases leave the
Q35 ACPI ABI untouched, and when one does change it the generated blobs stop
matching the measured ones, which is strictly more informative than refusing to
generate. Adding a profile therefore means adding its fixtures **and** moving
`Compatibility::LATEST` to it.
