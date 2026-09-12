# dstack ACPI reference image

This directory builds the production QEMU compatibility fork at revision
`0f3d3f6ed099e4cf0b79f59e8b6ba0083b7c414f` with its test-only
`DUMP_ACPI_TABLES` mode. The resulting command writes QEMU's 128 KiB
`etc/acpi/tables` blob to standard output and exits without starting a VM.

That revision samples the blob after the PCI bridge `BSEL` properties are
assigned. QEMU only assigns them during machine reset and rebuilds the tables
afterwards, so the blob a guest measures is the post-reset one. Earlier
revisions dumped from inside `acpi_setup()`, which yielded a DSDT with no
`BSEL` anywhere and therefore none of the root-port hotplug AML a GPU CVM
measures — an oracle built from them silently agreed with a generator that
omitted those terms.

## What this oracle cannot test

Two measured inputs are out of its reach, so a green differential run says
nothing about them:

- **The 64-bit PCI window (`_CRS`) when `pci_hole64_size` is left at 0.** QEMU
  derives that window from `pci_bus_get_w64_range()`, which only sees BARs the
  guest firmware has already assigned. The oracle exits before any firmware
  runs, so the range is always empty and the window always falls back to the
  configured size. Adding a device with a large 64-bit BAR does not help: a
  64 GiB `ivshmem-plain` BAR still leaves the window at the 32 GiB default.
  A real GPU CVM grows it to the span OVMF assigned — several TiB for eight
  B200s — which no dump-and-exit oracle can reproduce. Set an explicit
  `qemu_pci_hole64_size` on GPU hosts; the explicit path is covered here.
- **More than one PXB.** `dstack-vmm` emits one `pxb-pcie` per GPU NUMA node,
  but `MachineConfig` carries only `hugepages` and `num_gpus`, so a multi-node
  topology cannot be expressed as a case at all.

The image is a differential-test oracle only. Production Rust code does not
depend on it. The source revision and GPL license are recorded as OCI labels;
the corresponding source is available from the repository and revision named
in the labels.

Build locally with:

```sh
docker build -t kvin/dstack-acpi-tables:qemu-11.1-20260911 \
  -f dstack/crates/qemu-acpi/reference/Dockerfile .
```
