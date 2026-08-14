#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

"""Reproducible differential tests against the QEMU ACPI reference image."""

# ruff: noqa: D101, D103

import argparse
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

TABLE_BLOB_SIZE = 128 * 1024
LOADER_COMMAND_SIZE = 128
LOADER_BLOB_SIZE = 4096
TABLES_FILE = "etc/acpi/tables"
RSDP_FILE = "etc/acpi/rsdp"


@dataclass(frozen=True)
class Case:
    version: str = "11.1.0"
    cpus: int = 1
    memory_mib: int = 2048
    nics: int = 1
    volumes: int = 0
    gpus: int = 0
    switches: int = 0
    hugepages: bool = False
    root_verity: bool = True
    hotplug_off: bool = False
    smm: bool = False
    pic: bool = False
    pci_hole64_size: int = 0


def fixed_cases():
    cases = [
        Case(version=v)
        for v in ["8.0.0", "9.1.0", "9.2.0", "10.0.0", "11.0.0", "11.1.0", "11.2.0"]
    ]
    cases += [Case(cpus=n) for n in [1, 8, 9, 254, 255, 256, 4096]]
    cases += [Case(memory_mib=n) for n in [1, 2047, 2048, 2815, 2816, 1_048_576]]
    cases += [
        Case(nics=0, root_verity=False),
        Case(nics=4, volumes=4),
        Case(hotplug_off=True),
        Case(smm=True, pic=True),
        Case(pci_hole64_size=1 << 40),
        Case(hugepages=True),
        Case(hugepages=True, gpus=1),
        Case(hugepages=True, gpus=8, switches=4),
        Case(version="9.1.0", hugepages=True, gpus=1, hotplug_off=True),
    ]
    return cases


def random_case(rng):
    hugepages = rng.choice([False, True])
    gpus = rng.randint(0, 8)
    switches = rng.randint(0, 4) if gpus else 0
    pxb = hugepages and gpus > 0
    available = 25 if pxb else 26
    passthrough = switches if pxb else gpus + switches
    root_verity = rng.choice([False, True])
    capacity = available - passthrough - (1 if root_verity else 0) + 1
    if pxb:
        # QEMU adds the fixed-address PXB after the ordinary virtio devices.
        # Keep slot 0x10 free for it, matching configurations QEMU can realize.
        capacity = min(capacity, 12 - int(root_verity))
    nics = rng.randint(0, max(0, capacity))
    volumes = rng.randint(0, max(0, capacity - nics))
    return Case(
        version=rng.choice(
            ["8.0.0", "9.1.0", "9.2.0", "10.0.0", "11.0.0", "11.1.0", "11.2.0"]
        ),
        cpus=rng.choice([1, 2, 8, 9, 254, 255, 256, rng.randint(1, 512)]),
        memory_mib=rng.choice([1, 2047, 2048, 2815, 2816, rng.randint(1, 1_048_576)]),
        nics=nics,
        volumes=volumes,
        gpus=gpus,
        switches=switches,
        hugepages=hugepages,
        root_verity=root_verity,
        hotplug_off=rng.choice([False, True]),
        smm=rng.choice([False, True]),
        pic=rng.choice([False, True]),
        pci_hole64_size=rng.choice([0, 32 << 30, 1 << 40]),
    )


def qemu_args(case):
    args = [
        "-cpu",
        "qemu64",
        "-smp",
        str(case.cpus),
        "-m",
        f"{case.memory_mib}M",
        "-nographic",
        "-nodefaults",
        "-serial",
        "stdio",
        "-drive",
        "file=/bin/sh,if=none,id=hd1,format=raw,readonly=on",
        "-device",
        "virtio-blk-pci,drive=hd1",
    ]
    for index in range(case.volumes):
        args += [
            "-drive",
            f"file=/bin/sh,if=none,id=vol{index},format=raw,readonly=on",
            "-device",
            f"virtio-blk-pci,drive=vol{index}",
        ]
    for index in range(case.nics):
        args += [
            "-netdev",
            f"socket,id=net{index},listen=:0",
            "-device",
            f"virtio-net-pci,netdev=net{index}",
        ]
    args += [
        "-device",
        "vhost-vsock-pci,guest-cid=3",
        "-virtfs",
        "local,path=/bin,mount_tag=host-shared,readonly=on,security_model=none,id=virtfs0",
    ]
    if case.root_verity:
        args += [
            "-drive",
            "file=/bin/sh,if=none,id=hd0,format=raw,readonly=on",
            "-device",
            "virtio-blk-pci,drive=hd0",
        ]
    else:
        args += ["-cdrom", "/bin/sh"]
    args += [
        "-machine",
        f"q35,kernel-irqchip=split,hpet=off,smm={'on' if case.smm else 'off'},pic={'on' if case.pic else 'off'}",
    ]
    if case.hugepages:
        args += [
            "-numa",
            f"node,nodeid=0,cpus=0-{case.cpus - 1},memdev=mem0",
            "-object",
            f"memory-backend-file,id=mem0,size={case.memory_mib}M,mem-path=/tmp,share=on,prealloc=no",
        ]
    port = 0
    if case.gpus:
        args += ["-object", "iommufd,id=iommufd0"]
        bus = "pcie.0"
        if case.hugepages:
            args += [
                "-device",
                "pxb-pcie,id=pcie.node0,bus=pcie.0,addr=10,numa_node=0,bus_nr=5",
            ]
            bus = "pcie.node0"
        for _ in range(case.gpus):
            args += [
                "-device",
                f"pcie-root-port,id=pci.{port},bus={bus},chassis={port}",
                "-device",
                f"vfio-pci,host=00:00.0,bus=pci.{port},iommufd=iommufd0",
            ]
            port += 1
    for _ in range(case.switches):
        args += [
            "-device",
            f"pcie-root-port,id=pci.{port},bus=pcie.0,chassis={port}",
            "-device",
            f"vfio-pci,host=00:00.0,bus=pci.{port},iommufd=iommufd0",
        ]
        port += 1
    if case.hotplug_off:
        args += ["-global", "ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off"]
    if case.pci_hole64_size:
        args += ["-global", f"q35-pcihost.pci-hole64-size=0x{case.pci_hole64_size:x}"]
    return args


def command(kind, payload):
    data = struct.pack("<I", kind) + payload
    return data + bytes(LOADER_COMMAND_SIZE - len(data))


def filename(name):
    encoded = name.encode()
    return encoded + bytes(56 - len(encoded))


def reference_blobs(tables):
    if len(tables) < TABLE_BLOB_SIZE or len(tables) % TABLE_BLOB_SIZE:
        raise RuntimeError(
            f"reference emitted invalid table allocation size {len(tables)}"
        )
    locations = {}
    offset = 0
    while tables[offset : offset + 4] != bytes(4):
        signature = tables[offset : offset + 4]
        length = struct.unpack_from("<I", tables, offset + 4)[0]
        if length < 36 or offset + length > len(tables):
            raise RuntimeError(
                f"invalid reference table {signature!r} length {length} at {offset}"
            )
        locations[signature] = (offset, length)
        offset += length
    rsdt_offset, rsdt_length = locations[b"RSDT"]
    rsdp = b"RSD PTR \0BOCHS \0" + struct.pack("<I", rsdt_offset)
    loader = command(1, filename(RSDP_FILE) + struct.pack("<IB", 16, 2))
    loader += command(1, filename(TABLES_FILE) + struct.pack("<IB", 64, 1))

    def checksum(signature):
        start, length = locations[signature]
        return command(
            3, filename(TABLES_FILE) + struct.pack("<III", start + 9, start, length)
        )

    loader += checksum(b"DSDT")
    fadt, _ = locations[b"FACP"]
    for relative, size in [(36, 4), (40, 4), (140, 8)]:
        loader += command(
            2,
            filename(TABLES_FILE)
            + filename(TABLES_FILE)
            + struct.pack("<IB", fadt + relative, size),
        )
    loader += checksum(b"FACP") + checksum(b"APIC")
    if b"SRAT" in locations:
        loader += checksum(b"SRAT")
    loader += checksum(b"MCFG") + checksum(b"WAET")
    for relative in range(36, rsdt_length, 4):
        loader += command(
            2,
            filename(TABLES_FILE)
            + filename(TABLES_FILE)
            + struct.pack("<IB", rsdt_offset + relative, 4),
        )
    loader += checksum(b"RSDT")
    loader += command(
        2, filename(RSDP_FILE) + filename(TABLES_FILE) + struct.pack("<IB", 16, 4)
    )
    loader += command(3, filename(RSDP_FILE) + struct.pack("<III", 8, 0, 20))
    return tables, loader + bytes(LOADER_BLOB_SIZE - len(loader)), rsdp


def first_difference(left, right):
    for index, pair in enumerate(zip(left, right)):
        if pair[0] != pair[1]:
            return index
    return min(len(left), len(right))


def run_case(case, image, rust_dump, output):
    env = os.environ.copy()
    env["QEMU_ACPI_COMPAT_VER"] = case.version
    reference = subprocess.run(
        ["docker", "run", "--rm", "-e", f"QEMU_ACPI_COMPAT_VER={case.version}", image]
        + qemu_args(case),
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    (output / "reference-tables.bin").write_bytes(reference)
    subprocess.run(
        [
            rust_dump,
            str(case.nics),
            str(case.cpus),
            case.version,
            str(case.gpus),
            str(case.switches),
            str(int(case.hugepages)),
            str(int(case.root_verity)),
            str(int(case.hotplug_off)),
            str(int(case.smm)),
            str(case.pci_hole64_size),
            str(case.memory_mib * 1024 * 1024),
            str(case.volumes),
            str(int(case.pic)),
        ],
        check=True,
        env={**env, "QEMU_ACPI_OUTPUT_DIR": str(output)},
    )
    expected = reference_blobs(reference)
    actual = tuple(
        (output / name).read_bytes()
        for name in ["tables.bin", "loader.bin", "rsdp.bin"]
    )
    for name, blob in zip(["tables", "loader", "rsdp"], expected):
        (output / f"reference-{name}.bin").write_bytes(blob)
    for name, wanted, got in zip(["tables", "loader", "rsdp"], expected, actual):
        if wanted != got:
            at = first_difference(wanted, got)
            raise RuntimeError(
                f"{name} differs at byte {at}: expected {wanted[at : at + 16].hex(' ')}, got {got[at : at + 16].hex(' ')}"
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--rust-dump", required=True)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0x1053)
    parser.add_argument("--cases", type=int, default=32)
    parser.add_argument("--failure-dir", type=Path)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    cases = fixed_cases() + [random_case(rng) for _ in range(args.cases)]
    with tempfile.TemporaryDirectory(prefix="qemu-acpi-diff-") as directory:
        output = Path(directory)
        for index, case in enumerate(cases):
            try:
                run_case(case, args.image, args.rust_dump, output)
            except Exception as error:
                print(
                    f"FAIL seed={args.seed:#x} case={index} config={case}",
                    file=sys.stderr,
                )
                if args.failure_dir:
                    if args.failure_dir.exists():
                        shutil.rmtree(args.failure_dir)
                    shutil.copytree(output, args.failure_dir)
                    (args.failure_dir / "case.txt").write_text(
                        f"seed={args.seed:#x}\nindex={index}\nconfig={case}\nerror={error}\n"
                    )
                raise
            print(f"PASS {index + 1}/{len(cases)} {case}")


if __name__ == "__main__":
    main()
