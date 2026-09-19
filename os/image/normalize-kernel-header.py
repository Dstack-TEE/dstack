#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Phala Network
# SPDX-License-Identifier: Apache-2.0
"""Normalize the Linux setup header of a bzImage.

QEMU acts as the boot loader for `-kernel` and fills in the setup-header fields
the Linux boot protocol expects a boot loader to supply. OVMF measures the
result into RTMR[1], so the same image measures differently depending on
whether QEMU rewrote the header -- which changed in QEMU 10.2 (commit
a7542a38f399, "x86/loader: Don't update kernel header for CoCo VMs").

Writing those fields in the shipped kernel, and having OVMF write them again
before measuring, makes RTMR[1] the plain Authenticode hash of the file we
ship, on every QEMU version.

The values are the ones QEMU <= 10.1 wrote for a kernel loaded high in a guest
with 2 GiB or more of RAM below 4G. Zeros would serve the measurement goal
equally well; these particular values are chosen because `dstack-mr` already
computes them (`patch_kernel` in dstack/dstack-mr/src/kernel.rs) for an image
that does not declare `kernel_header_normalized`, so a verifier or KMS from an
earlier dstack release can still measure these images.

This writes one fixed header. It is not a reimplementation of QEMU's loader:
the branches below reproduce the header QEMU in fact wrote for the kernels
dstack ships, and a kernel outside that shape is refused rather than guessed
at.

Every field written is one QEMU fills in as boot loader. All but one are typed
`write` in `Documentation/arch/x86/boot.rst`: the boot loader supplies them and
the kernel has no value there. The exception is `loadflags`, typed
`modify (obligatory)`, of which only `CAN_USE_HEAP` is set -- a bit the
protocol assigns to the boot loader. Fields carrying real kernel-supplied
values, such as `code32_start`, are left alone, and so are the `write` fields
QEMU never touches: a built kernel ships them zero, so writing them would only
add a way to disagree.

The initrd size decides `ramdisk_image`, so the initrd the image ships is an
input.
"""

import argparse
import sys

# Offsets of the boot.rst `write` fields QEMU fills in.
TYPE_OF_LOADER_OFFSET = 0x210
RAMDISK_IMAGE_OFFSET = 0x218
RAMDISK_SIZE_OFFSET = 0x21C
HEAP_END_PTR_OFFSET = 0x224
CMD_LINE_PTR_OFFSET = 0x228
INITRD_ADDR_MAX_OFFSET = 0x22C
XLOADFLAGS_OFFSET = 0x236

LOADFLAGS_OFFSET = 0x211
LOADED_HIGH = 0x01
CAN_USE_HEAP = 0x80
# xloadflags bit 1. Bit 6, 0x40, is XLF_5LEVEL_ENABLED, not this flag.
XLF_CAN_BE_LOADED_ABOVE_4G = 0x02

# What QEMU writes: "Qemu" version 0, the real-mode block and command line it
# loads a kernel loaded high at, the 0x200-byte gap it leaves below the command
# line for the setup heap, the below-4G window it reserves for ACPI tables with
# RAM split at 2 GiB, the initrd ceiling a kernel that declares none gets, and
# the alignment it rounds the initrd address down to.
TYPE_OF_LOADER_QEMU = 0xB0
REAL_ADDR = 0x10000
CMDLINE_ADDR = 0x20000
SETUP_HEAP_GAP = 0x200
LOW_MEMORY_SPLIT = 0x80000000
ACPI_DATA_SIZE = 0x28000
INITRD_ADDR_MAX_DEFAULT = 0x37FFFFFF
INITRD_ALIGNMENT = 0x1000

HEADER_MAGIC_OFFSET = 0x202
HEADER_MAGIC = b"HdrS"
VERSION_OFFSET = 0x206
# Minimum length for an image to be treated as carrying a setup header. The
# fields below all sit under 0x238; 0x258 is the end of the protocol 2.09
# header, kept as the bound so a truncated image is rejected outright instead
# of being sliced past its end, which would silently grow it. The OVMF side
# applies the same bound.
HEADER_END_OFFSET = 0x258
# `cmd_line_ptr` moved into the setup header in 2.02, `initrd_addr_max`
# arrived in 2.03 and `xloadflags` in 2.12.
MIN_PROTOCOL = 0x0202
IAM_PROTOCOL = 0x0203
XLF_PROTOCOL = 0x020C


def target_fields(image: bytes, initrd_size: int) -> list:
    """Return the (offset, bytes, name) QEMU writes for this kernel."""
    if len(image) < HEADER_END_OFFSET:
        raise ValueError(
            f"image is {len(image)} bytes, shorter than the "
            f"0x{HEADER_END_OFFSET:x}-byte setup header"
        )
    if image[HEADER_MAGIC_OFFSET : HEADER_MAGIC_OFFSET + 4] != HEADER_MAGIC:
        raise ValueError("not a Linux bzImage: missing HdrS magic at 0x202")
    protocol = int.from_bytes(image[VERSION_OFFSET : VERSION_OFFSET + 2], "little")
    if protocol < MIN_PROTOCOL:
        raise ValueError(
            f"boot protocol {protocol >> 8}.{protocol & 0xFF:02} is older than "
            f"{MIN_PROTOCOL >> 8}.{MIN_PROTOCOL & 0xFF:02}; the field layout this "
            "script normalizes is not guaranteed"
        )

    if not image[LOADFLAGS_OFFSET] & LOADED_HIGH:
        # For a kernel loaded low, QEMU's command line sits at
        # 0x9a000 - cmdline_size, which depends on the command line the host
        # passes: there is no single value to normalize to. Every kernel this
        # build ships is loaded high, so refuse rather than write a value QEMU
        # never writes. The OVMF side leaves such a header as served.
        raise ValueError(
            "the kernel is not loaded high; its cmd_line_ptr depends on the "
            "command line and cannot be normalized"
        )

    fields = [
        (TYPE_OF_LOADER_OFFSET, bytes([TYPE_OF_LOADER_QEMU]), "type_of_loader"),
        (
            LOADFLAGS_OFFSET,
            bytes([image[LOADFLAGS_OFFSET] | CAN_USE_HEAP]),
            "loadflags",
        ),
        # heap_end_ptr is two bytes, but the value never exceeds 16 bits and
        # the two bytes above it (ext_loader_ver, ext_loader_type) are zero in
        # a built kernel and untouched by QEMU, so writing the word
        # zero-extended to 32 bits is what OVMF and dstack-mr also write.
        (
            HEAP_END_PTR_OFFSET,
            (CMDLINE_ADDR - REAL_ADDR - SETUP_HEAP_GAP).to_bytes(4, "little"),
            "heap_end_ptr",
        ),
        (CMD_LINE_PTR_OFFSET, CMDLINE_ADDR.to_bytes(4, "little"), "cmd_line_ptr"),
    ]
    if initrd_size <= 0:
        return fields

    if protocol >= XLF_PROTOCOL:
        xloadflags = int.from_bytes(
            image[XLOADFLAGS_OFFSET : XLOADFLAGS_OFFSET + 2], "little"
        )
        initrd_max = (
            0xFFFFFFFF
            if xloadflags & XLF_CAN_BE_LOADED_ABOVE_4G
            else INITRD_ADDR_MAX_DEFAULT
        )
    elif protocol >= IAM_PROTOCOL:
        declared = int.from_bytes(
            image[INITRD_ADDR_MAX_OFFSET : INITRD_ADDR_MAX_OFFSET + 4], "little"
        )
        initrd_max = declared or INITRD_ADDR_MAX_DEFAULT
    else:
        initrd_max = INITRD_ADDR_MAX_DEFAULT
    available = LOW_MEMORY_SPLIT - ACPI_DATA_SIZE
    if initrd_max >= available:
        initrd_max = available - 1
    if initrd_size >= initrd_max:
        raise ValueError(
            f"an initrd of {initrd_size} bytes does not fit below 0x{initrd_max:x}"
        )
    initrd_addr = (initrd_max - initrd_size) & ~(INITRD_ALIGNMENT - 1)
    fields.append(
        (RAMDISK_IMAGE_OFFSET, initrd_addr.to_bytes(4, "little"), "ramdisk_image")
    )
    fields.append(
        (RAMDISK_SIZE_OFFSET, initrd_size.to_bytes(4, "little"), "ramdisk_size")
    )
    return fields


def normalize(image: bytearray, initrd_size: int) -> list:
    """Write the boot-loader-written fields. Returns the fields it changed."""
    changed = []
    for offset, value, name in target_fields(bytes(image), initrd_size):
        old = bytes(image[offset : offset + len(value)])
        if old != value:
            changed.append((name, offset, old.hex(), value.hex()))
            image[offset : offset + len(value)] = value
    return changed


def main() -> int:
    """Normalize the image named on the command line, or check it in place."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bzimage", help="kernel image to normalize in place")
    parser.add_argument(
        "initrd",
        help="initrd the image ships, whose size decides the initrd address",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report whether the image is already normalized, do not write",
    )
    args = parser.parse_args()

    with open(args.bzimage, "rb") as f:
        image = bytearray(f.read())
    with open(args.initrd, "rb") as f:
        f.seek(0, 2)
        initrd_size = f.tell()

    changed = normalize(image, initrd_size)

    for name, offset, old, new in changed:
        print(f"{args.bzimage}: {name} (0x{offset:03x}) {old} -> {new}")

    if args.check:
        if changed:
            print(f"{args.bzimage}: not normalized", file=sys.stderr)
            return 1
        return 0

    if changed:
        with open(args.bzimage, "wb") as f:
            f.write(image)
    else:
        print(f"{args.bzimage}: already normalized")
    return 0


if __name__ == "__main__":
    sys.exit(main())
