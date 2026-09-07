#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Phala Network
# SPDX-License-Identifier: Apache-2.0
"""Normalize the Linux setup header of a bzImage.

QEMU acts as the boot loader for `-kernel` and fills in the setup-header fields
the Linux boot protocol expects a boot loader to supply. OVMF measures the
result into RTMR[1], so the same image measures differently depending on
whether QEMU rewrote the header -- which changed in QEMU 10.2 (commit
a7542a38f399, "x86/loader: Don't update kernel header for CoCo VMs").

Zeroing those fields in the shipped kernel, and having OVMF zero them again
before measuring, makes RTMR[1] the plain Authenticode hash of the file we
ship, on every QEMU version.

The field set comes from the boot protocol, not from QEMU: every field
`Documentation/arch/x86/boot.rst` types as `write` is one the boot loader
fills in and the kernel supplies no value for. Fields typed `modify` carry
real kernel-supplied values (`code32_start` is the protected-mode entry point)
and are left alone.

In a freshly built kernel every one of these fields is already zero except
`heap_end_ptr`, so this normally rewrites exactly two bytes.
"""

import argparse
import sys

# Offset, size, name -- every boot.rst field typed `write`.
WRITE_FIELDS = [
    (0x210, 1, "type_of_loader"),
    (0x218, 4, "ramdisk_image"),
    (0x21C, 4, "ramdisk_size"),
    (0x224, 2, "heap_end_ptr"),
    (0x226, 1, "ext_loader_ver"),
    (0x227, 1, "ext_loader_type"),
    (0x228, 4, "cmd_line_ptr"),
    (0x23C, 4, "hardware_subarch"),
    (0x240, 8, "hardware_subarch_data"),
    (0x250, 8, "setup_data"),
]

LOADFLAGS_OFFSET = 0x211
CAN_USE_HEAP = 0x80

HEADER_MAGIC_OFFSET = 0x202
HEADER_MAGIC = b"HdrS"
VERSION_OFFSET = 0x206
# One past the last field this touches. Anything shorter cannot carry a setup
# header, and slicing past the end would silently grow the image instead of
# failing. The OVMF side applies the same bound.
HEADER_END_OFFSET = 0x258
# `setup_data` (0x250) requires 2.09+; every field above exists by then.
MIN_PROTOCOL = 0x0209


def normalize(image: bytearray) -> list:
    """Zero the boot-loader-written fields. Returns the fields it changed."""
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

    changed = []
    for offset, size, name in WRITE_FIELDS:
        old = bytes(image[offset : offset + size])
        if old != bytes(size):
            changed.append((name, offset, old.hex(), "0" * (size * 2)))
            image[offset : offset + size] = bytes(size)

    loadflags = image[LOADFLAGS_OFFSET]
    if loadflags & CAN_USE_HEAP:
        changed.append(
            (
                "loadflags",
                LOADFLAGS_OFFSET,
                f"{loadflags:02x}",
                f"{loadflags & ~CAN_USE_HEAP:02x}",
            )
        )
        image[LOADFLAGS_OFFSET] = loadflags & ~CAN_USE_HEAP

    return changed


def main() -> int:
    """Normalize the image named on the command line, or check it in place."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bzimage", help="kernel image to normalize in place")
    parser.add_argument(
        "--check",
        action="store_true",
        help="report whether the image is already normalized, do not write",
    )
    args = parser.parse_args()

    with open(args.bzimage, "rb") as f:
        image = bytearray(f.read())

    changed = normalize(image)

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
