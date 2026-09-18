#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# The setup-header normalization has two independent implementations that must
# agree byte for byte, because one produces the kernel we ship and the other
# produces the bytes OVMF measures:
#
#   os/image/normalize-kernel-header.py                 (image build)
#   0007-OvmfPkg-...-normalize-setup-header.patch        (firmware)
#
# If they ever disagree, every CVM fails attestation with an RTMR[1] mismatch
# and nothing else points at why. So this test checks that both write the same
# fields with the same constants, then exercises the Python side against a
# synthetic bzImage. dstack-mr is the third implementation -- it predicts this
# layout for an image that does not declare the flag -- so its constants are
# checked too.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/../.." && pwd)
script=$root/os/image/normalize-kernel-header.py
patch=$root/os/yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf/0007-OvmfPkg-QemuKernelLoaderFsDxe-normalize-setup-header.patch

[ -x "$script" ] || { echo "missing $script" >&2; exit 1; }
[ -f "$patch" ] || { echo "missing $patch" >&2; exit 1; }

kernel_rs=$root/dstack/dstack-mr/src/kernel.rs
[ -f "$kernel_rs" ] || { echo "missing $kernel_rs" >&2; exit 1; }

python3 - "$script" "$patch" "$kernel_rs" <<'PYEOF'
import importlib.util
import re
import sys

script_path, patch_path, kernel_rs_path = sys.argv[1:4]

spec = importlib.util.spec_from_file_location("normalize", script_path)
normalize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalize)

patch_text = open(patch_path, encoding="utf-8").read()
kernel_rs = open(kernel_rs_path, encoding="utf-8").read()


def ovmf(name):
    match = re.search(rf"^\+#define {name}\s+(0x[0-9A-Fa-f]+)", patch_text, re.M)
    assert match, f"the OVMF patch no longer defines {name}"
    return int(match.group(1), 16)


# Both sides write these fields, and only these.
py_offsets = {0x210, 0x211, 0x218, 0x21C, 0x224, 0x228}
ovmf_offsets = {
    ovmf(f"LINUX_HDR_{name}_OFFSET")
    for name in (
        "TYPE_OF_LOADER",
        "LOADFLAGS",
        "RAMDISK_IMAGE",
        "RAMDISK_SIZE",
        "HEAP_END_PTR",
        "CMD_LINE_PTR",
    )
}
assert py_offsets == ovmf_offsets, (py_offsets, ovmf_offsets)

# Every value the layout depends on, in all three implementations.
for name, value, rust in (
    ("QEMU_LINUX_TYPE_OF_LOADER", normalize.TYPE_OF_LOADER_QEMU, "0xb0"),
    ("QEMU_LINUX_REAL_ADDR_LOW", normalize.REAL_ADDR_LOW, "0x90000_u32"),
    ("QEMU_LINUX_CMDLINE_ADDR_LOW", normalize.CMDLINE_ADDR_LOW, "0x9a000_u32"),
    ("QEMU_LINUX_REAL_ADDR_HIGH", normalize.REAL_ADDR_HIGH, "0x10000_u32"),
    ("QEMU_LINUX_CMDLINE_ADDR_HIGH", normalize.CMDLINE_ADDR_HIGH, "0x20000_u32"),
    ("QEMU_LINUX_SETUP_HEAP_GAP", normalize.SETUP_HEAP_GAP, "0x200"),
    ("QEMU_LOW_MEMORY_SPLIT", normalize.LOW_MEMORY_SPLIT, "0x80000000"),
    ("QEMU_ACPI_DATA_SIZE", normalize.ACPI_DATA_SIZE, "0x28000"),
    ("LINUX_INITRD_ADDR_MAX_DEFAULT", normalize.INITRD_ADDR_MAX_DEFAULT, "0x37ffffff"),
    ("QEMU_INITRD_ALIGNMENT", normalize.INITRD_ALIGNMENT, "4095"),
):
    assert ovmf(name) == value, f"{name} is {ovmf(name):#x} in the OVMF patch"
    assert rust in kernel_rs, f"dstack-mr no longer spells {rust}"

assert ovmf("LINUX_HDR_MIN_PROTOCOL") == normalize.MIN_PROTOCOL == 0x0202
assert ovmf("LINUX_LOADFLAGS_CAN_USE_HEAP") == normalize.CAN_USE_HEAP == 0x80
assert ovmf("LINUX_LOADFLAGS_LOADED_HIGH") == normalize.LOADED_HIGH == 0x01

# `modify` fields carry kernel-supplied values and must never be written.
# code32_start is the protected-mode entry point; overwriting it bricks the
# kernel. loadflags is only OR-ed with CAN_USE_HEAP, never replaced.
for forbidden in (0x1F2, 0x1FA, 0x212, 0x214):
    assert forbidden not in py_offsets, (
        f"0x{forbidden:x} is a `modify` field and must not be written"
    )

# Synthetic bzImage: a plausible built kernel, then the same image with every
# boot-loader-written field filled in the way QEMU fills them.
def make_image(patched: bool) -> bytearray:
    image = bytearray(0x1000)
    image[0x202:0x206] = b"HdrS"
    image[0x206:0x208] = (0x020F).to_bytes(2, "little")
    image[0x1F2:0x1F4] = (0x0001).to_bytes(2, "little")  # root_flags
    image[0x1FA:0x1FC] = (0xFFFF).to_bytes(2, "little")  # vid_mode
    image[0x211] = 0x01                                   # loadflags: LOADED_HIGH
    image[0x212:0x214] = (0x8000).to_bytes(2, "little")  # setup_move_size
    image[0x214:0x218] = (0x100000).to_bytes(4, "little")  # code32_start
    image[0x224:0x226] = (0x50A0).to_bytes(2, "little")  # heap_end_ptr
    if patched:
        # What QEMU writes for a 1 GiB guest, whose initrd sits lower than the
        # layout normalized to.
        image[0x210] = 0xB0
        image[0x211] |= 0x80
        image[0x218:0x21C] = (0x37BF3000).to_bytes(4, "little")
        image[0x21C:0x220] = (INITRD_SIZE).to_bytes(4, "little")
        image[0x224:0x226] = (0xFE00).to_bytes(2, "little")
        image[0x228:0x22C] = (0x20000).to_bytes(4, "little")
    return image


INITRD_SIZE = 6_454_799

built, patched = make_image(False), make_image(True)
assert built != patched

normalize.normalize(built, INITRD_SIZE)
normalize.normalize(patched, INITRD_SIZE)
assert built == patched, "normalizing a QEMU-patched kernel must reproduce the shipped one"

# The layout QEMU writes, which is what dstack-mr predicts for an image that
# does not declare the flag.
assert built[0x210] == 0xB0
assert built[0x211] == 0x81
assert built[0x218:0x21C] == (0x379D8000).to_bytes(4, "little")
assert built[0x21C:0x220] == (INITRD_SIZE).to_bytes(4, "little")
assert built[0x224:0x228] == (0xFE00).to_bytes(4, "little")
assert built[0x228:0x22C] == (0x20000).to_bytes(4, "little")

# Independent of guest RAM: an initrd address QEMU derived for another guest
# size normalizes to the same bytes, which is what makes the host's QEMU
# version and memory size irrelevant.
again = bytearray(built)
assert normalize.normalize(again, INITRD_SIZE) == []
assert again == built

# The `modify` fields survived, and loadflags kept LOADED_HIGH.
assert built[0x1F2:0x1F4] == (0x0001).to_bytes(2, "little")
assert built[0x1FA:0x1FC] == (0xFFFF).to_bytes(2, "little")
assert built[0x211] & 0x01
assert built[0x212:0x214] == (0x8000).to_bytes(2, "little")
assert built[0x214:0x218] == (0x100000).to_bytes(4, "little")

# The two sides deliberately differ on a non-bzImage. OVMF boots arbitrary EFI
# binaries through the same path and must leave them alone (QEMU stopped
# patching them in commit 05e984c200a), while at build time a kernel without
# the HdrS magic is a broken build and has to fail loudly.
other = bytearray(0x1000)
other[0x210] = 0xB0
try:
    normalize.normalize(other, INITRD_SIZE)
except ValueError:
    pass
else:
    raise AssertionError("the image build must reject a non-bzImage")
assert "return;" in patch_text.split('CompareMem (Data + LINUX_HDR_MAGIC_OFFSET')[1][:400], (
    "the OVMF side must return quietly on a non-bzImage"
)

# Too old a boot protocol: the field layout is not guaranteed, so neither side
# normalizes. The image build still fails loudly about it.
ancient = bytearray(0x1000)
ancient[0x202:0x206] = b"HdrS"
ancient[0x206:0x208] = (0x0201).to_bytes(2, "little")
try:
    normalize.normalize(ancient, INITRD_SIZE)
except ValueError:
    pass
else:
    raise AssertionError("the image build must reject boot protocols below 2.02")

print("kernel setup-header normalization: OK")
PYEOF
