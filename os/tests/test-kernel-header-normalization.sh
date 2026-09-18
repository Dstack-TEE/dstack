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
machine_rs=$root/dstack/dstack-mr/src/machine.rs
[ -f "$kernel_rs" ] || { echo "missing $kernel_rs" >&2; exit 1; }
[ -f "$machine_rs" ] || { echo "missing $machine_rs" >&2; exit 1; }

python3 - "$script" "$patch" "$kernel_rs" "$machine_rs" <<'PYEOF'
import importlib.util
import re
import sys

script_path, patch_path, kernel_rs_path, machine_rs_path = sys.argv[1:5]

# Importing the script must not leave a .pyc beside it: a cached one whose
# source changed within the same second, without changing size, is reused, and
# this test would then check bytecode that is no longer on disk.
sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("normalize", script_path)
normalize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalize)

patch_text = open(patch_path, encoding="utf-8").read()
machine_rs = open(machine_rs_path, encoding="utf-8").read()
# Only what dstack-mr compiles into a release counts: a constant that survives
# in `#[cfg(test)]` alone would let the two sides drift while this test passes.
kernel_rs = open(kernel_rs_path, encoding="utf-8").read().split("mod tests {")[0]


def ovmf(name):
    match = re.search(rf"^\+#define {name}\s+(0x[0-9A-Fa-f]+)", patch_text, re.M)
    assert match, f"the OVMF patch no longer defines {name}"
    return int(match.group(1), 16)


INITRD_SIZE = 6_454_798


# Synthetic bzImage: a plausible built kernel, then the same image with every
# boot-loader-written field filled in the way QEMU fills them.
def make_image(patched: bool, xloadflags: int = 0, initrd_addr: int = 0) -> bytearray:
    image = bytearray(0x1000)
    image[0x202:0x206] = b"HdrS"
    image[0x206:0x208] = (0x020F).to_bytes(2, "little")
    image[0x1F2:0x1F4] = (0x0001).to_bytes(2, "little")  # root_flags
    image[0x1FA:0x1FC] = (0xFFFF).to_bytes(2, "little")  # vid_mode
    image[0x211] = 0x01                                   # loadflags: LOADED_HIGH
    image[0x212:0x214] = (0x8000).to_bytes(2, "little")  # setup_move_size
    image[0x214:0x218] = (0x100000).to_bytes(4, "little")  # code32_start
    image[0x224:0x226] = (0x50A0).to_bytes(2, "little")  # heap_end_ptr
    image[0x236:0x238] = xloadflags.to_bytes(2, "little")
    if patched:
        # What QEMU wrote for some other guest: the initrd address is the only
        # field its memory size reaches, so it is the caller's to vary.
        image[0x210] = 0xB0
        image[0x211] |= 0x80
        image[0x218:0x21C] = initrd_addr.to_bytes(4, "little")
        image[0x21C:0x220] = (INITRD_SIZE).to_bytes(4, "little")
        image[0x224:0x226] = (0xFE00).to_bytes(2, "little")
        image[0x228:0x22C] = (0x20000).to_bytes(4, "little")
    return image


# Both sides must write the same fields at the same widths. Read the Python
# side out of the script instead of restating it here, so that a field added or
# widened on one side alone fails this test.
py_fields = {
    (offset, len(value))
    for offset, value, _ in normalize.target_fields(bytes(make_image(False)), INITRD_SIZE)
}


def ovmf_written_fields():
    """The (offset, size) the OVMF patch assigns to, parsed from its code."""
    written = {}
    depth = 0
    for line in patch_text.splitlines():
        if not line.startswith("+"):
            continue
        body = line[1:]
        for match in re.finditer(r"Data\[LINUX_HDR_(\w+)_OFFSET\]\s*\|?=", body):
            written[match.group(1)] = 1
        if depth:
            for match in re.finditer(r"LINUX_HDR_(\w+)_OFFSET", body):
                written[match.group(1)] = 4
        if "LinuxHdrWrite32 (" in body:
            # A call reaching the closing `);` on its own line spans several.
            after = body.split("LinuxHdrWrite32 (", 1)[1]
            for match in re.finditer(r"LINUX_HDR_(\w+)_OFFSET", after):
                written[match.group(1)] = 4
            depth = 0 if ");" in after else 1
        elif depth and ");" in body:
            depth = 0
    return {(ovmf(f"LINUX_HDR_{name}_OFFSET"), size) for name, size in written.items()}


ovmf_fields = ovmf_written_fields()
assert py_fields == ovmf_fields, (sorted(py_fields), sorted(ovmf_fields))
assert len(py_fields) == 6, sorted(py_fields)

# Every value the layout depends on, in the firmware.
for name, value in (
    ("QEMU_LINUX_TYPE_OF_LOADER", normalize.TYPE_OF_LOADER_QEMU),
    ("QEMU_LINUX_REAL_ADDR", normalize.REAL_ADDR),
    ("QEMU_LINUX_CMDLINE_ADDR", normalize.CMDLINE_ADDR),
    ("QEMU_LINUX_SETUP_HEAP_GAP", normalize.SETUP_HEAP_GAP),
    ("QEMU_LOW_MEMORY_SPLIT", normalize.LOW_MEMORY_SPLIT),
    ("QEMU_ACPI_DATA_SIZE", normalize.ACPI_DATA_SIZE),
    ("LINUX_INITRD_ADDR_MAX_DEFAULT", normalize.INITRD_ADDR_MAX_DEFAULT),
    ("QEMU_INITRD_ALIGNMENT", normalize.INITRD_ALIGNMENT),
    ("LINUX_XLF_CAN_BE_LOADED_ABOVE_4G", normalize.XLF_CAN_BE_LOADED_ABOVE_4G),
    ("LINUX_HDR_MIN_PROTOCOL", normalize.MIN_PROTOCOL),
    ("LINUX_LOADFLAGS_CAN_USE_HEAP", normalize.CAN_USE_HEAP),
    ("LINUX_LOADFLAGS_LOADED_HIGH", normalize.LOADED_HIGH),
):
    assert ovmf(name) == value, f"{name} is {ovmf(name):#x} in the OVMF patch"

assert normalize.MIN_PROTOCOL == 0x0202
assert normalize.CAN_USE_HEAP == 0x80
assert normalize.LOADED_HIGH == 0x01

# The same values in dstack-mr, matched where it computes the layout rather
# than anywhere in the file: it is the implementation an earlier release's
# verifier or KMS runs against these images.
for text, spelling, what in (
    (kernel_rs, f"kd[0x210] = {normalize.TYPE_OF_LOADER_QEMU:#x}", "type_of_loader"),
    (
        kernel_rs,
        f"({normalize.REAL_ADDR:#x}_u32, {normalize.CMDLINE_ADDR:#x}_u32)",
        "the real-mode and command-line addresses",
    ),
    (
        kernel_rs,
        f"saturating_sub({normalize.SETUP_HEAP_GAP:#x})",
        "the setup-heap gap",
    ),
    (
        kernel_rs,
        f"xlf & {normalize.XLF_CAN_BE_LOADED_ABOVE_4G:#04x}",
        "XLF_CAN_BE_LOADED_ABOVE_4G",
    ),
    (
        kernel_rs,
        f"{normalize.INITRD_ADDR_MAX_DEFAULT:#x}",
        "the default initrd ceiling",
    ),
    (kernel_rs, f"& !{normalize.INITRD_ALIGNMENT - 1}", "the initrd alignment"),
    (
        kernel_rs,
        f"TDX_KERNEL_HASH_COMPAT_2G_MEMORY: u64 = {normalize.LOW_MEMORY_SPLIT:#x}",
        "the 2 GiB split",
    ),
    (machine_rs, f"{normalize.ACPI_DATA_SIZE:#x}", "the ACPI window"),
):
    assert spelling in text, f"dstack-mr no longer spells {what} as {spelling}"

# `modify` fields carry kernel-supplied values and must never be written.
# code32_start is the protected-mode entry point; overwriting it bricks the
# kernel. loadflags is only OR-ed with CAN_USE_HEAP, never replaced.
for forbidden in (0x1F2, 0x1FA, 0x212, 0x214):
    assert forbidden not in {offset for offset, _ in py_fields}, (
        f"0x{forbidden:x} is a `modify` field and must not be written"
    )

built, patched = make_image(False), make_image(True, initrd_addr=0x37BF3000)
assert built != patched

normalize.normalize(built, INITRD_SIZE)
normalize.normalize(patched, INITRD_SIZE)
assert built == patched, "normalizing a QEMU-patched kernel must reproduce the shipped one"

# The layout QEMU writes, which is what dstack-mr predicts for an image that
# does not declare the flag. This kernel declares no xloadflags, so QEMU caps
# the initrd at the 0x37ffffff a kernel that cannot be loaded above 4G gets.
assert built[0x210] == 0xB0
assert built[0x211] == 0x81
assert built[0x218:0x21C] == (0x379D8000).to_bytes(4, "little")
assert built[0x21C:0x220] == (INITRD_SIZE).to_bytes(4, "little")
assert built[0x224:0x228] == (0xFE00).to_bytes(4, "little")
assert built[0x228:0x22C] == (0x20000).to_bytes(4, "little")

# The branch every kernel this build ships takes: XLF_CAN_BE_LOADED_ABOVE_4G
# lifts QEMU's ceiling to 4G, and what caps the initrd is then the below-4G
# window it reserves for ACPI tables with RAM split at 2 GiB.
above_4g = make_image(False, xloadflags=normalize.XLF_CAN_BE_LOADED_ABOVE_4G)
normalize.normalize(above_4g, INITRD_SIZE)
assert above_4g[0x218:0x21C] == (0x7F9B0000).to_bytes(4, "little"), (
    f"initrd address is {int.from_bytes(above_4g[0x218:0x21C], 'little'):#x}"
)
assert above_4g[0x21C:0x220] == (INITRD_SIZE).to_bytes(4, "little")

# 0x40 is XLF_5LEVEL_ENABLED, not XLF_CAN_BE_LOADED_ABOVE_4G. Reading it as the
# latter -- which all three implementations once did -- moves the initrd about
# 1.1 GiB away from where QEMU puts it, for any kernel built without 5-level
# paging.
five_level = make_image(False, xloadflags=0x0040)
normalize.normalize(five_level, INITRD_SIZE)
assert five_level[0x218:0x21C] == built[0x218:0x21C], (
    "the 5-level flag must not raise the initrd ceiling"
)

# A kernel loaded low takes QEMU's other command-line address, which depends on
# the command line the host passes: there is nothing to normalize to, and the
# build has to say so rather than write a value QEMU never writes.
low = make_image(False)
low[0x211] &= ~normalize.LOADED_HIGH
try:
    normalize.normalize(low, INITRD_SIZE)
except ValueError:
    pass
else:
    raise AssertionError("the image build must reject a kernel not loaded high")
assert "kernel is not loaded high" in patch_text, (
    "the OVMF side must leave a low-loaded kernel as served"
)

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
