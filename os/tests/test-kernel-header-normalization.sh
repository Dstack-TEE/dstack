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
# and nothing else points at why. So this test parses the field table out of
# both and compares them, then exercises the Python side against a synthetic
# bzImage.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/../.." && pwd)
script=$root/os/image/normalize-kernel-header.py
patch=$root/os/yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf/0007-OvmfPkg-QemuKernelLoaderFsDxe-normalize-setup-header.patch

[ -x "$script" ] || { echo "missing $script" >&2; exit 1; }
[ -f "$patch" ] || { echo "missing $patch" >&2; exit 1; }

python3 - "$script" "$patch" <<'PYEOF'
import importlib.util
import re
import sys

script_path, patch_path = sys.argv[1], sys.argv[2]

spec = importlib.util.spec_from_file_location("normalize", script_path)
normalize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalize)

py_fields = sorted((offset, size) for offset, size, _ in normalize.WRITE_FIELDS)

# Added lines of the form "  { 0x210, 1 }, // type_of_loader".
patch_text = open(patch_path, encoding="ascii").read()
ovmf_fields = sorted(
    (int(offset, 16), int(size))
    for offset, size in re.findall(
        r"^\+\s*\{\s*(0x[0-9A-Fa-f]+),\s*(\d+)\s*\},", patch_text, re.M
    )
)

assert ovmf_fields, "no field table found in the OVMF patch"
assert py_fields == ovmf_fields, (
    "normalization field tables disagree\n"
    f"  image build: {[(hex(o), s) for o, s in py_fields]}\n"
    f"  OVMF patch:  {[(hex(o), s) for o, s in ovmf_fields]}"
)

for token in ("LINUX_HDR_MIN_PROTOCOL  0x0209", "LINUX_LOADFLAGS_CAN_USE_HEAP  0x80"):
    assert token in patch_text, f"OVMF patch no longer defines {token}"
assert normalize.MIN_PROTOCOL == 0x0209
assert normalize.CAN_USE_HEAP == 0x80

# `modify` fields carry kernel-supplied values and must never be normalized.
# code32_start is the protected-mode entry point; zeroing it bricks the kernel.
for forbidden in (0x1F2, 0x1FA, 0x211, 0x212, 0x214):
    assert all(offset != forbidden for offset, _ in py_fields), (
        f"0x{forbidden:x} is a `modify` field and must not be zeroed"
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
        image[0x210] = 0xB0
        image[0x211] |= 0x80
        image[0x218:0x21C] = (0xA97FC000).to_bytes(4, "little")
        image[0x21C:0x220] = (0x0062A954).to_bytes(4, "little")
        image[0x224:0x226] = (0xFE00).to_bytes(2, "little")
        image[0x228:0x22C] = (0x20000).to_bytes(4, "little")
    return image

built, patched = make_image(False), make_image(True)
assert built != patched

normalize.normalize(built)
normalize.normalize(patched)
assert built == patched, "normalizing a QEMU-patched kernel must reproduce the shipped one"

# Idempotent, so OVMF re-running it over an already normalized kernel is a no-op.
again = bytearray(built)
assert normalize.normalize(again) == []
assert again == built

# The `modify` fields survived.
assert built[0x1F2:0x1F4] == (0x0001).to_bytes(2, "little")
assert built[0x1FA:0x1FC] == (0xFFFF).to_bytes(2, "little")
assert built[0x211] == 0x01
assert built[0x212:0x214] == (0x8000).to_bytes(2, "little")
assert built[0x214:0x218] == (0x100000).to_bytes(4, "little")

# The two sides deliberately differ on a non-bzImage. OVMF boots arbitrary EFI
# binaries through the same path and must leave them alone (QEMU stopped
# patching them in commit 05e984c200a), while at build time a kernel without
# the HdrS magic is a broken build and has to fail loudly.
other = bytearray(0x1000)
other[0x210] = 0xB0
try:
    normalize.normalize(other)
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
ancient[0x206:0x208] = (0x0208).to_bytes(2, "little")
try:
    normalize.normalize(ancient)
except ValueError:
    pass
else:
    raise AssertionError("the image build must reject boot protocols below 2.09")

print("kernel setup-header normalization: OK")
PYEOF
