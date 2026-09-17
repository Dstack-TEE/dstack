#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Export the minimal kernel build tree an application needs to compile an
# out-of-tree module (`make -C $KDIR M=$PWD modules`) against the guest kernel.
#
# The guest image ships modules but no build tree, so an application that needs
# its own .ko had to reconstruct a byte-identical kernel build to obtain a
# matching Module.symvers and vermagic. This exports that tree from the build
# that produced the shipped kernel instead.
#
# The file selection is upstream's: scripts/package/install-extmod-build is
# what `make bindeb-pkg` uses to produce Debian's linux-headers package, so the
# set of files carried here tracks Kbuild rather than a list maintained by
# dstack. It is invoked through `make run-command` because it reads srctree,
# SRCARCH, CC and HOSTCC out of the Kbuild environment.
#
# The result is deliberately NOT installed into the guest rootfs: it is ~100 MB
# of build inputs no CVM needs at runtime, and adding it would change the
# rootfs verity hash and therefore the OS image identity. It ships as a
# separate release artifact.
set -euo pipefail

usage() {
    cat <<EOF
Usage: ${0##*/} --src DIR --build DIR --out DIR [options]

Options:
  --src DIR            Kernel source tree the image was built from
  --build DIR          Kernel output directory (O=) holding .config
  --out DIR            Output directory, created fresh
  --backend NAME       Backend that produced the kernel (default: unknown)
  --image-version VER  dstack OS image version the kernel belongs to
  --flavor NAME        Image flavor the kernel belongs to

SOURCE_DATE_EPOCH, when set, is applied to every exported file so the tree can
be archived reproducibly.
EOF
}

SRC='' BUILD='' OUT='' BACKEND=unknown IMAGE_VERSION='' FLAVOR=''
while [ $# -gt 0 ]; do
    case "$1" in
        --src) SRC=$2; shift 2 ;;
        --build) BUILD=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --backend) BACKEND=$2; shift 2 ;;
        --image-version) IMAGE_VERSION=$2; shift 2 ;;
        --flavor) FLAVOR=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done
if [ -z "$SRC" ] || [ -z "$BUILD" ] || [ -z "$OUT" ]; then
    usage >&2
    exit 2
fi
SRC=$(realpath "$SRC")
BUILD=$(realpath "$BUILD")
OUT=$(realpath -m "$OUT")

exporter="$SRC/scripts/package/install-extmod-build"
[ -x "$exporter" ] || {
    echo "kernel source does not provide scripts/package/install-extmod-build: $SRC" >&2
    exit 1
}
config="$BUILD/.config"
release_file="$BUILD/include/config/kernel.release"
symvers="$BUILD/Module.symvers"
for required in "$config" "$release_file" "$symvers"; do
    [ -f "$required" ] || {
        echo "kernel output directory is incomplete, build modules first: $required" >&2
        exit 1
    }
done
release=$(cat "$release_file")
[ -n "$release" ] || { echo "empty kernel release in $release_file" >&2; exit 1; }
version=$(make -C "$SRC" -s kernelversion)

headers="$OUT/linux-headers-$release"
rm -rf "$OUT"
mkdir -p "$OUT"
# run-command exports the Kbuild environment install-extmod-build reads, and it
# runs in the output directory, which is where the script expects to find
# Module.symvers and include/config. This is exactly how scripts/package/builddeb
# invokes it.
make -C "$SRC" O="$BUILD" run-command \
    KBUILD_RUN_COMMAND="$exporter $headers"
# install-extmod-build carries include/config/auto.conf, which is what Kbuild
# reads for an external module build, but not .config. Ship it anyway: it is
# what an application inspects to find out whether a config option it needs is
# enabled, and kernel-hardening or module-compat questions are answered from it.
install -m0644 "$config" "$headers/.config"
# The one file upstream's list carries that cannot be reproducible:
# scripts/mod/devicetable-offsets.s is a -fverbose-asm intermediate whose
# comments and line markers record the absolute source path of the build that
# produced it, and no prefix map rewrites them (-ffile-prefix-map applies to
# __FILE__ and debug info, not to -S output; measured, the paths survive).
# Dropping it costs nothing: it exists only to generate
# scripts/mod/devicetable-offsets.h, which ships, and so does its .c source.
find "$headers" -name '*.s' -delete

# Written for the consumer, not for the build: an out-of-tree module is only
# loadable by the image whose kernel produced this tree, so the tree has to say
# which image that is, and a Module.symvers or .config that differs from the
# shipped one silently produces a module that fails to load.
python3 - "$OUT" "$headers" "$release" "$version" "$BACKEND" "$IMAGE_VERSION" \
    "$FLAVOR" <<'PY'
import hashlib
import json
import os
import sys

out, headers, release, version, backend, image_version, flavor = sys.argv[1:]


def digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def compiler():
    prefix = 'CONFIG_CC_VERSION_TEXT="'
    with open(os.path.join(headers, ".config"), encoding="utf-8") as handle:
        for line in handle:
            if line.startswith(prefix):
                return line.rstrip("\n")[len(prefix) : -1]
    return ""


files = 0
total = 0
for root, _, names in os.walk(headers):
    for name in names:
        path = os.path.join(root, name)
        files += 1
        if not os.path.islink(path):
            total += os.path.getsize(path)

metadata = {
    "backend": backend,
    "compiler": compiler(),
    "config_sha256": digest(os.path.join(headers, ".config")),
    "file_count": files,
    "flavor": flavor,
    "image_version": image_version,
    "kernel_release": release,
    "kernel_version": version,
    "module_symvers_sha256": digest(os.path.join(headers, "Module.symvers")),
    "uncompressed_bytes": total,
}
with open(os.path.join(out, "kernel-devel.json"), "w", encoding="utf-8") as handle:
    json.dump(metadata, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    find "$OUT" -print0 | xargs -0r touch --no-dereference \
        --date="@$SOURCE_DATE_EPOCH"
fi
echo "exported kernel build tree for $release to $OUT"
