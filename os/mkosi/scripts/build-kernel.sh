#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
MKOSI_DIR="$ROOT/os/mkosi"
# shellcheck source=/dev/null
source "$MKOSI_DIR/versions.env"
BUILD_DIR=${1:?build directory required}
STAGING=${2:?staging tree required}
JOBS=${JOBS:-$(nproc)}
export KBUILD_BUILD_TIMESTAMP="@${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH required}"
export KBUILD_BUILD_USER=dstack KBUILD_BUILD_HOST=reproducible
export KBUILD_BUILD_VERSION=1
export KCONFIG_NOTIMESTAMP=1

mkdir -p "$BUILD_DIR/downloads" "$BUILD_DIR/kernel-build" "$STAGING"
tarball="$BUILD_DIR/downloads/linux-$KERNEL_VERSION.tar.xz"
if [[ ! -f $tarball ]]; then
    curl --fail --location --retry 3 -o "$tarball.tmp" \
      "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$KERNEL_VERSION.tar.xz"
    mv "$tarball.tmp" "$tarball"
fi
echo "$KERNEL_SHA256  $tarball" | sha256sum --check --status || {
    echo "kernel source checksum mismatch" >&2; exit 1;
}
src="$BUILD_DIR/linux-$KERNEL_VERSION"
rm -rf "$src" "$BUILD_DIR/kernel-build" "$STAGING/usr/lib/modules/$KERNEL_VERSION-dstack"
tar -C "$BUILD_DIR" --no-same-owner -xf "$tarball"
for patch in \
  "$ROOT/os/yocto/layers/meta-dstack/recipes-kernel/linux/files/0001-x86-tdx-select-dma-direct-remap.patch" \
  "$ROOT/os/yocto/layers/meta-dstack/recipes-kernel/linux/files/0002-acpi-sandbox-block-aml-systemmemory-ram-access.patch"; do
    patch -d "$src" -p1 --fuzz=0 < "$patch"
done

make -C "$src" O="$BUILD_DIR/kernel-build" x86_64_defconfig
"$src/scripts/kconfig/merge_config.sh" -m -O "$BUILD_DIR/kernel-build" \
    "$BUILD_DIR/kernel-build/.config" "$MKOSI_DIR/kernel.config"
make -C "$src" O="$BUILD_DIR/kernel-build" olddefconfig
"$MKOSI_DIR/scripts/check-kernel-config.sh" "$BUILD_DIR/kernel-build/.config"
make -C "$src" O="$BUILD_DIR/kernel-build" -j"$JOBS" bzImage modules
make -C "$src" O="$BUILD_DIR/kernel-build" \
    INSTALL_MOD_PATH="$STAGING" modules_install
# Debian is usr-merged: /lib is a symlink. Normalize modules into /usr/lib so
# ExtraTrees never tries to replace that symlink with a directory.
if [[ -d $STAGING/lib/modules ]]; then
    mkdir -p "$STAGING/usr/lib/modules"
    cp -a "$STAGING/lib/modules/." "$STAGING/usr/lib/modules/"
    rm -rf "${STAGING:?}/lib"
fi
rm -f "$STAGING/usr/lib/modules/$KERNEL_VERSION-dstack/build" \
      "$STAGING/usr/lib/modules/$KERNEL_VERSION-dstack/source"
install -Dm0644 "$BUILD_DIR/kernel-build/arch/x86/boot/bzImage" \
    "$STAGING/usr/lib/modules/$KERNEL_VERSION-dstack/vmlinuz"
install -Dm0644 "$BUILD_DIR/kernel-build/.config" \
    "$STAGING/usr/lib/modules/$KERNEL_VERSION-dstack/config"
find "$STAGING" -print0 | xargs -0r touch --no-dereference --date="@$SOURCE_DATE_EPOCH"
