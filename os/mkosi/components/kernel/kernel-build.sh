#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
MKOSI_DIR="$ROOT/os/mkosi"
# shellcheck source=/dev/null
source "$MKOSI_DIR/versions.env"
BUILD_DIR=${1:?build directory required}
STAGING=${2:?staging tree required}
BUILD_DIR=$(realpath -m "$BUILD_DIR")
STAGING=$(realpath -m "$STAGING")
JOBS=${JOBS:-$(nproc)}
export KBUILD_BUILD_TIMESTAMP="@${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH required}"
export KBUILD_BUILD_USER=dstack KBUILD_BUILD_HOST=reproducible
export KBUILD_BUILD_VERSION=1
export KCONFIG_NOTIMESTAMP=1
# Neither the source nor output directory may leak into DWARF/BTF or module
# metadata: repro-check deliberately builds in two differently named trees.
kernel_map="-fdebug-prefix-map=$BUILD_DIR=/usr/src/linux -fmacro-prefix-map=$BUILD_DIR=/usr/src/linux"
export KCFLAGS="${KCFLAGS:-} $kernel_map"
export KAFLAGS="${KAFLAGS:-} $kernel_map"
export KCPPFLAGS="${KCPPFLAGS:-} $kernel_map"

mkdir -p "$BUILD_DIR/downloads" "$BUILD_DIR/kernel-build" "$STAGING"
# pahole 1.25 produces a different BTF type order when its encoder runs with
# Kbuild's parallel job count. Keep compilation parallel, but serialize BTF
# encoding so vmlinux and bzImage are byte-for-byte reproducible.
pahole_wrapper="$BUILD_DIR/pahole-reproducible"
cat > "$pahole_wrapper" <<'EOF'
#!/bin/bash
set -euo pipefail
args=()
for arg; do
    # dwarves 1.25's parallel and optimized-function encoders both depend on
    # unstable traversal order. Neither is needed for BTF correctness.
    [[ $arg == -j* || $arg == --btf_gen_optimized ]] || args+=("$arg")
done
exec pahole -j1 "${args[@]}"
EOF
chmod 0755 "$pahole_wrapper"
tarball="$BUILD_DIR/downloads/linux-$KERNEL_VERSION.tar.xz"
if [[ ! -f $tarball ]]; then
    curl --fail --location --retry 3 -o "$tarball.tmp" \
      "https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_VERSION%%.*}.x/linux-$KERNEL_VERSION.tar.xz"
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

make -C "$src" O="$BUILD_DIR/kernel-build" PAHOLE="$pahole_wrapper" x86_64_defconfig
"$src/scripts/kconfig/merge_config.sh" -m -O "$BUILD_DIR/kernel-build" \
    "$BUILD_DIR/kernel-build/.config" "$MKOSI_DIR/components/kernel/kernel.config"
make -C "$src" O="$BUILD_DIR/kernel-build" PAHOLE="$pahole_wrapper" olddefconfig
"$ROOT/os/common/scripts/check-kernel-config.sh" "$BUILD_DIR/kernel-build/.config" \
    "$MKOSI_DIR/components/kernel/kernel.config"
make -C "$src" O="$BUILD_DIR/kernel-build" PAHOLE="$pahole_wrapper" -j"$JOBS" bzImage modules
make -C "$src" O="$BUILD_DIR/kernel-build" \
    PAHOLE="$pahole_wrapper" INSTALL_MOD_PATH="$STAGING" modules_install
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
