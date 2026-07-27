#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
SELF="$ROOT/os/mkosi"
# shellcheck source=/dev/null
source "$SELF/versions.env"
B=$(realpath -m "${1:?build directory required}")
KERNEL_SRC=$(realpath "${2:?kernel source required}")
KERNEL_BUILD=$(realpath "${3:?kernel build directory required}")
ROOT_STAGE=$(realpath -m "${4:?rootfs staging tree required}")
KERNEL_STAGE=$(realpath -m "${5:?kernel staging tree required}")
src="$B/zfs"
export CFLAGS="${CFLAGS:-} -O2 -g0 -ffile-prefix-map=$B=/usr/src/zfs"
export CXXFLAGS="${CXXFLAGS:-} -O2 -g0 -ffile-prefix-map=$B=/usr/src/zfs"
export KCFLAGS="${KCFLAGS:-} -fdebug-prefix-map=$B=/usr/src/zfs -fmacro-prefix-map=$B=/usr/src/zfs -fdebug-prefix-map=$KERNEL_SRC=/usr/src/linux -fmacro-prefix-map=$KERNEL_SRC=/usr/src/linux -fdebug-prefix-map=$KERNEL_BUILD=/usr/src/linux-build -fmacro-prefix-map=$KERNEL_BUILD=/usr/src/linux-build"
export KAFLAGS="${KAFLAGS:-} $KCFLAGS"
export KCPPFLAGS="${KCPPFLAGS:-} $KCFLAGS"
if [[ ! -d $src/.git ]]; then git init -q "$src"; git -C "$src" remote add origin https://github.com/openzfs/zfs.git; fi
git -C "$src" fetch -q --depth=1 origin "$ZFS_REVISION"
git -C "$src" checkout -q --detach FETCH_HEAD
git -C "$src" reset -q --hard "$ZFS_REVISION"
git -C "$src" clean -qfdx
patch -d "$src" -p1 --fuzz=0 < "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-zfs/dstack-zfs/0001-Define-strndupa-if-it-does-not-exist.patch"
(cd "$src" && ./autogen.sh)
mkdir -p "$B/build"
(cd "$B/build" && "$src/configure" --prefix=/usr --with-linux="$KERNEL_SRC" \
  --with-linux-obj="$KERNEL_BUILD" --with-config=all --enable-systemd \
  --disable-pyzfs --without-dracutdir --with-udevdir=/usr/lib/udev \
  --with-systemdunitdir=/usr/lib/systemd/system)
# External-module BTF goes through pahole 1.25's optimized encoder, whose
# output order is unstable. Kernel/in-tree BTF remains enabled; omit only ZFS
# module BTF, as is also done for NVIDIA's external modules.
make -C "$B/build" -j"${JOBS:-$(nproc)}" CONFIG_DEBUG_INFO_BTF_MODULES=
make -C "$B/build" CONFIG_DEBUG_INFO_BTF_MODULES= DESTDIR="$ROOT_STAGE" install
# ZFS installs kernel modules below DESTDIR/lib; merge them into usr-merge.
if [[ -d $ROOT_STAGE/lib/modules ]]; then
  mkdir -p "$KERNEL_STAGE/usr/lib/modules"
  cp -a "$ROOT_STAGE/lib/modules/." "$KERNEL_STAGE/usr/lib/modules/"
  rm -rf "${ROOT_STAGE:?}/lib/modules"
fi
rm -rf "$ROOT_STAGE/usr/share/zfs" "$ROOT_STAGE/usr/share/initramfs-tools"
ln -sfn usr/lib "$KERNEL_STAGE/lib"
depmod -b "$KERNEL_STAGE" "$KERNEL_VERSION-dstack"
rm -f "$KERNEL_STAGE/lib"
find "$ROOT_STAGE" "$KERNEL_STAGE" -print0 | xargs -0r touch -h -d "@${SOURCE_DATE_EPOCH:?}"
