# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=zfs
COMPONENT_CACHE_PATHS=(component-stages/zfs-root component-stages/zfs-kernel)
COMPONENT_ROOTFS_TREES=(component-stages/zfs-root)
COMPONENT_KERNEL_TREES=(component-stages/zfs-kernel)

component_cache_key() {
    key_dependency kernel
    key_value "$ZFS_VERSION" "$ZFS_REVISION"
    key_file "$COMPONENT_PATH/zfs-build.sh" \
      "$COMPONENT_PATH/patches/0001-linux-6.19-7.1-compat.patch" \
      "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-zfs/dstack-zfs/0001-Define-strndupa-if-it-does-not-exist.patch"
    key_tools gcc make autoconf automake
    key_packages libssl-dev libelf-dev zlib1g-dev libtool uuid-dev
}

component_build() {
    "$COMPONENT_PATH/zfs-build.sh" "$WORK/zfs-build" \
      "$WORK/linux-$KERNEL_VERSION" "$WORK/kernel-build" \
      "$WORK/component-stages/zfs-root" "$WORK/component-stages/zfs-kernel"
}

component_prepare_outputs() {
    find "$WORK/component-stages/zfs-kernel/usr/lib/modules" -maxdepth 2 \
      -type f -name 'modules.*' -delete
}
