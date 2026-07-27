# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=sysbox
COMPONENT_CACHE_PATHS=(component-stages/sysbox)
COMPONENT_ROOTFS_TREES=(component-stages/sysbox)
COMPONENT_KERNEL_TREES=()

component_cache_key() {
    key_value "$SYSBOX_VERSION" "$SYSBOX_REVISION" "$SYSBOX_RUNC_REVISION" \
      "$SYSBOX_FS_REVISION" "$SYSBOX_MGR_REVISION" "$SYSBOX_IPC_REVISION" \
      "$SYSBOX_LIBS_REVISION" "$SYSBOX_FUSE_REVISION"
    key_file "$COMPONENT_PATH/sysbox-build.sh"
    key_tree os/yocto/layers/meta-dstack/recipes-core/dstack-sysbox
    key_tools go
    key_packages libseccomp-dev
}

component_build() {
    "$COMPONENT_PATH/sysbox-build.sh" "$WORK/sysbox-build" \
      "$WORK/component-stages/sysbox"
}
