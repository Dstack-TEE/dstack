# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=kernel
COMPONENT_CACHE_PATHS=("linux-$KERNEL_VERSION" kernel-build component-stages/kernel)
COMPONENT_ROOTFS_TREES=()
COMPONENT_KERNEL_TREES=(component-stages/kernel)

component_cache_key() {
    key_value "$KERNEL_VERSION" "$KERNEL_SHA256"
    key_file "$COMPONENT_PATH/kernel-build.sh" "$COMPONENT_PATH/kernel.config" \
      "$ROOT/os/yocto/layers/meta-dstack/recipes-kernel/linux/files/0001-x86-tdx-select-dma-direct-remap.patch" \
      "$ROOT/os/yocto/layers/meta-dstack/recipes-kernel/linux/files/0002-acpi-sandbox-block-aml-systemmemory-ram-access.patch"
    key_tools gcc ld make pahole
    key_packages binutils dwarves bc bison flex libssl-dev libelf-dev
}

component_build() {
    "$COMPONENT_PATH/kernel-build.sh" "$WORK" "$WORK/component-stages/kernel"
}
