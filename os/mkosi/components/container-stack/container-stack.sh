# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=container-stack
COMPONENT_CACHE_PATHS=(component-stages/container-stack)
COMPONENT_ROOTFS_TREES=(component-stages/container-stack)
COMPONENT_KERNEL_TREES=()

component_cache_key() {
    key_value "$NVIDIA_CONTAINER_TOOLKIT_REVISION" "$LIBNVIDIA_CONTAINER_REVISION" \
      "$NERDCTL_VERSION" "$NERDCTL_SHA256" "$CNI_VERSION" "$CNI_SHA256" \
      "$STARGZ_VERSION" "$STARGZ_SHA256"
    key_file "$COMPONENT_PATH/container-stack-build.sh" \
      "$COMPONENT_PATH/patches/0001-omit-prefix-map-from-build-flags.patch"
    key_tree os/yocto/layers/meta-nvidia/recipes-graphics/nvidia-container-toolkit \
      os/yocto/layers/meta-dstack/recipes-containers
    key_tools gcc go
    key_packages libelf-dev libtirpc-dev
}

component_build() {
    "$COMPONENT_PATH/container-stack-build.sh" "$WORK/container-stack-build" \
      "$WORK/component-stages/container-stack"
}
