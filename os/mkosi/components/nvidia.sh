# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=nvidia
COMPONENT_CACHE_PATHS=(component-stages/nvidia-root component-stages/nvidia-kernel)
COMPONENT_ROOTFS_TREES=(component-stages/nvidia-root)
COMPONENT_KERNEL_TREES=(component-stages/nvidia-kernel)

component_cache_key() {
    key_dependency kernel
    key_value "$NVIDIA_VERSION" "$NVIDIA_RUN_SHA256" \
      "$NVIDIA_FABRICMANAGER_SHA256" "$NVIDIA_NSCQ_SHA256"
    key_file "$SELF/scripts/build-nvidia.sh" \
      "$SELF/patches/nvidia/0001-linux-7.1-drop-legacy-of-gpio-api.patch"
    key_tree os/yocto/layers/meta-nvidia/recipes-graphics/nvidia
    key_tools gcc make
}

component_build() {
    "$SELF/scripts/build-nvidia.sh" "$WORK/nvidia-build" \
      "$WORK/linux-$KERNEL_VERSION" "$WORK/kernel-build" \
      "$WORK/component-stages/nvidia-root" "$WORK/component-stages/nvidia-kernel"
}

component_prepare_outputs() {
    find "$WORK/component-stages/nvidia-kernel/usr/lib/modules" -maxdepth 2 \
      -type f -name 'modules.*' -delete
}
