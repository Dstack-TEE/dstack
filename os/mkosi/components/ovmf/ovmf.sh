# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=ovmf
COMPONENT_CACHE_PATHS=(component-stages/ovmf)
COMPONENT_ROOTFS_TREES=()
COMPONENT_KERNEL_TREES=(component-stages/ovmf)

component_cache_key() {
    key_value "$OVMF_REVISION" "$OVMF_VARIANT"
    key_file "$COMPONENT_PATH/ovmf-build.sh" \
      "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf/0003-Debug-prefix-map.patch" \
      "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf/0004-Reproduciable.patch" \
      "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf/0005-UefiCpuPkg-CpuExceptionHandlerLib-fix-push-instructi.patch" \
      "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf/0006-OvmfPkg-AmdSev-drop-embedded-grub.patch"
    key_tools gcc make python3
    key_packages nasm acpica-tools uuid-dev
}

component_build() {
    mkdir -p "$WORK/component-stages/ovmf/usr/lib/dstack/firmware"
    "$COMPONENT_PATH/ovmf-build.sh" "$WORK/ovmf-build" \
      "$WORK/component-stages/ovmf/usr/lib/dstack/firmware/ovmf.fd" \
      "$WORK/component-stages/ovmf/usr/lib/dstack/firmware/ovmf-sev.fd"
}
