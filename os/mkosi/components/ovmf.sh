# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=ovmf
COMPONENT_CACHE_PATHS=(component-stages/ovmf)
COMPONENT_ROOTFS_TREES=()
COMPONENT_KERNEL_TREES=(component-stages/ovmf)

component_cache_key() {
    key_file "$SELF/scripts/build-ovmf.sh" \
      "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf/0004-Reproduciable.patch"
    key_tools gcc make python3
    key_packages nasm acpica-tools uuid-dev
}

component_build() {
    mkdir -p "$WORK/component-stages/ovmf"
    "$SELF/scripts/build-ovmf.sh" "$WORK/ovmf-build" \
      "$WORK/component-stages/ovmf/ovmf.fd" \
      "$WORK/component-stages/ovmf/ovmf-sev.fd"
}
