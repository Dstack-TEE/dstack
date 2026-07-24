# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=image-tools
COMPONENT_CACHE_PATHS=(component-stages/image-tools image-tools-target)
COMPONENT_ROOTFS_TREES=(component-stages/image-tools)
COMPONENT_KERNEL_TREES=()

component_cache_key() {
    key_value "$NITRO_TPM_TOOLS_REVISION"
    key_file "$COMPONENT_PATH/image-tools-build.sh"
    key_tree dstack/Cargo.toml dstack/Cargo.lock dstack/dstack-mr
    key_tools rustc cargo
    key_packages libssl-dev
}

component_build() {
    "$COMPONENT_PATH/image-tools-build.sh" \
      "$WORK/image-tools-target" "$WORK/component-stages/image-tools"
}
