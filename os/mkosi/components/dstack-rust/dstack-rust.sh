# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=dstack-rust
COMPONENT_CACHE_PATHS=(component-stages/dstack-rust)
COMPONENT_ROOTFS_TREES=(component-stages/dstack-rust)
COMPONENT_KERNEL_TREES=()

component_cache_key() {
    key_file "$COMPONENT_PATH/dstack-rust-build.sh"
    key_tree dstack os/common/rootfs
    key_tools rustc cargo
}

component_build() {
    "$COMPONENT_PATH/dstack-rust-build.sh" "$WORK/component-stages/dstack-rust" "$FLAVOR"
}
