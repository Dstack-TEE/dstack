# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=nvattest
COMPONENT_CACHE_PATHS=(component-stages/nvattest)
COMPONENT_ROOTFS_TREES=(component-stages/nvattest)
COMPONENT_KERNEL_TREES=()

component_cache_key() {
    key_value "$NVATTEST_VERSION" "$NVATTEST_REVISION"
    key_file "$COMPONENT_PATH/nvattest-build.sh" \
      "$COMPONENT_PATH/patches/0001-pin-fetchcontent-inputs.patch"
    key_tree os/yocto/layers/meta-nvidia/recipes-graphics/nvattest
    key_tools gcc cmake ninja rustc cargo
    key_packages libssl-dev libcurl4-openssl-dev
}

component_build() {
    "$COMPONENT_PATH/nvattest-build.sh" "$WORK/nvattest-build" \
      "$WORK/component-stages/nvattest"
}
