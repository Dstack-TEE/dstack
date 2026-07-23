# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=nvattest
COMPONENT_CACHE_PATHS=(component-stages/nvattest)
COMPONENT_ROOTFS_TREES=(component-stages/nvattest)
COMPONENT_KERNEL_TREES=()

component_cache_key() {
    key_value "$NVATTEST_VERSION" "$NVATTEST_REVISION"
    key_file "$SELF/scripts/build-nvattest.sh"
    key_tree os/mkosi/patches/nvattest \
      os/yocto/layers/meta-nvidia/recipes-graphics/nvattest
    key_tools gcc cmake ninja rustc cargo
    key_packages libssl-dev libcurl4-openssl-dev
}

component_build() {
    "$SELF/scripts/build-nvattest.sh" "$WORK/nvattest-build" \
      "$WORK/component-stages/nvattest"
}
