#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Build and compose every non-Debian guest component. Cache-aware staging is
# kept here so the release pipeline in build.sh remains cache-agnostic.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SELF="$ROOT/os/mkosi"
# shellcheck source=/dev/null
source "$SELF/versions.env"
# shellcheck source=/dev/null
source "$SELF/scripts/dev-cache.sh"

use_cache=0
if [[ ${1:-} == --dev-cache ]]; then use_cache=1; shift; fi
WORK=$(realpath -m "${1:?work directory required}")
STAGE=$(realpath -m "${2:?rootfs staging tree required}")
KSTAGE=$(realpath -m "${3:?kernel staging tree required}")
FLAVOR=${4:?flavor required}
COMPONENTS="$WORK/component-stages"
mkdir -p "$STAGE" "$KSTAGE" "$COMPONENTS"
dev_cache_init "$use_cache" "$ROOT" "$FLAVOR" "${SOURCE_DATE_EPOCH:?}"

merge() { cp -a "$1/." "$2/"; }

root="$COMPONENTS/dstack-rust"
dev_cache_run dstack-rust "$WORK" component-stages/dstack-rust -- \
  "$SELF/scripts/stage-rootfs.sh" "$root" "$FLAVOR"
merge "$root" "$STAGE"

root="$COMPONENTS/container-stack"
dev_cache_run container-stack "$WORK" component-stages/container-stack -- \
  "$SELF/scripts/build-container-stack.sh" "$WORK/container-stack-build" "$root"
merge "$root" "$STAGE"

root="$COMPONENTS/sysbox"
dev_cache_run sysbox "$WORK" component-stages/sysbox -- \
  "$SELF/scripts/build-sysbox.sh" "$WORK/sysbox-build" "$root"
merge "$root" "$STAGE"

root="$COMPONENTS/nvattest"
dev_cache_run nvattest "$WORK" component-stages/nvattest -- \
  "$SELF/scripts/build-nvattest.sh" "$WORK/nvattest-build" "$root"
merge "$root" "$STAGE"

dev_cache_run kernel "$WORK" "linux-$KERNEL_VERSION" kernel-build kernel-stage -- \
  "$SELF/scripts/build-kernel.sh" "$WORK" "$KSTAGE"

root="$COMPONENTS/nvidia-root" modules="$COMPONENTS/nvidia-kernel"
dev_cache_run nvidia "$WORK" component-stages/nvidia-root component-stages/nvidia-kernel -- \
  "$SELF/scripts/build-nvidia.sh" "$WORK/nvidia-build" \
    "$WORK/linux-$KERNEL_VERSION" "$WORK/kernel-build" "$root" "$modules"
merge "$root" "$STAGE"; merge "$modules" "$KSTAGE"

root="$COMPONENTS/zfs-root" modules="$COMPONENTS/zfs-kernel"
dev_cache_run zfs "$WORK" component-stages/zfs-root component-stages/zfs-kernel -- \
  "$SELF/scripts/build-zfs.sh" "$WORK/zfs-build" \
    "$WORK/linux-$KERNEL_VERSION" "$WORK/kernel-build" "$root" "$modules"
merge "$root" "$STAGE"; merge "$modules" "$KSTAGE"

root="$COMPONENTS/ovmf"; mkdir -p "$root"
dev_cache_run ovmf "$WORK" component-stages/ovmf -- \
  "$SELF/scripts/build-ovmf.sh" "$WORK/ovmf-build" \
    "$root/ovmf.fd" "$root/ovmf-sev.fd"
install -Dm0644 "$root/ovmf.fd" "$KSTAGE/ovmf.fd"
install -Dm0644 "$root/ovmf-sev.fd" "$KSTAGE/ovmf-sev.fd"
