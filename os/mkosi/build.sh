#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SELF/../.." && pwd)
# shellcheck source=/dev/null
source "$SELF/versions.env"
action=${1:-image}
BUILD_DIR=${2:-$SELF/build}
BUILD_DIR=$(realpath -m "$BUILD_DIR")
case "$action" in
  image|dev-image|repro-check|lint) ;;
  *) echo "Usage: $0 {image|dev-image|repro-check|lint} [build-dir]" >&2; exit 2 ;;
esac
if [[ $action == lint ]]; then exec "$SELF/tests/acceptance.sh"; fi
unset DSTACK_DEV_CACHE_ACTIVE
[[ $action == dev-image ]] && export DSTACK_DEV_CACHE_ACTIVE=1
# shellcheck source=/dev/null
source "$SELF/scripts/dev-cache.sh"
command -v mkosi >/dev/null || { echo 'mkosi >= 26 is required' >&2; exit 1; }
actual=$(mkosi --version | awk '{print $2}' | cut -d. -f1)
(( actual >= MKOSI_MIN_VERSION )) || { echo "mkosi >= $MKOSI_MIN_VERSION required" >&2; exit 1; }
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
export TZ=UTC LC_ALL=C

build_one() {
  local out=$1 work=$2 flavor=$3
  local stage="$work/rootfs-stage" kstage="$work/kernel-stage" tree="$work/rootfs"
  local components="$work/component-stages" source_fingerprint=disabled tool_fingerprint=disabled
  rm -rf "$work" "$out"; mkdir -p "$stage" "$kstage" "$out" "$components"
  if [[ ${DSTACK_DEV_CACHE_ACTIVE:-0} == 1 ]]; then
    source_fingerprint=$(
      git -C "$ROOT" ls-files -z --cached --others --exclude-standard -- \
        dstack os/common os/mkosi os/yocto/layers/meta-dstack \
        os/yocto/layers/meta-nvidia \
      | sort -z | while IFS= read -r -d '' input; do
          if [[ -f $ROOT/$input ]]; then
            sha256sum "$ROOT/$input"
          elif [[ -d $ROOT/$input ]]; then
            printf 'gitlink %s %s\n' "$input" \
              "$(git -C "$ROOT/$input" rev-parse HEAD)"
          else
            printf 'missing %s\n' "$input"
          fi
        done | sha256sum | cut -d' ' -f1
    )
    tool_fingerprint=$({
      gcc --version | head -1; ld --version | head -1; go version
      rustc --version; cargo --version; cmake --version | head -1
      make --version | head -1; pahole --version; tar --version | head -1
    } | sha256sum | cut -d' ' -f1)
  fi
  component_key() {
    dev_cache_key "$1" "$flavor" "$source_fingerprint" \
      "$tool_fingerprint" "$SOURCE_DATE_EPOCH" "$(uname -m)"
  }
  merge_stage() { cp -a "$1/." "$2/"; }

  base_stage="$components/dstack-rust"
  dev_cache_run dstack-rust "$(component_key dstack-rust)" "$work" 1 \
    component-stages/dstack-rust -- \
    "$SELF/scripts/stage-rootfs.sh" "$base_stage" "$flavor"
  merge_stage "$base_stage" "$stage"

  container_stage="$components/container-stack"
  dev_cache_run container-stack "$(component_key container-stack)" "$work" 1 \
    component-stages/container-stack -- \
    "$SELF/scripts/build-container-stack.sh" "$work/container-stack-build" "$container_stage"
  merge_stage "$container_stage" "$stage"

  sysbox_stage="$components/sysbox"
  dev_cache_run sysbox "$(component_key sysbox)" "$work" 1 \
    component-stages/sysbox -- \
    "$SELF/scripts/build-sysbox.sh" "$work/sysbox-build" "$sysbox_stage"
  merge_stage "$sysbox_stage" "$stage"

  nvattest_stage="$components/nvattest"
  dev_cache_run nvattest "$(component_key nvattest)" "$work" 1 \
    component-stages/nvattest -- \
    "$SELF/scripts/build-nvattest.sh" "$work/nvattest-build" "$nvattest_stage"
  merge_stage "$nvattest_stage" "$stage"

  dev_cache_run kernel "$(component_key kernel)" "$work" 3 \
    "linux-$KERNEL_VERSION" kernel-build kernel-stage -- \
    "$SELF/scripts/build-kernel.sh" "$work" "$kstage"

  nvidia_root="$components/nvidia-root" nvidia_kernel="$components/nvidia-kernel"
  dev_cache_run nvidia "$(component_key nvidia)" "$work" 2 \
    component-stages/nvidia-root component-stages/nvidia-kernel -- \
    "$SELF/scripts/build-nvidia.sh" "$work/nvidia-build" \
      "$work/linux-$KERNEL_VERSION" "$work/kernel-build" "$nvidia_root" "$nvidia_kernel"
  merge_stage "$nvidia_root" "$stage"; merge_stage "$nvidia_kernel" "$kstage"

  zfs_root="$components/zfs-root" zfs_kernel="$components/zfs-kernel"
  dev_cache_run zfs "$(component_key zfs)" "$work" 2 \
    component-stages/zfs-root component-stages/zfs-kernel -- \
    "$SELF/scripts/build-zfs.sh" "$work/zfs-build" \
      "$work/linux-$KERNEL_VERSION" "$work/kernel-build" "$zfs_root" "$zfs_kernel"
  merge_stage "$zfs_root" "$stage"; merge_stage "$zfs_kernel" "$kstage"

  ovmf_stage="$components/ovmf"; mkdir -p "$ovmf_stage"
  dev_cache_run ovmf "$(component_key ovmf)" "$work" 1 component-stages/ovmf -- \
    "$SELF/scripts/build-ovmf.sh" "$work/ovmf-build" \
      "$ovmf_stage/ovmf.fd" "$ovmf_stage/ovmf-sev.fd"
  install -Dm0644 "$ovmf_stage/ovmf.fd" "$kstage/ovmf.fd"
  install -Dm0644 "$ovmf_stage/ovmf-sev.fd" "$kstage/ovmf-sev.fd"
  # ExtraTrees is copied over Debian's usr-merged root where /bin, /sbin and
  # /lib are symlinks. Normalize build systems (notably OpenZFS) that install
  # into the legacy physical directories before handing the tree to mkosi.
  for legacy in bin sbin lib lib64; do
    if [[ -d $stage/$legacy && ! -L $stage/$legacy ]]; then
      mkdir -p "$stage/usr/$legacy"
      cp -a "$stage/$legacy/." "$stage/usr/$legacy/"
      rm -rf "${stage:?}/$legacy"
    fi
  done
  cat > "$work/mkosi.local.conf" <<EOF
[Content]
ExtraTrees=$stage
Bootable=no
[Output]
Format=directory
OutputDirectory=$work
Output=rootfs
CompressOutput=no
EOF
  if [[ $flavor == dev ]]; then
    cat >> "$work/mkosi.local.conf" <<EOF
[Content]
Packages=strace,tcpdump,gdb,vim
EOF
  fi
  devargs=()
  if [[ $flavor == dev ]]; then
    devargs+=(--package=strace --package=tcpdump --package=gdb --package=vim \
      --package=openssh-server)
  fi
  mkosi --directory "$SELF" --force --extra-tree="$stage" "${devargs[@]}" \
    --format=directory --output-directory="$work" --output=rootfs \
    --compress-output=no --bootable=no build
  # ldconfig's binary auxiliary cache records traversal-dependent ordering.
  # /var is volatile at runtime, so ship no host-generated cache.
  rm -f "$tree/var/cache/ldconfig/aux-cache"
  mkdir -p "$tree/usr/lib/modules"
  cp -a "$kstage/usr/lib/modules/." "$tree/usr/lib/modules/"
  "$SELF/tests/check-parity.py" "$SELF/parity.json" "$tree" "$kstage" "$flavor"
  artifact_dir="$work/artifacts/$flavor"
  "$SELF/scripts/make-release-artifacts.sh" "$tree" "$kstage" "$artifact_dir" "$flavor"
  DIST_DIR="$out" \
    TAR_OPTIONS="--sort=name --mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner" \
    "$ROOT/os/image/assemble.sh" --manifest "$artifact_dir/artifact-manifest.json"
  release_name=dstack
  [[ $flavor == dev ]] && release_name=dstack-dev
  "$SELF/tests/check-output.sh" "$out/$release_name-$DSTACK_VERSION" "$flavor"
}

if [[ $action == image || $action == dev-image ]]; then
  for flavor in $FLAVORS; do build_one "$BUILD_DIR/out/$flavor" "$BUILD_DIR/work-$flavor" "$flavor"; done
  exit
fi
build_one "$BUILD_DIR/a" "$BUILD_DIR/work-a" prod
build_one "$BUILD_DIR/b" "$BUILD_DIR/work-b" prod
cmp "$BUILD_DIR/a/dstack-0.6.0.tar.gz" "$BUILD_DIR/b/dstack-0.6.0.tar.gz"
echo 'reproducibility check passed'
