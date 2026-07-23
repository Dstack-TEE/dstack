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
component_cache_args=()
[[ $action == dev-image ]] && component_cache_args+=(--dev-cache)
command -v mkosi >/dev/null || { echo 'mkosi >= 26 is required' >&2; exit 1; }
actual=$(mkosi --version | awk '{print $2}' | cut -d. -f1)
(( actual >= MKOSI_MIN_VERSION )) || { echo "mkosi >= $MKOSI_MIN_VERSION required" >&2; exit 1; }
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
export TZ=UTC LC_ALL=C

build_one() {
  local out=$1 work=$2 flavor=$3
  local stage="$work/rootfs-stage" kstage="$work/kernel-stage" tree="$work/rootfs"
  rm -rf "$work" "$out"; mkdir -p "$stage" "$kstage" "$out"
  "$SELF/scripts/build-components.sh" "${component_cache_args[@]}" \
    "$work" "$stage" "$kstage" "$flavor"
  if [[ $flavor == prod ]]; then
    # Yocto splits module DWARF into debug packages which are not shipped in
    # the production image. Keep BTF and loadable ELF metadata, but do not put
    # hundreds of MiB of host-side DWARF into the immutable guest root.
    find "$kstage/usr/lib/modules" -type f -name '*.ko' -exec objcopy --strip-debug {} +
  fi
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
