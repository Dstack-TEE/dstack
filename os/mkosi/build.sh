#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SELF/../.." && pwd)
# shellcheck source=/dev/null
source "$SELF/versions.env"
FLAVORS=${FLAVORS:-prod}
action=${1:-image}
BUILD_DIR=${2:-$SELF/build}
BUILD_DIR=$(realpath -m "$BUILD_DIR")
case "$action" in
  image|dev-image|repro-check|lint) ;;
  *) echo "Usage: $0 {image|dev-image|repro-check|lint} [build-dir]" >&2; exit 2 ;;
esac
if [[ $action == lint ]]; then exec "$SELF/tests/acceptance.sh"; fi
command -v mkosi >/dev/null || { echo 'mkosi >= 26 is required' >&2; exit 1; }
actual=$(mkosi --version | awk '{print $2}' | cut -d. -f1)
(( actual >= MKOSI_MIN_VERSION )) || { echo "mkosi >= $MKOSI_MIN_VERSION required" >&2; exit 1; }
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
export TZ=UTC LC_ALL=C

build_one() {
  local out=$1 work=$2 flavor=$3
  local kstage="$work/kernel-stage" tree="$work/rootfs"
  rm -rf "$work" "$out"; mkdir -p "$out"

  mkosi_args=(
    --directory "$SELF"
    --force
    --format=directory
    --output-directory="$work"
    --output=rootfs
    --compress-output=no
    --bootable=no
    --environment="DSTACK_BUILD_FLAVOR=$flavor"
    --environment="DSTACK_COMPONENT_CACHE=$([[ $action == dev-image ]] && echo 1 || echo 0)"
    --environment="JOBS=${JOBS:-$(nproc)}"
  )
  if [[ $action == dev-image ]]; then
    cache_root=${DSTACK_DEV_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/dstack/mkosi-dev}
    mkdir -p "$cache_root"
    mkosi_args+=(--build-sources="$cache_root:component-cache")
  fi
  if [[ $flavor == dev ]]; then
    mkosi_args+=(--package=strace --package=tcpdump --package=gdb --package=vim \
      --package=openssh-server)
  fi
  mkosi "${mkosi_args[@]}" build

  mkdir -p "$kstage/usr/lib"
  cp -a "$tree/usr/lib/modules" "$kstage/usr/lib/"
  install -m0644 "$tree/usr/lib/dstack/firmware/ovmf.fd" "$kstage/ovmf.fd"
  install -m0644 "$tree/usr/lib/dstack/firmware/ovmf-sev.fd" "$kstage/ovmf-sev.fd"
  rm -rf "$tree/usr/lib/dstack/firmware"
  if [[ $flavor == prod ]]; then
    "$SELF/scripts/prune-rootfs.sh" "$tree"
  fi
  # ldconfig's binary auxiliary cache records traversal-dependent ordering.
  # /var is volatile at runtime, so ship no host-generated cache.
  rm -f "$tree/var/cache/ldconfig/aux-cache"
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
cmp "$BUILD_DIR/a/dstack-$DSTACK_VERSION.tar.gz" "$BUILD_DIR/b/dstack-$DSTACK_VERSION.tar.gz"
cmp "$BUILD_DIR/a/dstack-$DSTACK_VERSION-uki.tar.gz" \
  "$BUILD_DIR/b/dstack-$DSTACK_VERSION-uki.tar.gz"
echo 'reproducibility check passed'
