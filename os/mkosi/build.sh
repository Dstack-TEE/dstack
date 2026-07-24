#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 0022
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
command -v mkosi >/dev/null || { echo "mkosi $MKOSI_VERSION is required" >&2; exit 1; }
actual=$(mkosi --version | awk '{print $2}' | cut -d. -f1)
[[ $actual == "$MKOSI_VERSION" ]] || {
  echo "mkosi $MKOSI_VERSION required, found $actual" >&2; exit 1;
}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
revision=$(git -C "$ROOT" rev-parse HEAD)
export DSTACK_GIT_REVISION=${DSTACK_GIT_REVISION:-git:${revision:0:20}}
export TZ=UTC LC_ALL=C
# A production invocation reconstructs the tools tree once from the immutable
# snapshot, then shares that read-only environment across all requested flavors
# or both legs of repro-check.
if [[ $action != dev-image ]]; then
  mkosi --directory "$SELF" clean -f
fi

build_one() {
  local out=$1 work=$2 flavor=$3
  rm -rf "$work" "$out"; mkdir -p "$out"
  mkosi_args=(
    --directory "$SELF"
    --force
    --format=none
    --output-directory="$out"
    --compress-output=no
    --bootable=no
    --environment="DSTACK_BUILD_FLAVOR=$flavor"
    --environment="DSTACK_COMPONENT_CACHE=$([[ $action == dev-image ]] && echo 1 || echo 0)"
    --environment="DSTACK_GIT_REVISION=$DSTACK_GIT_REVISION"
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
