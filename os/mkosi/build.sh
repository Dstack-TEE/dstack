#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SELF/../.." && pwd)
source "$SELF/versions.env"
action=${1:-image}
BUILD_DIR=${2:-$SELF/build}
case "$action" in
  image|repro-check|lint) ;;
  *) echo "Usage: $0 {image|repro-check|lint} [build-dir]" >&2; exit 2 ;;
esac
if [[ $action == lint ]]; then exec "$SELF/tests/acceptance.sh"; fi
command -v mkosi >/dev/null || { echo 'mkosi >= 26 is required' >&2; exit 1; }
actual=$(mkosi --version | awk '{print $2}' | cut -d. -f1)
(( actual >= MKOSI_MIN_VERSION )) || { echo "mkosi >= $MKOSI_MIN_VERSION required" >&2; exit 1; }
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
export TZ=UTC LC_ALL=C

build_one() {
  local out=$1 work=$2 flavor=$3
  local stage="$work/rootfs-stage" kstage="$work/kernel-stage" tree="$work/rootfs"
  rm -rf "$work" "$out"; mkdir -p "$stage" "$kstage" "$out"
  "$SELF/scripts/stage-rootfs.sh" "$stage"
  "$SELF/scripts/build-kernel.sh" "$work" "$kstage"
  "$SELF/scripts/build-ovmf.sh" "$work/ovmf-build" "$kstage/ovmf.fd"
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
    devargs+=(--package=strace --package=tcpdump --package=gdb --package=vim)
  fi
  mkosi --directory "$SELF" --force --extra-tree="$stage" "${devargs[@]}" \
    --format=directory --output-directory="$work" --output=rootfs \
    --compress-output=no --bootable=no build
  mkdir -p "$tree/usr/lib/modules"
  cp -a "$kstage/usr/lib/modules/." "$tree/usr/lib/modules/"
  artifact_dir="$work/artifacts/$flavor"
  "$SELF/scripts/make-release-artifacts.sh" "$tree" "$kstage" "$artifact_dir" "$flavor"
  DIST_DIR="$out" \
    TAR_OPTIONS="--sort=name --mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner" \
    "$ROOT/os/image/assemble.sh" --manifest "$artifact_dir/artifact-manifest.json"
  release_name=dstack
  [[ $flavor == dev ]] && release_name=dstack-dev
  "$SELF/tests/check-output.sh" "$out/$release_name-$DSTACK_VERSION" "$flavor"
}

if [[ $action == image ]]; then
  for flavor in $FLAVORS; do build_one "$BUILD_DIR/out/$flavor" "$BUILD_DIR/work-$flavor" "$flavor"; done
  exit
fi
build_one "$BUILD_DIR/a" "$BUILD_DIR/work-a" prod
build_one "$BUILD_DIR/b" "$BUILD_DIR/work-b" prod
cmp "$BUILD_DIR/a/dstack-0.6.0.tar.gz" "$BUILD_DIR/b/dstack-0.6.0.tar.gz"
echo 'reproducibility check passed'
