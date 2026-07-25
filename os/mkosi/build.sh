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
# BuildSources= mounts and compiles the working tree, not HEAD, so without this
# an uncommitted change would produce an image whose guest agent and measured
# metadata.json both report a clean upstream revision. git_revision! marks this
# the same way when it derives the value itself.
dirty=
if ! git -C "$ROOT" diff --quiet HEAD -- || \
   [[ -n $(git -C "$ROOT" ls-files --others --exclude-standard) ]]; then
  if [[ ${DSTACK_ALLOW_DIRTY:-0} != 1 ]]; then
    echo "refusing to build from a dirty worktree: the recorded revision would" >&2
    echo "not describe the sources being compiled. Commit or stash the changes," >&2
    echo "or set DSTACK_ALLOW_DIRTY=1 to record the revision as -modified." >&2
    exit 1
  fi
  dirty=-modified
fi
# Distinct from the Yocto backend's DSTACK_GIT_REVISION, which is a bare SHA
# used for release metadata. This one is compiled into the binaries by
# dstack-build-info and must carry the "git:" display prefix.
export DSTACK_BUILD_GIT_REVISION=${DSTACK_BUILD_GIT_REVISION:-git:${revision:0:20}$dirty}
revision="$revision$dirty"
export TZ=UTC LC_ALL=C
# A production invocation reconstructs the tools tree once from the immutable
# snapshot, then shares that read-only environment across all requested flavors
# or both legs of repro-check.
if [[ $action != dev-image ]]; then
  # --directory only chdirs, and no OutputDirectory= is configured, so without
  # the same --output-directory the build uses, mkosi.clean would run its
  # removal against os/mkosi/ instead of the build tree.
  mkdir -p "$BUILD_DIR/out"
  mkosi --directory "$SELF" --output-directory="$BUILD_DIR/out" clean -f
fi

build_one() {
  local out=$1 flavor=$2 jobs=${3:-${JOBS:-$(nproc)}}
  mkdir -p "$out"
  mkosi_args=(
    --directory "$SELF"
    --force
    --output-directory="$out"
    --profile="$flavor"
    --source-date-epoch="$SOURCE_DATE_EPOCH"
    --environment="DSTACK_COMPONENT_CACHE=$([[ $action == dev-image ]] && echo 1 || echo 0)"
    --environment="DSTACK_BUILD_GIT_REVISION=$DSTACK_BUILD_GIT_REVISION"
    --environment="DSTACK_SOURCE_REVISION=$revision"
    --environment="JOBS=$jobs"
  )
  if [[ $action == dev-image ]]; then
    cache_root=${DSTACK_DEV_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/dstack/mkosi-dev}
    # The component cache must go through BuildDirectory, which mkosi
    # bind-mounts read-write and preserves between runs. A BuildSources mount
    # cannot hold it: BuildSourcesEphemeral=yes gives every source an overlay
    # whose upper layer is a temporary directory, so cache writes would be
    # discarded when the build script exits. The manifest is a read-only input
    # regenerated on each run, so an ephemeral source mount suits it fine.
    mkdir -p "$cache_root/build" "$cache_root/manifest"
    "$SELF/scripts/write-source-manifest.py" "$ROOT" \
      "$cache_root/manifest/source-manifest"
    mkosi_args+=(--build-directory="$cache_root/build")
    mkosi_args+=(--build-sources="$cache_root/manifest:component-cache")
    mkosi_args+=(--environment="DSTACK_SOURCE_MANIFEST=/work/src/component-cache/source-manifest")
  fi
  mkosi "${mkosi_args[@]}" build
}

if [[ $action == image || $action == dev-image ]]; then
  for flavor in $FLAVORS; do build_one "$BUILD_DIR/out/$flavor" "$flavor"; done
  exit
fi
# The two legs deliberately differ in job count as well as in path. Build
# output that depends on parallelism is a real failure mode here -- the kernel
# component carries a pahole wrapper precisely because its BTF encoder varied
# with Kbuild's job count -- and it is invisible when both legs run identically.
jobs_a=${JOBS:-$(nproc)}
jobs_b=${REPRO_JOBS_B:-$(( jobs_a > 1 ? (jobs_a + 1) / 2 : 1 ))}
echo "reproducibility check: leg a with $jobs_a jobs, leg b with $jobs_b jobs"
build_one "$BUILD_DIR/a" prod "$jobs_a"
build_one "$BUILD_DIR/b" prod "$jobs_b"
cmp "$BUILD_DIR/a/dstack-$DSTACK_VERSION.tar.gz" "$BUILD_DIR/b/dstack-$DSTACK_VERSION.tar.gz"
cmp "$BUILD_DIR/a/dstack-$DSTACK_VERSION-uki.tar.gz" \
  "$BUILD_DIR/b/dstack-$DSTACK_VERSION-uki.tar.gz"
echo 'reproducibility check passed'
