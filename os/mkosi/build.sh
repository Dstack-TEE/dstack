#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 0022
SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SELF/../.." && pwd)
# shellcheck source=/dev/null
source "$SELF/versions.env"
FLAVORS=${FLAVORS:-prod}
usage="Usage: $0 [--no-cache] [--archive] {image|repro-check|lint} [build-dir]"
# The component cache is keyed on every declared input of each component, so a
# hit reproduces the same output a cold build would have produced. Reusing it is
# therefore the sensible default; --no-cache forces the cold path for a release
# build or when the key itself is what needs auditing. repro-check ignores both
# and always builds cold, because a cache hit would answer the wrong question.
cache=${DSTACK_COMPONENT_CACHE:-1}
# The two release tarballs are ~58 s of gzip over artifacts that already exist
# unpacked beside them. A cached build is an iteration build, and iterating on
# the guest wants disk.raw and the measurements, not a redistributable archive
# -- so a cached build skips them and a cold build still produces them. Pass
# --archive to get them out of a cached build anyway. Left unset here so the
# default can be derived from the final value of $cache below.
archive=${DSTACK_TAR_RELEASE:-}
action=
BUILD_DIR=
while [ $# -gt 0 ]; do
  case "$1" in
    --no-cache) cache=0 ;;
    --archive) archive=1 ;;
    -h|--help) echo "$usage"; exit 0 ;;
    -*) echo "Unknown option: $1" >&2; echo "$usage" >&2; exit 2 ;;
    *)
      if [[ -z $action ]]; then action=$1
      elif [[ -z $BUILD_DIR ]]; then BUILD_DIR=$1
      else echo "Unexpected argument: $1" >&2; echo "$usage" >&2; exit 2
      fi
      ;;
  esac
  shift
done
action=${action:-image}
BUILD_DIR=$(realpath -m "${BUILD_DIR:-$SELF/build}")
case "$action" in
  image|repro-check|lint) ;;
  *) echo "$usage" >&2; exit 2 ;;
esac
if [[ $action == repro-check ]]; then cache=0; fi
[[ $cache == 1 || $cache == 0 ]] || {
  echo "DSTACK_COMPONENT_CACHE must be 0 or 1, got: $cache" >&2; exit 2;
}
# Derived after repro-check has forced the cold path, so repro-check always
# archives: it compares the two release tarballs, and skipping them would leave
# it comparing nothing and passing vacuously.
archive=${archive:-$(( cache == 1 ? 0 : 1 ))}
# Not merely defaulted: forced. repro-check compares the two release tarballs,
# so an environment that switched archiving off would leave it comparing files
# that do not exist -- a check that fails for the wrong reason, or worse, is
# read as "no difference found".
if [[ $action == repro-check ]]; then archive=1; fi
[[ $archive == 1 || $archive == 0 ]] || {
  echo "DSTACK_TAR_RELEASE must be 0 or 1, got: $archive" >&2; exit 2;
}
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
# A cold invocation reconstructs the tools tree once from the immutable
# snapshot, then shares that read-only environment across all requested flavors
# or both legs of repro-check. A cached invocation keeps it, because rebuilding
# the tools overlay every run is exactly the cost the cache exists to avoid.
if [[ $cache == 0 ]]; then
  # --directory only chdirs, and no OutputDirectory= is configured, so without
  # the same --output-directory the build uses, mkosi.clean would run its
  # removal against os/mkosi/ instead of the build tree.
  mkdir -p "$BUILD_DIR/out"
  mkosi --directory "$SELF" --output-directory="$BUILD_DIR/out" clean -f
fi

# Digest of every input that determines the incrementally cached tree: the
# package lists and distribution pins in the configs, and the skeleton files
# copied in before packages are installed. Deliberately not the dstack sources
# or the component definitions -- those are consumed by the build script, which
# runs after the cache is restored, and folding them in would defeat the cache
# on every source edit. Sorted for a stable digest, and the file list itself is
# hashed too so that deleting a skeleton file also moves the key.
base_inputs_digest() {
  {
    find "$SELF/mkosi.skeleton" -type f -o -type l | sort
    echo "--"
    cat "$SELF/mkosi.conf" "$SELF/mkosi.tools.conf"
    for f in "$SELF"/mkosi.profiles/*/mkosi.conf; do
      echo "-- $f"
      cat "$f"
    done
    find "$SELF/mkosi.skeleton" -type f -print0 | sort -z | xargs -0 -r sha256sum
    find "$SELF/mkosi.skeleton" -type l -print0 | sort -z | \
      while IFS= read -r -d '' link; do
        printf '%s -> %s\n' "$link" "$(readlink "$link")"
      done
  } | sha256sum | cut -c1-32
}

build_one() {
  local out=$1 flavor=$2 jobs=${3:-${JOBS:-$(nproc)}}
  mkdir -p "$out"
  mkosi_args=(
    --directory "$SELF"
    --force
    --output-directory="$out"
    --profile="$flavor"
    --source-date-epoch="$SOURCE_DATE_EPOCH"
    --environment="DSTACK_COMPONENT_CACHE=$cache"
    --environment="DSTACK_TAR_RELEASE=$archive"
    --environment="DSTACK_BUILD_GIT_REVISION=$DSTACK_BUILD_GIT_REVISION"
    --environment="DSTACK_SOURCE_REVISION=$revision"
    --environment="JOBS=$jobs"
  )
  if [[ $cache == 1 ]]; then
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
    # mkosi's incremental cache captures the tree after the distribution and
    # build packages are installed and before any build script runs, which is
    # exactly the ~70 s this build otherwise repeats verbatim every time.
    #
    # It cannot be enabled as-is. mkosi keys the cache on CacheKey=, whose
    # default is &d~&r~&a~&I -- distribution, release, architecture, image id --
    # and whose specifier set contains no digest of the inputs that actually
    # determine that tree. Editing Packages= in mkosi.conf, or any file under
    # mkosi.skeleton/, leaves the key untouched, so mkosi would restore the
    # stale tree and the change would silently not be in the image. Mixing the
    # digest below into the key restores the invalidation mkosi does not do.
    base_digest=$(base_inputs_digest)
    mkosi_args+=(--incremental=yes)
    mkosi_args+=(--cache-directory="$cache_root/incremental")
    mkosi_args+=(--cache-key="&d~&r~&a~&I~$base_digest")
    # Package downloads are content-addressed by the pinned Snapshot=, so this
    # only avoids refetching identical files. Release builds still take the
    # cold path and fetch from the snapshot themselves.
    mkosi_args+=(--package-cache-directory="$cache_root/packages")
  fi
  mkosi "${mkosi_args[@]}" build
  # mkosi's own output is a plain Debian rootfs: unmeasured, not part of the
  # release contract, and it would otherwise sit beside the release artifacts.
  # It can only be removed after mkosi returns, because build_image() stats it
  # once more to report its size after the postoutput scripts have run.
  rm -f "$out/dstack-$DSTACK_VERSION-rootfs.tar" \
        "$out/dstack-$DSTACK_VERSION-rootfs"
}

if [[ $action == image ]]; then
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
