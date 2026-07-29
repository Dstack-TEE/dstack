#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
D=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=/dev/null
source "$D/scripts/dev-cache.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export DSTACK_DEV_CACHE_DIR="$tmp/cache"
base="$tmp/work"
count="$tmp/count"

build_output() {
    mkdir -p "$base/stage"
    printf 'payload:%s\n' "$1" > "$base/stage/file"
    printf x >> "$count"
}

dev_cache_init 1
dev_cache_run component key-v1 "$base" stage -- build_output v1
[[ $(cat "$base/stage/file") == payload:v1 && $(cat "$count") == x ]]

rm -rf "$base"
dev_cache_run component key-v1 "$base" stage -- build_output wrong
[[ $(cat "$base/stage/file") == payload:v1 && $(cat "$count") == x ]]

rm -rf "$base"
dev_cache_run component key-v2 "$base" stage -- build_output v2
[[ $(cat "$base/stage/file") == payload:v2 && $(cat "$count") == xx ]]

rm -rf "$base"
archive=$(find "$DSTACK_DEV_CACHE_DIR/component" -name '*.tar.zst' -newer "$count")
printf corrupt >> "$archive"
dev_cache_run component key-v2 "$base" stage -- build_output rebuilt
[[ $(cat "$base/stage/file") == payload:rebuilt && $(cat "$count") == xxx ]]

dev_cache_init 0
rm -rf "$base"
dev_cache_run component ignored "$base" stage -- build_output uncached
[[ $(cat "$base/stage/file") == payload:uncached && $(cat "$count") == xxxx ]]

# The staging tree now outlives the build, so these cases cover what that
# introduces: reusing a tree already staged under the same key, and -- the one
# that matters -- never reusing one staged under a different key. Note the
# tree is deliberately NOT removed between these calls.
dev_cache_init 1
rm -rf "$base"
dev_cache_run component key-s1 "$base" stage -- build_output s1
touch "$base/stage/only-in-s1"
before=$(cat "$count")
dev_cache_run component key-s1 "$base" stage -- build_output must-not-run
[[ $(cat "$count") == "$before" ]] || { echo 'staged tree was rebuilt' >&2; exit 1; }
[[ $(cat "$base/stage/file") == payload:s1 ]]

# Switching keys must clear files the new key does not contain, or a previous
# build's output silently survives into the image.
dev_cache_run component key-s2 "$base" stage -- build_output s2
[[ $(cat "$base/stage/file") == payload:s2 ]]
[[ ! -e $base/stage/only-in-s1 ]] || { echo 'stale staged file survived' >&2; exit 1; }

# The stamp now outlives the staging tree, so a tree removed behind its back
# must not be treated as staged: that would skip the extraction and leave the
# component silently missing from the image.
rm -rf "$base/stage"
dev_cache_run component key-s2 "$base" stage -- build_output must-not-run-either
[[ $(cat "$base/stage/file") == payload:s2 ]] || { echo 'staging tree not restored' >&2; exit 1; }

# Different keys still share one staging tree, so they must share one lock.
# Hold that lock externally and prove a build under a new key cannot start.
mkdir -p "$DSTACK_DEV_CACHE_DIR/serialized"
exec 8>"$DSTACK_DEV_CACHE_DIR/serialized/staging.lock"
flock 8
before=$(cat "$count")
dev_cache_run serialized key-a "$base" stage -- build_output serialized &
pid=$!
sleep 0.1
[[ $(cat "$count") == "$before" ]] || { echo 'different cache keys did not serialize' >&2; exit 1; }
flock -u 8
wait "$pid"
[[ $(cat "$base/stage/file") == payload:serialized ]]

echo 'development cache tests passed'
