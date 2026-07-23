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

dev_cache_init 1 "$D/../.." prod 1
dev_cache_run component "$base" stage -- build_output v1
[[ $(cat "$base/stage/file") == payload:v1 && $(cat "$count") == x ]]

rm -rf "$base"
dev_cache_run component "$base" stage -- build_output wrong
[[ $(cat "$base/stage/file") == payload:v1 && $(cat "$count") == x ]]

rm -rf "$base"
dev_cache_init 1 "$D/../.." prod 2
dev_cache_run component "$base" stage -- build_output v2
[[ $(cat "$base/stage/file") == payload:v2 && $(cat "$count") == xx ]]

rm -rf "$base"
archive=$(find "$DSTACK_DEV_CACHE_DIR/component" -name '*.tar.zst' -newer "$count")
printf corrupt >> "$archive"
dev_cache_run component "$base" stage -- build_output rebuilt
[[ $(cat "$base/stage/file") == payload:rebuilt && $(cat "$count") == xxx ]]

dev_cache_init 0 "$D/../.." prod 2
rm -rf "$base"
dev_cache_run component "$base" stage -- build_output uncached
[[ $(cat "$base/stage/file") == payload:uncached && $(cat "$count") == xxxx ]]

echo 'development cache tests passed'
