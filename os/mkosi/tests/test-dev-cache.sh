#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
D=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=/dev/null
source "$D/scripts/dev-cache.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export DSTACK_DEV_CACHE_ACTIVE=1 DSTACK_DEV_CACHE_DIR="$tmp/cache"
base="$tmp/work"
count="$tmp/count"

build_output() {
    mkdir -p "$base/stage"
    printf 'payload:%s\n' "$1" > "$base/stage/file"
    printf x >> "$count"
}

key=$(dev_cache_key component input-v1)
dev_cache_run component "$key" "$base" 1 stage -- build_output v1
[[ $(cat "$base/stage/file") == payload:v1 && $(cat "$count") == x ]]

rm -rf "$base"
dev_cache_run component "$key" "$base" 1 stage -- build_output wrong
[[ $(cat "$base/stage/file") == payload:v1 && $(cat "$count") == x ]]

rm -rf "$base"
key2=$(dev_cache_key component input-v2)
dev_cache_run component "$key2" "$base" 1 stage -- build_output v2
[[ $(cat "$base/stage/file") == payload:v2 && $(cat "$count") == xx ]]

rm -rf "$base"
archive=$(find "$DSTACK_DEV_CACHE_DIR/component" -name "$key2.tar.zst")
printf corrupt >> "$archive"
dev_cache_run component "$key2" "$base" 1 stage -- build_output rebuilt
[[ $(cat "$base/stage/file") == payload:rebuilt && $(cat "$count") == xxx ]]

unset DSTACK_DEV_CACHE_ACTIVE
rm -rf "$base"
dev_cache_run component ignored "$base" 1 stage -- build_output uncached
[[ $(cat "$base/stage/file") == payload:uncached && $(cat "$count") == xxxx ]]

echo 'development cache tests passed'
