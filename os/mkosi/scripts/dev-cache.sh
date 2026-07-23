#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Development-only, local component output cache. Production and reproducible
# builds never set DSTACK_DEV_CACHE_ACTIVE and therefore bypass this file.

dev_cache_key() {
    printf '%s\0' "mkosi-dev-cache-v1" "$@" | sha256sum | cut -d' ' -f1
}

dev_cache_run() {
    local component=$1 key=$2 base=$3 output_count=$4
    shift 4
    local outputs=("${@:1:output_count}")
    shift "$output_count"
    [[ $1 == -- ]]; shift

    if [[ ${DSTACK_DEV_CACHE_ACTIVE:-0} != 1 ]]; then
        "$@"
        return
    fi

    local cache_dir=${DSTACK_DEV_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/dstack/mkosi-dev}
    local dir="$cache_dir/$component"
    local archive="$dir/$key.tar.zst"
    local checksum="$archive.sha256" lock="$dir/$key.lock" tmp
    mkdir -p "$dir" "$base"
    exec {cache_lock}>"$lock"
    flock "$cache_lock"

    if [[ -f $archive && -f $checksum ]] &&
       (cd "$dir" && sha256sum --check --status "${checksum##*/}"); then
        tar --zstd -xf "$archive" -C "$base"
        echo "development cache hit: $component"
        flock -u "$cache_lock"
        exec {cache_lock}>&-
        return
    fi

    # A partial or corrupt entry is only a cache miss; it is never trusted.
    rm -f "$archive" "$checksum"
    echo "development cache miss: $component"
    "$@"

    tmp=$(mktemp "$dir/.${key}.XXXXXX.tar.zst")
    tar --zstd -cf "$tmp" -C "$base" "${outputs[@]}"
    mv "$tmp" "$archive"
    (cd "$dir" && sha256sum "${archive##*/}" > "${checksum##*/}.tmp")
    mv "$checksum.tmp" "$checksum"
    flock -u "$cache_lock"
    exec {cache_lock}>&-
}
