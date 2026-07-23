#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Local archive mechanics for dev-image. Component definitions own their keys
# and output boundaries; this file only validates, restores and stores them.

DEV_CACHE_ENABLED=0

dev_cache_init() {
    DEV_CACHE_ENABLED=$1
}

dev_cache_run() {
    local component=$1 key=$2 base=$3
    shift 3
    local outputs=()
    while [[ $1 != -- ]]; do outputs+=("$1"); shift; done
    shift

    if [[ $DEV_CACHE_ENABLED != 1 ]]; then
        "$@"
        return
    fi

    local cache_root=${DSTACK_DEV_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/dstack/mkosi-dev}
    local dir="$cache_root/$component" archive checksum
    archive="$dir/$key.tar.zst"
    checksum="$archive.sha256"
    mkdir -p "$dir" "$base"

    (
        flock 9
        if [[ -f $archive && -f $checksum ]] &&
           (cd "$dir" && sha256sum --check --status "${checksum##*/}"); then
            tar --zstd -xf "$archive" -C "$base"
            echo "development cache hit: $component"
            exit
        fi

        local tmp
        rm -f "$archive" "$checksum"
        echo "development cache miss: $component"
        "$@"
        tmp=$(mktemp "$dir/.${key}.XXXXXX.tar.zst")
        tar --zstd -cf "$tmp" -C "$base" "${outputs[@]}"
        mv "$tmp" "$archive"
        (cd "$dir" && sha256sum "${archive##*/}" > "${checksum##*/}.tmp")
        mv "$checksum.tmp" "$checksum"
    ) 9>"$dir/$key.lock"
}
