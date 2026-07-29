#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Local archive mechanics for a cached build. Component definitions own their
# keys and output boundaries; this file only validates, restores and stores them.

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

    # Records which key the staging tree currently holds. Only meaningful when
    # the tree outlives the build, which it does once mkosi.build points the
    # work directory at BUILDDIR.
    local stamp="$base/.dstack-staged.$component"

    # Anything staged under a different key -- or under no key we can account
    # for -- is removed before it can be reused. Skipping this is how files
    # from a previous build survive into a later image, which is far worse than
    # the extraction it would have saved. Only the component's declared outputs
    # are touched, so components sharing a base do not disturb each other.
    discard_staged() {
        (cd "$base" && rm -rf -- "${outputs[@]}")
        rm -f "$stamp"
    }

    (
        flock 9
        if [[ -f $archive && -f $checksum ]] &&
           (cd "$dir" && sha256sum --check --status "${checksum##*/}"); then
            if [[ -f $stamp && $(cat "$stamp") == "$key" ]]; then
                echo "development cache hit (already staged): $component"
                exit
            fi
            discard_staged
            tar --zstd -xf "$archive" -C "$base"
            printf '%s' "$key" > "$stamp"
            echo "development cache hit: $component"
            exit
        fi

        local tmp
        rm -f "$archive" "$checksum"
        echo "development cache miss: $component"
        discard_staged
        "$@"
        tmp=$(mktemp "$dir/.${key}.XXXXXX.tar.zst")
        tar --zstd -cf "$tmp" -C "$base" "${outputs[@]}"
        mv "$tmp" "$archive"
        (cd "$dir" && sha256sum "${archive##*/}" > "${checksum##*/}.tmp")
        mv "$checksum.tmp" "$checksum"
        # Written last: a stamp is a claim that the tree matches the archive,
        # so it must not exist if any step above failed.
        printf '%s' "$key" > "$stamp"
    ) 9>"$dir/$key.lock"
}
