#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Local component-output cache for dev-image. This file owns all cache policy;
# callers only initialize it and run named components through it.

DEV_CACHE_ENABLED=0
DEV_CACHE_CONTEXT=

dev_cache_init() {
    local enabled=$1 root=$2 flavor=$3 epoch=$4
    DEV_CACHE_ENABLED=$enabled
    [[ $enabled == 1 ]] || return 0

    local sources tools
    sources=$(
        git -C "$root" ls-files -z --cached --others --exclude-standard -- \
          dstack os/common os/mkosi os/yocto/layers/meta-dstack \
          os/yocto/layers/meta-nvidia \
        | sort -z | while IFS= read -r -d '' input; do
            if [[ -f $root/$input ]]; then
                sha256sum "$root/$input"
            elif [[ -d $root/$input ]]; then
                printf 'gitlink %s %s\n' "$input" \
                  "$(git -C "$root/$input" rev-parse HEAD)"
            else
                printf 'missing %s\n' "$input"
            fi
          done | sha256sum | cut -d' ' -f1
    )
    tools=$({
        gcc --version | head -1; ld --version | head -1; go version
        rustc --version; cargo --version; cmake --version | head -1
        make --version | head -1; pahole --version; tar --version | head -1
        python3 --version; ninja --version; autoconf --version | head -1
        automake --version | head -1; zstd --version | head -1
        dpkg-query -W -f='${binary:Package}=${Version}\n' | sort
    } | sha256sum | cut -d' ' -f1)
    DEV_CACHE_CONTEXT=$(printf '%s\0' mkosi-dev-cache-v2 "$sources" "$tools" \
      "$flavor" "$epoch" "$(uname -m)" | sha256sum | cut -d' ' -f1)
}

dev_cache_run() {
    local component=$1 base=$2
    shift 2
    local outputs=()
    while [[ $1 != -- ]]; do outputs+=("$1"); shift; done
    shift

    if [[ $DEV_CACHE_ENABLED != 1 ]]; then
        "$@"
        return
    fi

    local cache_root=${DSTACK_DEV_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/dstack/mkosi-dev}
    local dir="$cache_root/$component" key archive checksum
    key=$(printf '%s\0' "$component" "$DEV_CACHE_CONTEXT" | sha256sum | cut -d' ' -f1)
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
