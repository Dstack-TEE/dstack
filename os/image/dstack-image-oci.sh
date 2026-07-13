#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# dstack guest image OCI packaging tool
# Pack and push dstack guest OS images to an OCI-compatible container registry.
set -euo pipefail

usage() {
    local status=${1:-1}
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  push  <image-dir> <image-ref> [--tag <tag>]   Pack and push image to registry
  list  <image-ref> [--filter <pattern>]         List available tags in registry

Arguments:
  <image-dir>   Path to a dstack guest image directory (contains metadata.json)
  <image-ref>   Full image reference (e.g., ghcr.io/org/guest-image)

Examples:
  $0 push ./dstack-0.6.0 ghcr.io/dstack-tee/guest-image
  $0 push ./dstack-0.6.0 ghcr.io/dstack-tee/guest-image --tag 0.6.0
  $0 list ghcr.io/dstack-tee/guest-image
  $0 list ghcr.io/dstack-tee/guest-image --filter nvidia
EOF
    exit "$status"
}

COMMAND="${1:-}"
[ -z "$COMMAND" ] && usage
shift

# --- PUSH ---
cmd_push() (
    local image_dir=""
    local image_ref=""
    local extra_tag=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --tag)
                [ $# -ge 2 ] || { echo "Error: --tag requires a value"; exit 1; }
                extra_tag="$2"
                shift 2
                ;;
            -h|--help) usage 0 ;;
            -*)  echo "Unknown option: $1"; exit 1 ;;
            *)
                if [ -z "$image_dir" ]; then
                    image_dir="$1"
                elif [ -z "$image_ref" ]; then
                    image_ref="$1"
                else
                    echo "Unexpected argument: $1"; exit 1
                fi
                shift
                ;;
        esac
    done

    [ -z "$image_dir" ] && { echo "Error: image directory required"; usage; }
    [ -z "$image_ref" ] && { echo "Error: image reference required"; usage; }
    [ -d "$image_dir" ] || { echo "Error: $image_dir is not a directory"; exit 1; }

    local metadata="$image_dir/metadata.json"
    [ -f "$metadata" ] || { echo "Error: metadata.json not found in $image_dir"; exit 1; }

    # Read image info
    local version
    version=$(python3 - "$metadata" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as file:
    print(json.load(file)["version"])
PY
    )
    if [[ ! "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]]; then
        echo "Error: metadata.json contains an invalid version: $version"
        exit 1
    fi
    local digest_file="$image_dir/digest.txt"
    local os_image_hash=""
    if [ -f "$digest_file" ]; then
        os_image_hash=$(tr -d '\n\r' < "$digest_file")
        if [[ ! "$os_image_hash" =~ ^[0-9A-Fa-f]{64}$ ]]; then
            echo "Error: digest.txt must contain one SHA-256 hex digest"
            exit 1
        fi
        os_image_hash=${os_image_hash,,}
    fi

    # Detect image variant from directory name
    local dirname
    dirname=$(basename "$image_dir")
    local variant=""
    if [[ "$dirname" == *-nvidia-dev-* ]]; then
        variant="nvidia-dev"
    elif [[ "$dirname" == *-nvidia-* ]]; then
        variant="nvidia"
    elif [[ "$dirname" == *-dev-* ]]; then
        variant="dev"
    elif [[ "$dirname" == *-cloud-* ]]; then
        variant="cloud"
    fi

    # Build tag list
    local tags=()
    if [ -n "$extra_tag" ]; then
        tags+=("$extra_tag")
    else
        # Auto-generate tags from variant + version
        if [ -n "$variant" ]; then
            tags+=("${variant}-${version}")
        else
            tags+=("${version}")
        fi
        if [ -n "$os_image_hash" ]; then
            tags+=("sha256-${os_image_hash}")
        fi
    fi

    echo "=== Packing dstack guest image ==="
    echo "  Source:   $image_dir"
    echo "  Version:  $version"
    echo "  Variant:  ${variant:-standard}"
    echo "  Hash:     ${os_image_hash:-<none>}"
    echo "  Registry: $image_ref"
    echo "  Tags:     ${tags[*]}"
    echo ""

    # Create build context in a temp directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    # Collect all files
    local files=()
    for f in "$image_dir"/*; do
        if [ -f "$f" ]; then
            local name
            name=$(basename "$f")
            if [[ ! "$name" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]]; then
                echo "Error: image filename is not OCI-packaging safe: $name"
                exit 1
            fi
            files+=("$name")
        fi
    done

    # Generate Dockerfile
    {
        echo "FROM scratch"
        for f in "${files[@]}"; do
            echo "COPY $f /"
        done
        echo "LABEL org.opencontainers.image.title=\"dstack-guest-image\""
        echo "LABEL org.opencontainers.image.version=\"$version\""
        echo "LABEL wang.dstack.os-image-hash=\"${os_image_hash}\""
        echo "LABEL wang.dstack.variant=\"${variant:-standard}\""
    } > "$tmp_dir/Dockerfile"

    # Copy files to build context
    for f in "${files[@]}"; do
        cp "$image_dir/$f" "$tmp_dir/"
    done

    # Build
    local primary_ref="${image_ref}:${tags[0]}"
    echo "Building: $primary_ref"
    docker build -t "$primary_ref" "$tmp_dir"

    # Tag additional tags
    for ((i=1; i<${#tags[@]}; i++)); do
        local ref="${image_ref}:${tags[$i]}"
        echo "Tagging: $ref"
        docker tag "$primary_ref" "$ref"
    done

    # Push all tags
    for tag in "${tags[@]}"; do
        local ref="${image_ref}:${tag}"
        echo "Pushing: $ref"
        docker push "$ref"
    done

    # Build and push measurement-only image (no rootfs, for verifier)
    if [ -n "$os_image_hash" ]; then
        local mr_tag="mr-sha256-${os_image_hash}"
        local mr_dir
        mr_dir="$tmp_dir/measurement"
        mkdir -p "$mr_dir"

        # Read rootfs filename from metadata to exclude it
        local rootfs_name
        rootfs_name=$(python3 - "$metadata" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as file:
    print(json.load(file).get("rootfs", ""))
PY
        )

        # Collect files excluding rootfs
        local mr_files=()
        for f in "${files[@]}"; do
            if [ "$f" != "$rootfs_name" ]; then
                mr_files+=("$f")
                cp "$image_dir/$f" "$mr_dir/"
            fi
        done

        {
            echo "FROM scratch"
            for f in "${mr_files[@]}"; do
                echo "COPY $f /"
            done
            echo "LABEL org.opencontainers.image.title=\"dstack-guest-image-mr\""
            echo "LABEL org.opencontainers.image.version=\"$version\""
            echo "LABEL wang.dstack.os-image-hash=\"${os_image_hash}\""
            echo "LABEL wang.dstack.variant=\"${variant:-standard}\""
            echo "LABEL wang.dstack.measurement-only=\"true\""
        } > "$mr_dir/Dockerfile"

        local mr_ref="${image_ref}:${mr_tag}"
        echo ""
        echo "Building measurement image (no rootfs): $mr_ref"
        echo "  Files: ${mr_files[*]}"
        docker build -t "$mr_ref" "$mr_dir"

        echo "Pushing: $mr_ref"
        docker push "$mr_ref"

        tags+=("$mr_tag")
    fi

    rm -rf "$tmp_dir"
    trap - EXIT

    echo ""
    echo "=== Done ==="
    for tag in "${tags[@]}"; do
        echo "  ${image_ref}:${tag}"
    done
)

# --- LIST ---
cmd_list() {
    local image_ref=""
    local filter=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --filter)
                [ $# -ge 2 ] || { echo "Error: --filter requires a value"; exit 1; }
                filter="$2"
                shift 2
                ;;
            -h|--help) usage 0 ;;
            -*)  echo "Unknown option: $1"; exit 1 ;;
            *)
                if [ -z "$image_ref" ]; then
                    image_ref="$1"
                else
                    echo "Unexpected argument: $1"; exit 1
                fi
                shift
                ;;
        esac
    done

    [ -z "$image_ref" ] && { echo "Error: image reference required"; usage; }

    echo "=== Tags for ${image_ref} ==="

    # Parse registry and repo from image_ref
    local registry repo
    registry="${image_ref%%/*}"
    repo="${image_ref#*/}"

    local tags_json
    tags_json=$(skopeo list-tags "docker://${image_ref}" 2>/dev/null || \
                curl -sf "https://${registry}/v2/${repo}/tags/list" 2>/dev/null || \
                echo '{"tags":[]}')

    python3 -c '
import json
import re
import sys

data = json.load(sys.stdin)
tags = sorted(data.get("Tags", data.get("tags", [])))
filt = sys.argv[1]
for tag in tags:
    if not filt or re.search(filt, tag):
        print(f"  {tag}")
' "$filter" <<< "$tags_json"
}

# Dispatch
case "$COMMAND" in
    push) cmd_push "$@" ;;
    list) cmd_list "$@" ;;
    -h|--help) usage 0 ;;
    *)    echo "Unknown command: $COMMAND"; usage ;;
esac
