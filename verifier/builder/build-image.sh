#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONTEXT_DIR=$(dirname "$SCRIPT_DIR")
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
SHARED_DIR="$SCRIPT_DIR/shared"
SHARED_GIT_PATH=$(realpath --relative-to="$REPO_ROOT" "$SHARED_DIR")
DOCKERFILE="$SCRIPT_DIR/Dockerfile"

NO_CACHE=${NO_CACHE:-}
NAME=${1:-}
if [ -z "$NAME" ]; then
    echo "Usage: $0 <image-name>[:<tag>]" >&2
    exit 1
fi

extract_packages() {
    local image_name=$1
    local pkg_list_file=$2
    if [ -z "$pkg_list_file" ]; then
        return
    fi
    docker run --rm --entrypoint bash "$image_name" \
        -c "dpkg -l | grep '^ii' | awk '{print \$2\"=\"\$3}' | sort" \
        >"$pkg_list_file"
}

docker_build() {
    local image_name=$1
    local target=$2
    local pkg_list_file=$3

    local commit_timestamp
    commit_timestamp=$(git -C "$REPO_ROOT" show -s --format=%ct "$GIT_REV")

    local args=(
        --builder buildkit_20
        --progress=plain
        --output type=docker,name="$image_name",rewrite-timestamp=true
        --build-arg SOURCE_DATE_EPOCH="$commit_timestamp"
        --build-arg DSTACK_REV="$GIT_REV"
        --build-arg DSTACK_SRC_URL="$DSTACK_SRC_URL"
    )

    if [ -n "$NO_CACHE" ]; then
        args+=(--no-cache)
    fi

    if [ -n "$target" ]; then
        args+=(--target "$target")
    fi

    docker buildx build "${args[@]}" \
        --file "$DOCKERFILE" \
        "$CONTEXT_DIR"

    extract_packages "$image_name" "$pkg_list_file"
}

if ! docker buildx inspect buildkit_20 &>/dev/null; then
    docker buildx create --use --driver-opt image=moby/buildkit:v0.20.2 --name buildkit_20
fi

mkdir -p "$SHARED_DIR"
touch "$SHARED_DIR/builder-pinned-packages.txt"
touch "$SHARED_DIR/qemu-pinned-packages.txt"
touch "$SHARED_DIR/pinned-packages.txt"

GIT_REV=${GIT_REV:-HEAD}
GIT_REV=$(git -C "$REPO_ROOT" rev-parse "$GIT_REV")
DSTACK_SRC_URL=${DSTACK_SRC_URL:-https://github.com/Dstack-TEE/dstack.git}

docker_build "$NAME" "" "$SHARED_DIR/pinned-packages.txt"
docker_build "verifier-builder-temp" "verifier-builder" "$SHARED_DIR/builder-pinned-packages.txt"
docker_build "verifier-acpi-builder-temp" "acpi-builder" "$SHARED_DIR/qemu-pinned-packages.txt"

git_status=$(git -C "$REPO_ROOT" status --porcelain -- "$SHARED_GIT_PATH")
if [ -n "$git_status" ]; then
    echo "The working tree has updates in $SHARED_GIT_PATH. Commit or stash before re-running." >&2
    exit 1
fi
