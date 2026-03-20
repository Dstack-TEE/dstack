#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Shared build library for reproducible Docker image builds.
#
# Expected variables (set by the sourcing script):
#   REPO_ROOT    - absolute path to the git repo root
#   CONTEXT_DIR  - Docker build context directory
#   DOCKERFILE   - path to the Dockerfile
#   GIT_REV      - git revision to build
#   DSTACK_SRC_URL - git URL for dstack source

set -euo pipefail

BUILDKIT_VERSION="v0.20.2"
BUILDKIT_BUILDER="buildkit_20"
BUILD_SHARED_DIR="$REPO_ROOT/build/shared"

ensure_buildkit() {
    if ! docker buildx inspect "$BUILDKIT_BUILDER" &>/dev/null; then
        docker buildx create --use --driver-opt "image=moby/buildkit:$BUILDKIT_VERSION" --name "$BUILDKIT_BUILDER"
    fi
}

extract_packages() {
    local image_name=$1
    local pkg_list_file=${2:-}
    if [ -z "$pkg_list_file" ]; then
        return
    fi
    docker run --rm --entrypoint bash "$image_name" \
        -c "dpkg -l | grep '^ii' | awk '{print \$2\"=\"\$3}' | sort" \
        >"$pkg_list_file"
}

docker_build() {
    local image_name=$1
    local target=${2:-}
    local pkg_list_file=${3:-}

    local commit_timestamp
    commit_timestamp=$(git -C "$REPO_ROOT" show -s --format=%ct "$GIT_REV")

    local args=(
        --builder "$BUILDKIT_BUILDER"
        --progress=plain
        --output "type=docker,name=$image_name,rewrite-timestamp=true"
        --build-context "build-shared=$BUILD_SHARED_DIR"
        --build-arg "SOURCE_DATE_EPOCH=$commit_timestamp"
        --build-arg "DSTACK_REV=$GIT_REV"
        --build-arg "DSTACK_SRC_URL=$DSTACK_SRC_URL"
    )

    if [ -n "${NO_CACHE:-}" ]; then
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

# Verify that pinned-packages files haven't changed (idempotency check).
check_clean_tree() {
    local check_path=$1
    local rel_path
    rel_path=$(realpath --relative-to="$REPO_ROOT" "$check_path")
    local git_status
    git_status=$(git -C "$REPO_ROOT" status --porcelain -- "$rel_path")
    if [ -n "$git_status" ]; then
        echo "The working tree has updates in $rel_path. Commit or stash before re-running." >&2
        exit 1
    fi
}
