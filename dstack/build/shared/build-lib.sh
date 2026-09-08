#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Shared build library for reproducible Docker image builds.
#
# Release CI runs the very same component build-image.sh that a user runs by
# hand, so everything that ends up in the published image -- layers, config
# labels and manifest annotations -- is reproducible outside CI.
#
# Expected variables (set by the sourcing script):
#   REPO_ROOT    - absolute path to the monorepo root
#   CONTEXT_DIR  - Docker build context directory
#   DOCKERFILE   - path to the Dockerfile
#   GIT_REV      - git revision to build
#   DSTACK_SRC_URL - git URL for dstack source
#
# Optional variables:
#   IMAGE_VERSION    - version recorded in the image metadata (default: dev).
#                      Release CI passes the tag version; pass the same value to
#                      reproduce a published image.
#   IMAGE_SOURCE_URL - repository URL recorded in the image metadata
#   PUSH             - non-empty to push the image instead of loading it
#   OCI_TAR          - path to also write an OCI archive to. The manifest digest
#                      of that archive is what a registry reports, so this is the
#                      way to check a local rebuild against a published digest.
#   METADATA_FILE    - path buildx writes its build metadata (incl. digest) to
#   NO_CACHE         - non-empty to build without the layer cache

set -euo pipefail

BUILDKIT_VERSION="v0.20.2"
BUILDKIT_BUILDER="buildkit_20"
BUILD_SHARED_DIR="$REPO_ROOT/dstack/build/shared"

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

# Print the OCI metadata for a component image as "key=value" lines.
#
# This is the single source of truth for that metadata: docker_build feeds the
# result to the config labels, the manifest annotations and the in-image
# /etc/<title>/build-info file, so the three can never disagree.
#
#   $1 - image title, e.g. dstack-kms
#   $2 - one-line description
#   $3 - component directory within the repo, e.g. dstack/kms
#   $4 - documentation file within the repo, e.g. dstack/kms/README.md
image_metadata() {
    local title=$1
    local description=$2
    local component_dir=$3
    local documentation=$4

    local source_url=${IMAGE_SOURCE_URL:-${DSTACK_SRC_URL%.git}}

    # Read the pinned base image out of the Dockerfile's last FROM so the
    # base.name/base.digest claims cannot drift from the layer they describe.
    local base_ref
    base_ref=$(awk '$1 == "FROM" { ref = $2 } END { print ref }' "$DOCKERFILE")
    if [[ "$base_ref" != *@sha256:* ]]; then
        echo "the final FROM in $DOCKERFILE must pin a digest; got '$base_ref'" >&2
        return 1
    fi
    local base_name=${base_ref%@*}
    local base_digest=${base_ref#*@}
    # Normalize a bare official-image reference to its canonical form.
    if [[ "$base_name" != */* ]]; then
        base_name="docker.io/library/$base_name"
    fi

    printf '%s\n' \
        "org.opencontainers.image.title=$title" \
        "org.opencontainers.image.description=$description" \
        "org.opencontainers.image.source=$source_url" \
        "org.opencontainers.image.revision=$GIT_REV" \
        "org.opencontainers.image.version=${IMAGE_VERSION:-dev}" \
        "org.opencontainers.image.url=$source_url/tree/$GIT_REV/$component_dir" \
        "org.opencontainers.image.documentation=$source_url/blob/$GIT_REV/$documentation" \
        "org.opencontainers.image.licenses=Apache-2.0" \
        "org.opencontainers.image.base.name=$base_name" \
        "org.opencontainers.image.base.digest=$base_digest"
}

# docker_build <tags> [target] [pkg_list_file] [metadata]
#
#   tags          - newline-separated list of image tags
#   target        - build stage to stop at, empty for the final image
#   pkg_list_file - where to record the installed Debian packages
#   metadata      - "key=value" lines from image_metadata, empty to record none
docker_build() {
    local tags=$1
    local target=${2:-}
    local pkg_list_file=${3:-}
    local metadata=${4:-}

    local commit_timestamp
    commit_timestamp=$(git -C "$REPO_ROOT" show -s --format=%ct "$GIT_REV")

    local args=(
        --builder "$BUILDKIT_BUILDER"
        --progress=plain
        # The Rust stages cross-compile to x86_64-unknown-linux-musl, so pin the
        # platform rather than inheriting the host's -- an arm64 workstation must
        # still reproduce the released amd64 image.
        --platform linux/amd64
        # BuildKit attaches a provenance attestation by default when pushing,
        # which carries build timestamps and turns the pushed tag into an index.
        # Both would make the digest unreproducible.
        --provenance=false
        --build-context "build-shared=$BUILD_SHARED_DIR"
        --build-arg "SOURCE_DATE_EPOCH=$commit_timestamp"
        --build-arg "DSTACK_REV=$GIT_REV"
        --build-arg "DSTACK_SRC_URL=$DSTACK_SRC_URL"
    )

    local tag
    while IFS= read -r tag; do
        [ -n "$tag" ] || continue
        args+=(--tag "$tag")
    done <<<"$tags"

    if [ -n "$metadata" ]; then
        local pair
        while IFS= read -r pair; do
            [ -n "$pair" ] || continue
            args+=(--label "$pair" --annotation "manifest:$pair")
        done <<<"$metadata"
        args+=(--build-arg "IMAGE_METADATA=$metadata")
    fi

    # Only the final image is publishable. Intermediate stages are built purely
    # to extract their package lists and must never reach a registry.
    #
    # oci-mediatypes keeps the pushed manifest byte-identical to the OCI archive
    # a local rebuild produces, which is what makes the digests comparable.
    if [ -n "${PUSH:-}" ] && [ -z "$target" ]; then
        args+=(--output "type=image,push=true,oci-mediatypes=true,rewrite-timestamp=true")
    fi
    if [ -n "${OCI_TAR:-}" ] && [ -z "$target" ]; then
        args+=(--output "type=oci,oci-mediatypes=true,rewrite-timestamp=true,dest=$OCI_TAR")
    fi
    # Always load locally as well: extract_packages inspects the built image.
    args+=(--output "type=docker,rewrite-timestamp=true")
    # Guard this like the outputs above: the intermediate stage builds run after
    # the final one and would otherwise overwrite its reported digest.
    if [ -n "${METADATA_FILE:-}" ] && [ -z "$target" ]; then
        args+=(--metadata-file "$METADATA_FILE")
    fi

    if [ -n "${NO_CACHE:-}" ]; then
        args+=(--no-cache)
    fi

    if [ -n "$target" ]; then
        args+=(--target "$target")
    fi

    docker buildx build "${args[@]}" \
        --file "$DOCKERFILE" \
        "$CONTEXT_DIR"

    extract_packages "$(head -n1 <<<"$tags")" "$pkg_list_file"
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
