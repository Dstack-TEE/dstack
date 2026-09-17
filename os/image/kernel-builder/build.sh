#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ $# != 3 ]]; then
    echo "Usage: $0 ARCHIVE IMAGE_REF KERNEL_RELEASE" >&2
    exit 2
fi
archive=$(realpath "$1")
image=$2
release=$3
SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../../mkosi/versions.env
source "$SELF/../../mkosi/versions.env"
DOCKER=${DOCKER:-docker}

# Do not send the neighboring OS image tarballs to the Docker daemon.
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
cp "$archive" "$context/kernel-devel.tar.gz"

$DOCKER build \
    --file "$SELF/Dockerfile" \
    --build-arg "BASE_IMAGE=debian:$DEBIAN_RELEASE-slim" \
    --build-arg "DEBIAN_SNAPSHOT=$DEBIAN_SNAPSHOT" \
    --build-arg "KERNEL_RELEASE=$release" \
    --build-arg KERNEL_DEVEL_TARBALL=kernel-devel.tar.gz \
    --build-arg "IMAGE_VERSION=${IMAGE_VERSION:-$DSTACK_VERSION}" \
    --build-arg "OS_IMAGE_HASH=${OS_IMAGE_HASH:-unknown}" \
    --build-arg "GIT_REVISION=${GIT_REVISION:-unknown}" \
    --tag "$image" \
    "$context"
