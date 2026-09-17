#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
# Usage: build.sh KERNEL_DEVEL_ARCHIVE IMAGE_REF
set -euo pipefail

archive=$(realpath "${1:?kernel-devel archive required}")
image=${2:?image ref required}
SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../../mkosi/versions.env
source "$SELF/../../mkosi/versions.env"

# Keep the build context to the one archive.
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
cp "$archive" "$context/kernel-devel.tar.gz"

${DOCKER:-docker} build \
    --file "$SELF/Dockerfile" \
    --build-arg "BASE_IMAGE=debian:$DEBIAN_RELEASE-slim" \
    --build-arg "DEBIAN_SNAPSHOT=$DEBIAN_SNAPSHOT" \
    --build-arg "KERNEL_RELEASE=$KERNEL_VERSION-dstack" \
    --build-arg "IMAGE_VERSION=${IMAGE_VERSION:-$DSTACK_VERSION}" \
    --build-arg "GIT_REVISION=${GIT_REVISION:-unknown}" \
    --tag "$image" \
    "$context"
