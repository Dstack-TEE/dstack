#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Build the guest OS with the mkosi backend inside a pinned container, so the
# only host requirements are Docker and the privileges mkosi needs for loop
# devices, device-mapper and mounts.
#
# This does not make the build reproducible -- os/mkosi already pins every
# compiler and package it consumes, and compiles them inside its own overlay.
# What the container pins is the last unpinned layer: mkosi itself and the
# handful of host tools it drives.
set -euo pipefail

usage() {
    cat <<EOF
Usage: ${0##*/} [-c] [-o DIR]

  -c        run build.sh repro-check (build twice, compare byte for byte)
            instead of a single image build
  -o DIR    build directory (default: <repo>/os/mkosi/repro-build/build)

Environment:
  FLAVORS   space-separated image flavors, e.g. FLAVORS="prod dev" (default: prod)
  JOBS      parallelism inside the container (default: the container's nproc)
  DOCKER    docker command to use (default: docker)
EOF
}

ACTION=image
THIS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=${REPO_ROOT:-$(cd "$THIS_DIR/../../.." && pwd)}
BUILD_DIR=

while getopts ":co:h" opt; do
    case "$opt" in
        c) ACTION=repro-check ;;
        o) BUILD_DIR=$OPTARG ;;
        h) usage; exit 0 ;;
        *) echo "Invalid option: -$OPTARG" >&2; usage >&2; exit 1 ;;
    esac
done
BUILD_DIR=${BUILD_DIR:-$THIS_DIR/build}

DOCKER=${DOCKER:-docker}
IMAGE=dstack-mkosi-build

# The pin comes from the tree being built, not from this script, so a checkout
# always gets the mkosi its own sources were tested against.
# shellcheck source=../versions.env
# shellcheck disable=SC1091
source "$REPO_ROOT/os/mkosi/versions.env"
if [ -z "${MKOSI_REVISION:-}" ]; then
    echo "error: $REPO_ROOT/os/mkosi/versions.env defines no MKOSI_REVISION" >&2
    echo "that tree predates the container builder; build it natively, or set" >&2
    echo "MKOSI_REVISION to the mkosi its CI used" >&2
    exit 1
fi

# build.sh derives SOURCE_DATE_EPOCH and the measured git revision from the
# repository, so git has to work inside the container. In a git worktree .git is
# a file pointing at the main checkout, which is outside the source mount; bind
# that directory at its own path so the pointer still resolves.
git_common=$(cd "$REPO_ROOT" && git rev-parse --git-common-dir)
git_common=$(cd "$REPO_ROOT" && cd "$git_common" && pwd)
git_mount=()
case "$git_common/" in
    "$REPO_ROOT"/*) ;;
    *) git_mount=(-v "$git_common:$git_common") ;;
esac

mkdir -p "$BUILD_DIR"

# mkosi assembles the build root as an overlayfs, and overlayfs cannot stack on
# overlayfs. Docker's default storage driver puts the whole container root --
# including /var/tmp, where mkosi places its workspace -- on exactly that, so
# the build dies in mkosi's sandbox with a bare EINVAL. Give the workspace a
# real filesystem from the host instead.
WORKSPACE=$BUILD_DIR/.workspace
mkdir -p "$WORKSPACE"
workspace_fs=$(stat -f -c %T "$WORKSPACE")
if [ "$workspace_fs" = overlayfs ]; then
    echo "error: $WORKSPACE is on overlayfs, which mkosi cannot use as a workspace" >&2
    echo "choose a build directory on a regular filesystem with -o DIR" >&2
    exit 1
fi

# An empty build context: the Dockerfile needs only its own entrypoint, and
# sending the monorepo would cost minutes and invalidate the layer cache on
# every source change.
ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT
cp "$THIS_DIR/entrypoint.sh" "$ctx/entrypoint.sh"
"$DOCKER" build --platform linux/amd64 -t "$IMAGE" \
    --build-arg "MKOSI_REVISION=$MKOSI_REVISION" \
    --build-arg "MKOSI_VERSION=$MKOSI_VERSION" \
    -f "$THIS_DIR/Dockerfile.repro" "$ctx"

# --privileged plus /dev: mkosi needs loop devices, device-mapper and mounts to
# assemble the dm-verity rootfs and the UKI disk image.
#
# The container runs as root while the source tree belongs to the caller, which
# trips git's dubious-ownership check. GIT_CONFIG_* passes safe.directory in the
# environment rather than writing to the caller's git config.
"$DOCKER" run --rm --platform linux/amd64 \
    --privileged \
    -v /dev:/dev \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -v "$BUILD_DIR:$BUILD_DIR" \
    -v "$WORKSPACE:/var/tmp" \
    "${git_mount[@]}" \
    -e "DSTACK_SRC_DIR=$REPO_ROOT" \
    -e "DSTACK_BUILD_DIR=$BUILD_DIR" \
    -e "DSTACK_ACTION=$ACTION" \
    -e "DSTACK_HOST_UID=$(id -u)" \
    -e "DSTACK_HOST_GID=$(id -g)" \
    -e "FLAVORS=${FLAVORS:-prod}" \
    ${JOBS:+-e "JOBS=$JOBS"} \
    -e GIT_CONFIG_COUNT=1 \
    -e GIT_CONFIG_KEY_0=safe.directory \
    -e GIT_CONFIG_VALUE_0='*' \
    -w "$REPO_ROOT" \
    "$IMAGE"

if [ "$ACTION" = repro-check ]; then
    echo "reproducibility check passed; artifacts in $BUILD_DIR/a"
    exit 0
fi

# Report the release identity. os_image_hash is what authorizes the image on
# chain, so print it here rather than making every caller dig it out.
for flavor in ${FLAVORS:-prod}; do
    dist="$BUILD_DIR/out/$flavor"
    name=dstack
    [ "$flavor" = dev ] && name=dstack-dev
    img="$dist/$name-$DSTACK_VERSION"
    [ -d "$img" ] || continue
    echo
    echo "=== $flavor ==="
    echo "os_image_hash  $(cat "$img/digest.txt")"
    (cd "$dist" && sha256sum "$name-$DSTACK_VERSION.tar.gz" "$name-$DSTACK_VERSION-uki.tar.gz")
done
