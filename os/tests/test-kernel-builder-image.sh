#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Check that the builder compiles a module for the expected kernel release.
# This is not a load test: vermagic's release field does not validate symbol
# versions, compiler compatibility, or the rest of the kernel configuration.
set -euo pipefail

IMAGE=${1:?container image required}
EXPECTED_RELEASE=${2:-}
DOCKER=${DOCKER:-docker}
SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$SELF/kmod-hello/hello.c" "$SELF/kmod-hello/Makefile" "$work/"

# --user keeps the build outputs owned by the caller, so the fixture copy stays
# removable without root. The inner script is single-quoted on purpose: KDIR
# and KERNEL_RELEASE are the image's own environment, not this shell's.
# shellcheck disable=SC2016
$DOCKER run --rm --user "$(id -u):$(id -g)" \
    -v "$work:/work" -w /work "$IMAGE" \
    bash -eu -o pipefail -c '
        make KDIR="$KDIR"
        vermagic=$(modinfo -F vermagic dstack-hello.ko)
        echo "vermagic: $vermagic"
        if [ "${vermagic%% *}" != "$KERNEL_RELEASE" ]; then
            echo "module vermagic ${vermagic%% *} does not match the image kernel $KERNEL_RELEASE" >&2
            exit 1
        fi
        printf "%s\n" "$KERNEL_RELEASE" > kernel-release.txt
    '
release=$(cat "$work/kernel-release.txt")
if [ -n "$EXPECTED_RELEASE" ] && [ "$release" != "$EXPECTED_RELEASE" ]; then
    echo "builder image serves $release but the release expects $EXPECTED_RELEASE" >&2
    exit 1
fi
echo "kernel module build accepted: $IMAGE serves $release"
