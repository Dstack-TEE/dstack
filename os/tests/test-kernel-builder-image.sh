#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Build the smoke-test module inside a kernel-builder image and assert that the
# result would load in the guest it claims to serve. A builder image whose
# headers, Module.symvers or compiler do not match the shipped kernel still
# produces a .ko; what it does not produce is a matching vermagic, so that is
# what this checks.
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
