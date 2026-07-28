#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Container-side wrapper. Runs the mkosi backend as root, then hands the
# artifacts back to the invoking user so the build directory is not left
# root-owned on the host.
set -euo pipefail

SRC=${DSTACK_SRC_DIR:?source mount required}
OUT=${DSTACK_BUILD_DIR:?build mount required}
ACTION=${DSTACK_ACTION:-image}
HOST_UID=${DSTACK_HOST_UID:-0}
HOST_GID=${DSTACK_HOST_GID:-0}

# Hand the artifacts back even when the build fails, so a partial tree is still
# inspectable without sudo.
# shellcheck disable=SC2317  # reached through the EXIT trap below
cleanup() {
    if [ "$HOST_UID" != 0 ]; then
        chown -R "$HOST_UID:$HOST_GID" "$OUT" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# mkosi grows dependencies between releases. Rather than let a missing package
# surface as an obscure failure halfway through a 40-minute build, compare the
# image's package set against what this mkosi actually asks for.
missing=()
while read -r dep; do
    [ -n "$dep" ] || continue
    # mkosi emits apt patterns such as ?exact-name(grub-pc-bin).
    case "$dep" in
        '?exact-name('*')') dep=${dep#'?exact-name('}; dep=${dep%')'} ;;
    esac
    dpkg-query --show "$dep" >/dev/null 2>&1 || missing+=("$dep")
done < <(mkosi --directory "$SRC/os/mkosi" dependencies 2>/dev/null || true)
if [ ${#missing[@]} -gt 0 ]; then
    echo "error: this mkosi needs packages the builder image does not have:" >&2
    printf '  %s\n' "${missing[@]}" >&2
    echo "add them to os/mkosi/repro-build/Dockerfile.repro and rebuild the image" >&2
    exit 1
fi

cd "$SRC"
# Deliberately not exec: exec replaces this shell and the EXIT trap above would
# never run, leaving a root-owned build directory the caller cannot even delete.
status=0
# The container path exists to produce reproducible artifacts, and its cache
# directory would be discarded with the container anyway, so it always takes
# the cold path rather than the cached default of a local `build.sh image`.
./os/mkosi/build.sh --no-cache "$ACTION" "$OUT" || status=$?
exit "$status"
