#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) Hashforest Technology LLC
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
    cat <<EOF
Usage: ${0##*/} --dist-name NAME --flavor FLAVOR [--build-dir DIR] [--output-dir DIR]

Export Yocto build results through the common OS artifact-manifest contract.
The manifest and its artifact symlinks are written under the BitBake build
directory by default.
EOF
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
YOCTO_DIR=$(realpath "$SCRIPT_DIR/..")
REPO_ROOT=$(realpath "$YOCTO_DIR/../..")

DIST_NAME=
FLAVOR=
BUILD_DIR=${BB_BUILD_DIR:-build}
ARTIFACT_DIR=

while [ $# -gt 0 ]; do
    case "$1" in
        --dist-name)
            DIST_NAME=$2
            shift 2
            ;;
        --flavor)
            FLAVOR=$2
            shift 2
            ;;
        --build-dir)
            BUILD_DIR=$2
            shift 2
            ;;
        --output-dir)
            ARTIFACT_DIR=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ -z "$DIST_NAME" ] || [ -z "$FLAVOR" ]; then
    echo "Error: --dist-name and --flavor are required" >&2
    usage >&2
    exit 1
fi

case "$FLAVOR" in
    prod)
        if [[ "$DIST_NAME" == *-dev ]]; then
            echo "Error: prod flavor requires a non-dev dist name: $DIST_NAME" >&2
            exit 1
        fi
        IS_DEV=false
        ;;
    dev)
        if [[ "$DIST_NAME" != *-dev ]]; then
            echo "Error: dev flavor requires a dist name ending in -dev: $DIST_NAME" >&2
            exit 1
        fi
        IS_DEV=true
        ;;
    *)
        echo "Error: unsupported flavor '$FLAVOR' (expected prod or dev)" >&2
        exit 1
        ;;
esac

if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: BitBake build directory not found: $BUILD_DIR" >&2
    exit 1
fi
BUILD_DIR=$(realpath "$BUILD_DIR")
ARTIFACT_DIR=${ARTIFACT_DIR:-"$BUILD_DIR/dstack-artifacts/$FLAVOR"}
ARTIFACT_DIR=$(realpath -m "$ARTIFACT_DIR")
case "$ARTIFACT_DIR" in
    /|"$BUILD_DIR"|"$REPO_ROOT"|"$YOCTO_DIR")
        echo "Error: refusing unsafe artifact output directory: $ARTIFACT_DIR" >&2
        exit 1
        ;;
esac

DSTACK_MACHINE=${DSTACK_MACHINE:-dstack}
COMMON_IMG_DIR="$BUILD_DIR/tmp/deploy/images/$DSTACK_MACHINE"
FLAVOR_IMG_DIR="$BUILD_DIR/tmp-mc-$FLAVOR/deploy/images/$DSTACK_MACHINE"
VERITY_ENV_FILE="$BUILD_DIR/tmp-mc-$FLAVOR/work-shared/$DSTACK_MACHINE/dm-verity/dstack-rootfs.squashfs.verity.env"

if [ ! -f "$VERITY_ENV_FILE" ]; then
    echo "Error: verity env not found: $VERITY_ENV_FILE" >&2
    echo "Build the rootfs first, e.g. bitbake mc:${FLAVOR}:dstack-rootfs" >&2
    exit 1
fi

# A kconfig fragment is a request, not a guarantee: an unmet dependency drops
# the line and a tristate is clamped to whatever it depends on, both silently.
# linux-yocto%.bbappend deploys the built .config next to the images, so check
# it here before anything is published -- shipping a guest image whose kernel
# quietly lacks an asserted capability is the failure this guards against.
#
# Only dstack-docker.cfg is gated for now. dstack.cfg still has six lines the
# build does not satisfy (CONFIG_HOTPLUG_CPU/SCSI/INPUT are forced back on by
# machine-level features, and CONFIG_TLS/CRYPTO_GCM/CRYPTO_CHACHA20POLY1305 do
# not come out as asserted); each needs its own decision rather than a blanket
# edit, so gating it belongs in a follow-up.
KERNEL_CONFIG_FILE="$COMMON_IMG_DIR/kernel-config"
if [ -f "$KERNEL_CONFIG_FILE" ]; then
    "$REPO_ROOT/os/common/scripts/check-kernel-config.sh" \
        "$KERNEL_CONFIG_FILE" \
        "$YOCTO_DIR/layers/meta-dstack/recipes-kernel/linux/files/dstack-docker.cfg"
else
    echo "Error: kernel config not found: $KERNEL_CONFIG_FILE" >&2
    exit 1
fi
# shellcheck source=/dev/null
source "$VERITY_ENV_FILE"
: "${ROOT_HASH:?ROOT_HASH missing from verity environment}"
: "${DATA_SIZE:?DATA_SIZE missing from verity environment}"

DSTACK_VERSION=$(bitbake-getvar --value DISTRO_VERSION | tail -1)
OVMF_VARIANT=$(bitbake-getvar --value OVMF_VARIANT -r dstack-ovmf)
if [ -z "$DSTACK_VERSION" ] || [ -z "$OVMF_VARIANT" ]; then
    echo "Error: failed to read DISTRO_VERSION or OVMF_VARIANT from BitBake" >&2
    exit 1
fi
GIT_REVISION=${DSTACK_GIT_REVISION:-}
if [ -z "$GIT_REVISION" ]; then
    GIT_REVISION=$(git -C "$REPO_ROOT" rev-parse HEAD)
fi

rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR/files"

link_required() {
    local source=$1
    local name=$2
    if [ ! -f "$source" ]; then
        echo "Error: required Yocto artifact not found: $source" >&2
        exit 1
    fi
    ln -s "$(realpath "$source")" "$ARTIFACT_DIR/files/$name"
}

link_optional() {
    local source=$1
    local name=$2
    if [ -f "$source" ]; then
        ln -s "$(realpath "$source")" "$ARTIFACT_DIR/files/$name"
        return 0
    fi
    return 1
}

link_required "$COMMON_IMG_DIR/dstack-initramfs.cpio.gz" initramfs.cpio.gz
link_required "$COMMON_IMG_DIR/bzImage" bzImage
link_required "$COMMON_IMG_DIR/ovmf.fd" ovmf.fd
link_required "$FLAVOR_IMG_DIR/dstack-rootfs-${DSTACK_MACHINE}.squashfs.verity" rootfs.squashfs.verity

FIRMWARE_SEV=
UKI=
if link_optional "$COMMON_IMG_DIR/ovmf-sev.fd" ovmf-sev.fd; then
    FIRMWARE_SEV=files/ovmf-sev.fd
fi
if link_optional "$FLAVOR_IMG_DIR/dstack-uki.efi" dstack-uki.efi; then
    UKI=files/dstack-uki.efi
fi

python3 - \
    "$ARTIFACT_DIR/artifact-manifest.json" \
    "$DIST_NAME" "$DSTACK_VERSION" "$FLAVOR" "$IS_DEV" \
    "$GIT_REVISION" "$OVMF_VARIANT" "$ROOT_HASH" "$DATA_SIZE" \
    "$DSTACK_MACHINE" "$FIRMWARE_SEV" "$UKI" <<'PYMANIFEST'
import json
import sys

(
    output,
    name,
    version,
    flavor,
    is_dev,
    git_revision,
    ovmf_variant,
    root_hash,
    data_size,
    machine,
    firmware_sev,
    uki,
) = sys.argv[1:]

manifest = {
    "schema_version": 1,
    "backend": "yocto",
    "image": {
        "name": name,
        "version": version,
        "flavor": flavor,
        "is_dev": is_dev == "true",
    },
    "source": {"git_revision": git_revision},
    "boot": {"ovmf_variant": ovmf_variant},
    "verity": {"root_hash": root_hash, "data_size": data_size},
    "artifacts": {
        "initramfs": "files/initramfs.cpio.gz",
        "kernel": "files/bzImage",
        "firmware": "files/ovmf.fd",
        "rootfs_verity": "files/rootfs.squashfs.verity",
        "firmware_sev": firmware_sev or None,
        "uki": uki or None,
    },
    "backend_metadata": {"machine": machine},
}
with open(output, "w", encoding="utf-8") as file:
    json.dump(manifest, file, indent=2)
    file.write("\n")
PYMANIFEST

echo "$ARTIFACT_DIR/artifact-manifest.json"
