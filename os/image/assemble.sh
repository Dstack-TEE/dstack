#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) Hashforest Technology LLC
#
# SPDX-License-Identifier: BUSL-1.1

set -euo pipefail

DSTACK_TAR_RELEASE=${DSTACK_TAR_RELEASE:-1}
ENABLE_UKI_IMAGE=${ENABLE_UKI_IMAGE:-1}

# Fixed GPT GUIDs so partitioned images are reproducible (sgdisk randomizes by
# default). Partitions are located by PARTLABEL, not GUID, so these are arbitrary.
DSTACK_DISK_GUID=${DSTACK_DISK_GUID:-d5acc000-0000-4000-8000-000000000000}
DSTACK_ROOTFS_PART_GUID=${DSTACK_ROOTFS_PART_GUID:-d5acc000-0000-4000-8000-000000000001}
DSTACK_EFI_PART_GUID=${DSTACK_EFI_PART_GUID:-d5acc000-0000-4000-8000-000000000002}

usage() {
    cat <<EOF
Usage: ${0##*/} --manifest PATH

Assemble a release image from the backend-neutral OS artifact manifest.

Environment:
  DIST_DIR               Release output parent (default: <manifest-dir>/dist)
  OUTPUT_DIR             Unpacked release directory
  DSTACK_TAR_RELEASE     Create release tarballs (default: 1)
  ENABLE_UKI_IMAGE       Create the optional UKI disk image (default: 1)
  DSTACK_MR_BIN          Existing dstack-mr binary
EOF
}

MANIFEST=
while [ $# -gt 0 ]; do
    case "$1" in
        --manifest)
            MANIFEST=$2
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

if [ -z "$MANIFEST" ]; then
    echo "Error: --manifest is required" >&2
    usage >&2
    exit 1
fi
if [ ! -f "$MANIFEST" ]; then
    echo "Error: artifact manifest not found: $MANIFEST" >&2
    exit 1
fi
MANIFEST=$(realpath "$MANIFEST")

# Read and validate the small contract without requiring jq or jsonschema.
mapfile -d '' -t MANIFEST_VALUES < <(
    python3 - "$MANIFEST" <<'PYMANIFEST'
import json
import os
import sys

manifest_path = os.path.realpath(sys.argv[1])
with open(manifest_path, encoding="utf-8") as file:
    data = json.load(file)

if data.get("schema_version") != 1:
    raise SystemExit("unsupported artifact manifest schema_version")
if not isinstance(data.get("image", {}).get("is_dev"), bool):
    raise SystemExit("image.is_dev must be a boolean")

base = os.path.dirname(manifest_path)

def required(obj, *keys):
    value = obj
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            raise SystemExit("missing manifest field: " + ".".join(keys))
        value = value[key]
    if value is None or value == "":
        raise SystemExit("empty manifest field: " + ".".join(keys))
    return value

def artifact(name, optional=False):
    value = data.get("artifacts", {}).get(name)
    if value in (None, ""):
        if optional:
            return ""
        raise SystemExit(f"missing manifest artifact: {name}")
    if not isinstance(value, str):
        raise SystemExit(f"artifact path must be a string: {name}")
    normalized = os.path.normpath(value)
    if os.path.isabs(value) or normalized == ".." or normalized.startswith("../"):
        raise SystemExit(f"artifact path must be relative to the manifest: {name}")
    path = os.path.realpath(os.path.join(base, value))
    if not os.path.isfile(path):
        raise SystemExit(f"artifact does not exist: {name}: {path}")
    return path

values = [
    required(data, "backend"),
    required(data, "image", "name"),
    required(data, "image", "version"),
    required(data, "image", "flavor"),
    "true" if data["image"]["is_dev"] else "false",
    required(data, "source", "git_revision"),
    required(data, "boot", "ovmf_variant"),
    required(data, "verity", "root_hash"),
    str(required(data, "verity", "data_size")),
    artifact("initramfs"),
    artifact("kernel"),
    artifact("firmware"),
    artifact("rootfs_verity"),
    artifact("firmware_sev", optional=True),
    artifact("uki", optional=True),
]
for value in values:
    if not isinstance(value, str):
        raise SystemExit("manifest scalar fields must be strings")
    sys.stdout.buffer.write(value.encode() + b"\0")
PYMANIFEST
)

if [ "${#MANIFEST_VALUES[@]}" -ne 15 ]; then
    echo "Error: failed to read artifact manifest: $MANIFEST" >&2
    exit 1
fi

BACKEND=${MANIFEST_VALUES[0]}
DIST_NAME=${MANIFEST_VALUES[1]}
DSTACK_VERSION=${MANIFEST_VALUES[2]}
FLAVOR=${MANIFEST_VALUES[3]}
IS_DEV=${MANIFEST_VALUES[4]}
GIT_REVISION=${MANIFEST_VALUES[5]}
OVMF_VARIANT=${MANIFEST_VALUES[6]}
ROOT_HASH=${MANIFEST_VALUES[7]}
DATA_SIZE=${MANIFEST_VALUES[8]}
INITRAMFS_IMAGE=${MANIFEST_VALUES[9]}
KERNEL_IMAGE=${MANIFEST_VALUES[10]}
OVMF_FIRMWARE=${MANIFEST_VALUES[11]}
ROOTFS_IMAGE=${MANIFEST_VALUES[12]}
OVMF_SEV_FIRMWARE=${MANIFEST_VALUES[13]}
UKI_IMAGE=${MANIFEST_VALUES[14]}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(realpath "$SCRIPT_DIR/../..")
AUTHENTICODE_HASH_SCRIPT="${SCRIPT_DIR}/authenticode_hash.py"

MANIFEST_DIR=$(dirname "$MANIFEST")
DIST_DIR=${DIST_DIR:-"${MANIFEST_DIR}/dist"}
mkdir -p "$DIST_DIR"
DIST_DIR=$(realpath "$DIST_DIR")
OUTPUT_DIR=${OUTPUT_DIR:-"${DIST_DIR}/${DIST_NAME}-${DSTACK_VERSION}"}
OUTPUT_DIR=$(realpath -m "$OUTPUT_DIR")
case "$OUTPUT_DIR" in
    /|"$DIST_DIR"|"$MANIFEST_DIR"|"$REPO_ROOT")
        echo "Error: refusing unsafe output directory: $OUTPUT_DIR" >&2
        exit 1
        ;;
esac
IMAGE_TAR=${IMAGE_TAR:-"${DIST_DIR}/${DIST_NAME}-${DSTACK_VERSION}.tar.gz"}
IMAGE_TAR_UKI=${IMAGE_TAR_UKI:-"${DIST_DIR}/${DIST_NAME}-${DSTACK_VERSION}-uki.tar.gz"}
TAR_DIR_NAME=$(basename "$OUTPUT_DIR")

echo "Assembling ${DIST_NAME} ${DSTACK_VERSION} from ${BACKEND} artifacts (${FLAVOR})"

verbose() {
    printf '+ '
    printf '%q ' "$@"
    printf '\n'
    "$@"
}

align_up() {
    local value=$1
    local align=$2
    echo $(( ( (value + align - 1) / align ) * align ))
}

calc_authenticode_hash() {
    local file="$1"

    if [[ ! -f "$AUTHENTICODE_HASH_SCRIPT" ]] || ! command -v python3 &>/dev/null; then
        return 0
    fi

    python3 "$AUTHENTICODE_HASH_SCRIPT" "$file" 2>/dev/null || true
}

write_authenticode_hash() {
    local file="$1"
    local out_file="$2"

    if [[ ! -f "$file" ]]; then
        return 0
    fi

    if [[ ! -f "$AUTHENTICODE_HASH_SCRIPT" ]] || ! command -v python3 &>/dev/null; then
        echo "Warning: authenticode_hash.py not found or python3 not available, skipping Authenticode hash calculation" >&2
        return 0
    fi

    echo "Calculating UKI Authenticode hash..."
    local auth_hash
    auth_hash=$(calc_authenticode_hash "$file")
    if [[ -n "$auth_hash" ]]; then
        echo "$auth_hash" > "$out_file"
        echo "UKI Authenticode hash: $auth_hash"
    else
        echo "Warning: Failed to calculate UKI Authenticode hash" >&2
    fi
}

ensure_dstack_mr() {
    DSTACK_SRC="${DSTACK_SRC:-$REPO_ROOT/dstack}"
    if [ -z "${DSTACK_MR_BIN:-}" ] && [ -x "$DSTACK_SRC/target/release/dstack-mr" ]; then
        DSTACK_MR_BIN="$DSTACK_SRC/target/release/dstack-mr"
    fi
    if [ -z "${DSTACK_MR_BIN:-}" ]; then
        echo "Building dstack-mr to compute OS-image measurement material"
        ( cd "$DSTACK_SRC" && cargo build --release -p dstack-mr )
        DSTACK_MR_BIN="$DSTACK_SRC/target/release/dstack-mr"
    fi
}

create_partitioned_rootfs() {
    local rootfs_img="$1"
    local output_img="$2"
    (
        set -e
        local align=$((1024 * 1024))
        local sector=512
        local rootfs_size
        local rootfs_size_aligned
        local total_size
        rootfs_size=$(stat -L -c %s "$rootfs_img")
        rootfs_size_aligned=$(align_up "$rootfs_size" "$align")
        local rootfs_start=$align
        # Leave extra room for GPT headers (1MB at start, 1MB at end)
        total_size=$(align_up $((rootfs_start + rootfs_size_aligned + align)) "$align")

        truncate -s "$total_size" "$output_img"

        local root_start_sector=$((rootfs_start / sector))
        local root_end_sector=$((root_start_sector + (rootfs_size_aligned / sector) - 1))

        sgdisk --zap-all "$output_img" >/dev/null
        # Fixed GUIDs keep the image bit-for-bit reproducible (GPT otherwise
        # randomizes disk/partition GUIDs). The rootfs is located by PARTLABEL.
        sgdisk --disk-guid="${DSTACK_DISK_GUID}" \
               --new=1:${root_start_sector}:${root_end_sector} --typecode=1:8300 \
               --partition-guid=1:"${DSTACK_ROOTFS_PART_GUID}" \
               --change-name=1:'dstack-rootfs' "$output_img" >/dev/null

        dd if="$rootfs_img" of="$output_img" bs=$align seek=$((rootfs_start / align)) conv=notrunc status=none
    )
}

build_uki_disk_image() {
    local disk_img="$1"
    local uki_file="$2"
    local rootfs_img="$3"
    (
        set -e
        local align=$((1024 * 1024))
        local sector=512
        local efi_size=$((256 * 1024 * 1024))
        local efi_size_aligned
        local rootfs_size
        local rootfs_size_aligned
        local total_size
        efi_size_aligned=$(align_up "$efi_size" "$align")
        rootfs_size=$(stat -L -c %s "$rootfs_img")
        rootfs_size_aligned=$(align_up "$rootfs_size" "$align")
        local efi_start=$align
        local rootfs_start=$((efi_start + efi_size_aligned))
        # Leave extra room for the backup GPT header
        total_size=$(align_up $((rootfs_start + rootfs_size_aligned + align)) "$align")

        truncate -s "$total_size" "$disk_img"

        local efi_start_sector=$((efi_start / sector))
        local efi_end_sector=$((efi_start_sector + (efi_size_aligned / sector) - 1))
        local root_start_sector=$((rootfs_start / sector))
        local root_end_sector=$((root_start_sector + (rootfs_size_aligned / sector) - 1))

        sgdisk --zap-all "$disk_img" >/dev/null
        sgdisk --disk-guid="${DSTACK_DISK_GUID}" \
               --new=1:${efi_start_sector}:${efi_end_sector} --typecode=1:ef00 \
               --partition-guid=1:"${DSTACK_EFI_PART_GUID}" \
               --change-name=1:'EFI System Partition' "$disk_img" >/dev/null
        sgdisk --new=2:${root_start_sector}:${root_end_sector} --typecode=2:8300 \
               --partition-guid=2:"${DSTACK_ROOTFS_PART_GUID}" \
               --change-name=2:'dstack-rootfs' "$disk_img" >/dev/null

        local tmp_dir
        tmp_dir=$(mktemp -d)
        trap 'rm -rf "$tmp_dir"' EXIT

        # Create EFI filesystem with UKI as bootloader
        local efi_img=${tmp_dir}/efi.img
        mkfs.vfat -F 32 -n DSTACKEFI -C "$efi_img" $((efi_size_aligned / 1024)) >/dev/null
        mmd -i "$efi_img" ::EFI ::EFI/BOOT
        mcopy -i "$efi_img" "$uki_file" ::EFI/BOOT/BOOTX64.EFI

        dd if="$efi_img" of="$disk_img" bs=$align seek=$((efi_start / align)) conv=notrunc status=none
        dd if="$rootfs_img" of="$disk_img" bs=$align seek=$((rootfs_start / align)) conv=notrunc status=none
    )
}

create_uki_artifacts() {
    local uki_dir="$1"
    mkdir -p "$uki_dir"

    echo "Building UKI disk image at ${uki_dir}/disk.raw"
    build_uki_disk_image "${uki_dir}/disk.raw" "$UKI_IMAGE" "$ROOTFS_IMAGE"

    write_authenticode_hash "$UKI_IMAGE" "${uki_dir}/auth_hash.txt"
}

# Create bare metal image directory
verbose rm -rf "${OUTPUT_DIR}/"
verbose mkdir -p "${OUTPUT_DIR}/"
verbose cp "$INITRAMFS_IMAGE" "${OUTPUT_DIR}/initramfs.cpio.gz"
verbose cp "$KERNEL_IMAGE" "${OUTPUT_DIR}/bzImage"
verbose cp "$OVMF_FIRMWARE" "${OUTPUT_DIR}/ovmf.fd"

# AMD SEV firmware (additive). Shipped alongside the TDX firmware so a SEV-SNP
# launch can select it via the metadata.json "bios-sev" field below. The SEV
# firmware blob itself is NOT added directly to sha256sum.txt; when present, its
# OVMF hash/sections are committed by measurement.snp.cbor, and that file is
# part of digest.txt. This does not change any TDX hardware
# measurement (MRTD comes from ovmf.fd, RTMRs from kernel/cmdline/rootfs) -- it
# only changes dstack's image-bundle digest.
HAVE_OVMF_SEV=0
BIOS_SEV_JSON=""
if [ -n "$OVMF_SEV_FIRMWARE" ]; then
    verbose cp "$OVMF_SEV_FIRMWARE" "${OUTPUT_DIR}/ovmf-sev.fd"
    HAVE_OVMF_SEV=1
    # Inserted after the "bios" line in metadata.json (see below).
    BIOS_SEV_JSON='
    "bios-sev": "ovmf-sev.fd",'
fi

echo "Creating partitioned rootfs image at ${OUTPUT_DIR}/rootfs.img.parted.verity"
# Bare-metal partitioning needs sgdisk (from the 'gdisk' package).
if ! command -v sgdisk >/dev/null; then
    echo "Error: cannot create partitioned rootfs image because 'sgdisk' is missing; install 'gdisk'." >&2
    exit 1
fi
create_partitioned_rootfs "$ROOTFS_IMAGE" "${OUTPUT_DIR}/rootfs.img.parted.verity"

echo "Generating metadata.json to ${OUTPUT_DIR}/metadata.json (ovmf_variant=$OVMF_VARIANT)"

KARG0="console=ttyS0 init=/init panic=1 net.ifnames=0 biosdevname=0"
KARG1="mce=off oops=panic pci=noearly pci=nommconf random.trust_cpu=y random.trust_bootloader=n tsc=reliable no-kvmclock"
KARG2="dstack.rootfs_hash=$ROOT_HASH dstack.rootfs_size=$DATA_SIZE"

cat <<EOF > "${OUTPUT_DIR}/metadata.json"
{
    "bios": "ovmf.fd",${BIOS_SEV_JSON}
    "kernel": "bzImage",
    "cmdline": "$KARG0 $KARG1 $KARG2",
    "initrd": "initramfs.cpio.gz",
    "rootfs": "rootfs.img.parted.verity",
    "version": "$DSTACK_VERSION",
    "git_revision": "$GIT_REVISION",
    "shared_ro": true,
    "is_dev": ${IS_DEV},
    "ovmf_variant": "$OVMF_VARIANT"
}
EOF

ensure_dstack_mr

echo "Generating measurement.tdx.cbor via ${DSTACK_MR_BIN}"
"${DSTACK_MR_BIN}" tdx-measurement-cbor "${OUTPUT_DIR}" > "${OUTPUT_DIR}/measurement.tdx.cbor"

HAVE_MEASUREMENT_SNP=0
if [ "$HAVE_OVMF_SEV" = "1" ]; then
    echo "Generating measurement.snp.cbor via ${DSTACK_MR_BIN}"
    "${DSTACK_MR_BIN}" snp-measurement-cbor "${OUTPUT_DIR}" > "${OUTPUT_DIR}/measurement.snp.cbor"
    HAVE_MEASUREMENT_SNP=1
fi

# Create UKI artifacts (disk.raw and auth_hash.txt) in OUTPUT_DIR
UKI_CREATED=0
if [ "$ENABLE_UKI_IMAGE" = "1" ]; then
    if [[ -z "$UKI_IMAGE" ]]; then
        echo "Skipping UKI disk image creation because the backend did not export a UKI" >&2
    elif command -v sgdisk >/dev/null && \
         command -v mkfs.vfat >/dev/null && \
         command -v mcopy >/dev/null && \
         command -v mmd >/dev/null; then
        create_uki_artifacts "${OUTPUT_DIR}"
        UKI_CREATED=1
    else
        echo "Error: cannot create UKI disk image because required tools are missing" >&2
        echo "Missing tools are among: sgdisk (gdisk), mkfs.vfat (dosfstools), mcopy/mmd (mtools)" >&2
        echo "Install them (e.g. apt-get install -y gdisk dosfstools mtools) or set ENABLE_UKI_IMAGE=0" >&2
        exit 1
    fi
fi

HAVE_MEASUREMENT_GCP=0
if [[ "$UKI_CREATED" = "1" ]]; then
    if [[ ! -f "${OUTPUT_DIR}/auth_hash.txt" ]]; then
        echo "Error: UKI image was created but auth_hash.txt is missing" >&2
        exit 1
    fi
    echo "Generating measurement.gcp.cbor via ${DSTACK_MR_BIN}"
    "${DSTACK_MR_BIN}" gcp-measurement-cbor "${OUTPUT_DIR}/auth_hash.txt" > "${OUTPUT_DIR}/measurement.gcp.cbor"
    HAVE_MEASUREMENT_GCP=1
fi

echo "Generating unified image digest to ${OUTPUT_DIR}/"
CHECKSUM_FILES=(ovmf.fd bzImage initramfs.cpio.gz metadata.json measurement.tdx.cbor)
if [ "$HAVE_MEASUREMENT_SNP" = "1" ]; then
    CHECKSUM_FILES+=(measurement.snp.cbor)
fi
if [ "$HAVE_MEASUREMENT_GCP" = "1" ]; then
    CHECKSUM_FILES+=(measurement.gcp.cbor)
fi
(
    cd "${OUTPUT_DIR}/"
    sha256sum "${CHECKSUM_FILES[@]}" > sha256sum.txt
    sha256sum sha256sum.txt | awk '{print $1}' > digest.txt
)

if [ "$DSTACK_TAR_RELEASE" = "1" ]; then
    OUTPUT_DIR=$(realpath "${OUTPUT_DIR}")
    PARENT_DIR=$(dirname "${OUTPUT_DIR}")

    # Bare metal tarball: all files except disk.raw and auth_hash.txt
    rm -rf "${IMAGE_TAR}"
    echo "Archiving bare metal image to ${IMAGE_TAR}"
    BARE_METAL_FILES=(rootfs.img.parted.verity bzImage ovmf.fd digest.txt sha256sum.txt initramfs.cpio.gz metadata.json measurement.tdx.cbor)
    if [ "$HAVE_OVMF_SEV" = "1" ]; then
        BARE_METAL_FILES+=(ovmf-sev.fd)
    fi
    if [ "$HAVE_MEASUREMENT_SNP" = "1" ]; then
        BARE_METAL_FILES+=(measurement.snp.cbor)
    fi
    if [ "$HAVE_MEASUREMENT_GCP" = "1" ]; then
        BARE_METAL_FILES+=(measurement.gcp.cbor)
    fi
    BARE_METAL_TAR_FILES=()
    for file in "${BARE_METAL_FILES[@]}"; do
        BARE_METAL_TAR_FILES+=("$TAR_DIR_NAME/$file")
    done
    (cd "$PARENT_DIR" && tar -czvf "$IMAGE_TAR" "${BARE_METAL_TAR_FILES[@]}")
    echo

    # UKI tarball: GCP boot disk plus the unified OS-image identity material.
    if [[ "$UKI_CREATED" = "1" ]]; then
        rm -rf "${IMAGE_TAR_UKI}"
        echo "Archiving UKI image to ${IMAGE_TAR_UKI}"
        UKI_FILES=(disk.raw digest.txt sha256sum.txt measurement.gcp.cbor)
        UKI_TAR_FILES=()
        for file in "${UKI_FILES[@]}"; do
            UKI_TAR_FILES+=("$TAR_DIR_NAME/$file")
        done
        (cd "$PARENT_DIR" && tar -czvf "$IMAGE_TAR_UKI" "${UKI_TAR_FILES[@]}")
        echo
    fi
fi
