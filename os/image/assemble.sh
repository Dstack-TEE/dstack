#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) Hashforest Technology LLC
#
# SPDX-License-Identifier: Apache-2.0

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
Usage: ${0##*/} --manifest PATH [--validate-only]

Assemble a release image from the backend-neutral OS artifact manifest.

Environment:
  DIST_DIR               Release output parent (default: <manifest-dir>/dist)
  OUTPUT_DIR             Unpacked release directory
  DSTACK_TAR_RELEASE     Create release tarballs (default: 1)
  ENABLE_UKI_IMAGE       Create the optional UKI disk image (default: 1)
  DSTACK_MR_BIN          Existing dstack-mr binary
  NITRO_TPM_PCR_COMPUTE_BIN  Pinned host nitro-tpm-pcr-compute (required for
                         UKI AWS PCRs; overrides PATH lookup)
  NITRO_TPM_PCR_PK/KEK/DB    Optional Secure Boot ESL paths for PCR7
  --validate-only          Validate the manifest and referenced artifacts only
EOF
}

MANIFEST=
VALIDATE_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --manifest)
            MANIFEST=$2
            shift 2
            ;;
        --validate-only)
            VALIDATE_ONLY=1
            shift
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
base = os.path.dirname(manifest_path)

def exact_keys(obj, path, required_keys, optional_keys=()):
    if not isinstance(obj, dict):
        raise SystemExit(f"manifest field must be an object: {path}")
    required_keys = set(required_keys)
    allowed_keys = required_keys | set(optional_keys)
    missing = sorted(required_keys - set(obj))
    extra = sorted(set(obj) - allowed_keys)
    if missing:
        raise SystemExit(f"missing manifest field: {path}." + missing[0])
    if extra:
        raise SystemExit(f"unknown manifest field: {path}." + extra[0])

exact_keys(
    data,
    "manifest",
    ("schema_version", "backend", "image", "source", "boot", "verity", "artifacts"),
    ("backend_metadata",),
)
exact_keys(data["image"], "image", ("name", "version", "flavor", "is_dev"))
exact_keys(data["source"], "source", ("git_revision",))
exact_keys(data["boot"], "boot", ("ovmf_variant",))
exact_keys(data["verity"], "verity", ("root_hash", "data_size"))
exact_keys(
    data["artifacts"],
    "artifacts",
    ("initramfs", "kernel", "firmware", "rootfs_verity", "firmware_sev", "uki"),
)
if "backend_metadata" in data and not isinstance(data["backend_metadata"], dict):
    raise SystemExit("manifest field must be an object: backend_metadata")

def nonempty_string(value, path):
    if not isinstance(value, str) or not value:
        raise SystemExit(f"manifest field must be a non-empty string: {path}")
    return value

for path, value in (
    ("backend", data["backend"]),
    ("image.name", data["image"]["name"]),
    ("image.version", data["image"]["version"]),
    ("image.flavor", data["image"]["flavor"]),
    ("source.git_revision", data["source"]["git_revision"]),
    ("boot.ovmf_variant", data["boot"]["ovmf_variant"]),
    ("verity.root_hash", data["verity"]["root_hash"]),
):
    nonempty_string(value, path)
if not isinstance(data["image"]["is_dev"], bool):
    raise SystemExit("image.is_dev must be a boolean")
data_size = data["verity"]["data_size"]
if isinstance(data_size, bool) or not (
    isinstance(data_size, int) and data_size >= 1
    or isinstance(data_size, str) and data_size.isdigit() and not data_size.startswith("0")
):
    raise SystemExit("verity.data_size must be a positive integer")

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
if [ "$VALIDATE_ONLY" -eq 1 ]; then
    echo "Artifact manifest is valid: $MANIFEST"
    exit 0
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

        # Fix both the FAT volume metadata and directory entry timestamps.
        # mmd stamps new directories with wall-clock time, so populate the
        # filesystem recursively from a normalized host-side tree instead.
        local efi_img=${tmp_dir}/efi.img
        local efi_tree=${tmp_dir}/tree
        mkdir -p "$efi_tree/EFI/BOOT"
        cp "$uki_file" "$efi_tree/EFI/BOOT/BOOTX64.EFI"
        # FAT stores local time and mtools converts using TZ, so the image
        # would otherwise differ between builders in different time zones.
        export TZ=UTC
        # FAT timestamps start at 1980-01-01, so a Unix epoch of 0 does not
        # round-trip: it wraps and every directory entry is dated 2107. No
        # backend entrypoint exports SOURCE_DATE_EPOCH today, so clamp rather
        # than fall back to 0.
        local fat_epoch=${SOURCE_DATE_EPOCH:-0}
        if [ "$fat_epoch" -lt 315532800 ]; then
            fat_epoch=315532800
        fi
        find "$efi_tree" -print0 | xargs -0r touch --no-dereference \
          --date="@${fat_epoch}"
        mkfs.vfat --invariant -F 32 -n DSTACKEFI -C "$efi_img" \
          $((efi_size_aligned / 1024)) >/dev/null
        mcopy -smp -i "$efi_img" "$efi_tree/EFI" ::

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

# shellcheck source=kernel-cmdline.sh
# The prek hook runs shellcheck without -x, so the path above documents the
# target but cannot be followed; SC1091 is noise rather than a finding.
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/kernel-cmdline.sh"
KERNEL_CMDLINE=$(dstack_kernel_cmdline "$ROOT_HASH" "$DATA_SIZE")

cat <<EOF > "${OUTPUT_DIR}/metadata.json"
{
    "bios": "ovmf.fd",${BIOS_SEV_JSON}
    "kernel": "bzImage",
    "cmdline": "$KERNEL_CMDLINE",
    "initrd": "initramfs.cpio.gz",
    "rootfs": "rootfs.img.parted.verity",
    "version": "$DSTACK_VERSION",
    "git_revision": "$GIT_REVISION",
    "backend": "$BACKEND",
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
         command -v mcopy >/dev/null; then
        create_uki_artifacts "${OUTPUT_DIR}"
        UKI_CREATED=1
    else
        echo "Error: cannot create UKI disk image because required tools are missing" >&2
        echo "Missing tools are among: sgdisk (gdisk), mkfs.vfat (dosfstools), mcopy (mtools)" >&2
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
    if [[ "$IS_DEV" = "true" ]]; then
        gcp_event_log_template="${GCP_TPM_EVENT_LOG_TEMPLATE:-$(dirname "$0")/../../dstack/cc-eventlog/samples/tpm_eventlog.bin}"
        echo "Generating image-specific GCP TPM event log for the dev image"
        python3 "$(dirname "$0")/gcp-tpm-eventlog.py" \
            --template "$gcp_event_log_template" \
            --uki-hash "${OUTPUT_DIR}/auth_hash.txt" \
            --output "${OUTPUT_DIR}/measurement.gcp.eventlog.bin"
    fi
    HAVE_MEASUREMENT_GCP=1
fi

# AWS NitroTPM boot PCR digest → measurement.aws.cbor
# (boot_pcr_digest = sha256(PCR4||PCR7||PCR12); raw PCRs not stored).
#
# MUST be computed at image assemble time and listed in sha256sum.txt so
# os_image_hash = sha256(sha256sum.txt) is fixed for the release artifact.
# prepare/deploy only *embed* this material; they must never recompute it.
#
# Requires a host `nitro-tpm-pcr-compute` (Rust tool from aws/NitroTPM-Tools,
# install with --locked). No unpinned container fallback: this value ends up
# in os_image_hash, so only a version-pinned operator-installed tool may
# produce it.
# Optional: NITRO_TPM_PCR_COMPUTE_BIN=/path/to/bin
# Optional Secure Boot ESL inputs (PCR7): NITRO_TPM_PCR_PK/KEK/DB (.esl paths)
HAVE_MEASUREMENT_AWS=0
if [[ "$UKI_CREATED" = "1" ]]; then
    if [[ -z "${UKI_IMAGE:-}" || ! -f "${UKI_IMAGE}" ]]; then
        echo "Error: UKI image was created but UKI_IMAGE is missing" >&2
        exit 1
    fi
    if ! command -v jq >/dev/null 2>&1; then
        echo "Error: jq is required to parse nitro-tpm-pcr-compute output" >&2
        exit 1
    fi

    uki_abs=$(realpath "$UKI_IMAGE")
    pcr_compute_bin="${NITRO_TPM_PCR_COMPUTE_BIN:-}"
    if [[ -z "$pcr_compute_bin" ]] && command -v nitro-tpm-pcr-compute >/dev/null 2>&1; then
        pcr_compute_bin=$(command -v nitro-tpm-pcr-compute)
    fi

    # No unpinned fallback here on purpose: the computed PCRs feed
    # measurement.aws.cbor -> sha256sum.txt -> os_image_hash, i.e. the
    # measurement the KMS and verifiers enforce. Only a version-pinned,
    # operator-installed tool may produce it.
    if [[ -z "$pcr_compute_bin" ]]; then
        echo "Error: cannot produce measurement.aws.cbor for UKI image." >&2
        echo "Install the pinned host tool:" >&2
        echo "  cargo install --git https://github.com/aws/NitroTPM-Tools --rev d76d6eeebd4169b00a3c3af9858852d48f40e748 --locked nitro-tpm-pcr-compute" >&2
        echo "  # or set NITRO_TPM_PCR_COMPUTE_BIN=/path/to/nitro-tpm-pcr-compute" >&2
        echo "measurement.aws.cbor must be fixed at assemble time for a stable os_image_hash." >&2
        exit 1
    fi
    echo "Generating AWS PCRs and replay events via host ${pcr_compute_bin}"
    pcr_args=(--image "$uki_abs")
    # Secure Boot variable stores (optional; affects PCR7)
    [[ -n "${NITRO_TPM_PCR_PK:-}" ]] && pcr_args+=(--PK "$NITRO_TPM_PCR_PK")
    [[ -n "${NITRO_TPM_PCR_KEK:-}" ]] && pcr_args+=(--KEK "$NITRO_TPM_PCR_KEK")
    [[ -n "${NITRO_TPM_PCR_DB:-}" ]] && pcr_args+=(--db "$NITRO_TPM_PCR_DB")
    pcr_trace="${OUTPUT_DIR}/aws-pcr-compute.trace"
    pcr_json_path="${OUTPUT_DIR}/aws-pcrs.json"
    pcr_json=$(RUST_LOG=nitro_tpm_pcr_compute=debug \
        "$pcr_compute_bin" "${pcr_args[@]}" 2>"$pcr_trace") \
        || { echo "Error: nitro-tpm-pcr-compute failed" >&2; exit 1; }
    printf '%s\n' "$pcr_json" > "$pcr_json_path"

    pcr4=$(jq -r '.Measurements.PCR4 // empty' <<<"$pcr_json")
    pcr7=$(jq -r '.Measurements.PCR7 // empty' <<<"$pcr_json")
    pcr12=$(jq -r '.Measurements.PCR12 // empty' <<<"$pcr_json")
    if [[ -z "$pcr4" || -z "$pcr7" || -z "$pcr12" ]]; then
        echo "Error: nitro-tpm-pcr-compute output missing PCR4, PCR7, or PCR12" >&2
        echo "$pcr_json" >&2
        exit 1
    fi
    echo "Generating measurement.aws.cbor via ${DSTACK_MR_BIN}"
    "${DSTACK_MR_BIN}" aws-measurement-cbor "$pcr4" "$pcr7" "$pcr12" \
        > "${OUTPUT_DIR}/measurement.aws.cbor"
    python3 "$(dirname "$0")/aws-pcr-replay.py" \
        --trace "$pcr_trace" \
        --measurements "$pcr_json_path" \
        --output "${OUTPUT_DIR}/measurement.aws.replay.json"
    rm "$pcr_trace"
    HAVE_MEASUREMENT_AWS=1
fi

echo "Generating unified image digest to ${OUTPUT_DIR}/"
CHECKSUM_FILES=(ovmf.fd bzImage initramfs.cpio.gz metadata.json measurement.tdx.cbor)
if [ "$HAVE_MEASUREMENT_SNP" = "1" ]; then
    CHECKSUM_FILES+=(measurement.snp.cbor)
fi
if [ "$HAVE_MEASUREMENT_GCP" = "1" ]; then
    CHECKSUM_FILES+=(measurement.gcp.cbor)
fi
if [ "$HAVE_MEASUREMENT_AWS" = "1" ]; then
    CHECKSUM_FILES+=(measurement.aws.cbor measurement.aws.replay.json)
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
        if [[ "$IS_DEV" = "true" ]]; then
            BARE_METAL_FILES+=(measurement.gcp.eventlog.bin)
        fi
    fi
    if [ "$HAVE_MEASUREMENT_AWS" = "1" ]; then
        BARE_METAL_FILES+=(measurement.aws.cbor measurement.aws.replay.json)
    fi
    BARE_METAL_TAR_FILES=()
    for file in "${BARE_METAL_FILES[@]}"; do
        BARE_METAL_TAR_FILES+=("$TAR_DIR_NAME/$file")
    done
    (cd "$PARENT_DIR" && tar -czvf "$IMAGE_TAR" "${BARE_METAL_TAR_FILES[@]}")
    echo

    # UKI tarball: cloud boot disk plus the unified OS-image identity material.
    if [[ "$UKI_CREATED" = "1" ]]; then
        rm -rf "${IMAGE_TAR_UKI}"
        echo "Archiving UKI image to ${IMAGE_TAR_UKI}"
        UKI_FILES=(disk.raw digest.txt sha256sum.txt measurement.gcp.cbor measurement.aws.cbor measurement.aws.replay.json)
        if [[ "$IS_DEV" = "true" ]]; then
            UKI_FILES+=(measurement.gcp.eventlog.bin)
        fi
        UKI_TAR_FILES=()
        for file in "${UKI_FILES[@]}"; do
            UKI_TAR_FILES+=("$TAR_DIR_NAME/$file")
        done
        (cd "$PARENT_DIR" && tar -czvf "$IMAGE_TAR_UKI" "${UKI_TAR_FILES[@]}")
        echo
    fi
fi
