#!/bin/bash
set -e

DSTACK_TAR_RELEASE=${DSTACK_TAR_RELEASE:-1}
ENABLE_UKI_IMAGE=${ENABLE_UKI_IMAGE:-1}

# Fixed GPT GUIDs so partitioned images are reproducible (sgdisk randomizes by
# default). Partitions are located by PARTLABEL, not GUID, so these are arbitrary.
DSTACK_DISK_GUID=${DSTACK_DISK_GUID:-d5acc000-0000-4000-8000-000000000000}
DSTACK_ROOTFS_PART_GUID=${DSTACK_ROOTFS_PART_GUID:-d5acc000-0000-4000-8000-000000000001}
DSTACK_EFI_PART_GUID=${DSTACK_EFI_PART_GUID:-d5acc000-0000-4000-8000-000000000002}

# Parse command line arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --dist-name)
            DIST_NAME="$2"
            shift 2
            ;;
        --flavor)
            FLAVOR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 --dist-name NAME --flavor FLAVOR"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$DIST_NAME" ]; then
    echo "Error: --dist-name is required"
    exit 1
fi

if [ -z "$FLAVOR" ]; then
    echo "Error: --flavor is required (prod, dev)"
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
        echo "Error: unsupported --flavor '$FLAVOR' (expected prod or dev)" >&2
        exit 1
        ;;
esac

BB_BUILD_DIR=$(realpath ${BB_BUILD_DIR:-build})
DIST_DIR=$(realpath ${DIST_DIR:-${BB_BUILD_DIR}/dist})

# MACHINE name; artifacts are deployed under deploy/images/${MACHINE}
DSTACK_MACHINE=${DSTACK_MACHINE:-dstack}

# Common artifacts are in tmp/, flavor-specific artifacts are in tmp-mc-<flavor>/
COMMON_IMG_DIR=${BB_BUILD_DIR}/tmp/deploy/images/${DSTACK_MACHINE}
FLAVOR_IMG_DIR=${BB_BUILD_DIR}/tmp-mc-${FLAVOR}/deploy/images/${DSTACK_MACHINE}

# Common artifacts (shared across all flavors)
INITRAMFS_IMAGE=${COMMON_IMG_DIR}/dstack-initramfs.cpio.gz
KERNEL_IMAGE=${COMMON_IMG_DIR}/bzImage
OVMF_FIRMWARE=${COMMON_IMG_DIR}/ovmf.fd

# Flavor-specific artifacts (from multiconfig build)
ROOTFS_IMAGE=${FLAVOR_IMG_DIR}/dstack-rootfs-${DSTACK_MACHINE}.squashfs.verity

# UKI filename
UKI_IMAGE=${FLAVOR_IMG_DIR}/dstack-uki.efi

# Verity env is in the flavor-specific work-shared directory
VERITY_ENV_FILE=${BB_BUILD_DIR}/tmp-mc-${FLAVOR}/work-shared/${DSTACK_MACHINE}/dm-verity/dstack-rootfs.squashfs.verity.env
if [ ! -f "${VERITY_ENV_FILE}" ]; then
    echo "Error: verity env not found: ${VERITY_ENV_FILE}" >&2
    echo "Build the rootfs first, e.g.: bitbake mc:${FLAVOR}:dstack-rootfs" >&2
    exit 1
fi
echo "Loading verity env from ${VERITY_ENV_FILE}"
# shellcheck source=/dev/null
source "${VERITY_ENV_FILE}"

DSTACK_VERSION=$(bitbake-getvar --value DISTRO_VERSION | tail -1)

# Output directory contains all artifacts; tarballs contain subsets
OUTPUT_DIR=${OUTPUT_DIR:-"${DIST_DIR}/${DIST_NAME}-${DSTACK_VERSION}"}
IMAGE_TAR=${IMAGE_TAR:-"${DIST_DIR}/${DIST_NAME}-${DSTACK_VERSION}.tar.gz"}
IMAGE_TAR_UKI="${DIST_DIR}/${DIST_NAME}-${DSTACK_VERSION}-uki.tar.gz"
TAR_DIR_NAME="${DIST_NAME}-${DSTACK_VERSION}"

# Use script's directory to find authenticode_hash.py
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AUTHENTICODE_HASH_SCRIPT="${SCRIPT_DIR}/scripts/bin/authenticode_hash.py"

verbose() {
    echo "$@"
    $@
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
    local out_file="${file}.auth_hash.txt"

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
    DSTACK_SRC="${DSTACK_SRC:-$SCRIPT_DIR/dstack}"
    if [ -z "${DSTACK_MR_BIN:-}" ]; then
        for c in "$SCRIPT_DIR/dstack-mr" "$SCRIPT_DIR/rust-target/release/dstack-mr" \
                 "$DSTACK_SRC/target/release/dstack-mr"; do
            [ -x "$c" ] && DSTACK_MR_BIN="$c" && break
        done
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
        local rootfs_size=$(stat -L -c %s "$rootfs_img")
        local rootfs_size_aligned=$(align_up $rootfs_size $align)
        local rootfs_start=$align
        # Leave extra room for GPT headers (1MB at start, 1MB at end)
        local total_size=$(align_up $((rootfs_start + rootfs_size_aligned + align)) $align)

        truncate -s $total_size "$output_img"

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
        local efi_size_aligned=$(align_up $efi_size $align)
        local rootfs_size=$(stat -L -c %s "$rootfs_img")
        local rootfs_size_aligned=$(align_up $rootfs_size $align)
        local efi_start=$align
        local rootfs_start=$((efi_start + efi_size_aligned))
        # Leave extra room for the backup GPT header
        local total_size=$(align_up $((rootfs_start + rootfs_size_aligned + align)) $align)

        truncate -s $total_size "$disk_img"

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

    # Calculate and copy auth hash
    write_authenticode_hash "$UKI_IMAGE"
    if [[ -f "${UKI_IMAGE}.auth_hash.txt" ]]; then
        cp "${UKI_IMAGE}.auth_hash.txt" "${uki_dir}/auth_hash.txt"
    fi
}

Q=verbose

# Create bare metal image directory
$Q rm -rf ${OUTPUT_DIR}/
$Q mkdir -p ${OUTPUT_DIR}/
$Q cp $INITRAMFS_IMAGE ${OUTPUT_DIR}/initramfs.cpio.gz
$Q cp $KERNEL_IMAGE ${OUTPUT_DIR}/
$Q cp $OVMF_FIRMWARE ${OUTPUT_DIR}/

# AMD SEV firmware (additive). Shipped alongside the TDX firmware so a SEV-SNP
# launch can select it via the metadata.json "bios-sev" field below. The SEV
# firmware blob itself is NOT added directly to sha256sum.txt; when present, its
# OVMF hash/sections are committed by measurement.snp.cbor, and that file is
# part of digest.txt. This does not change any TDX hardware
# measurement (MRTD comes from ovmf.fd, RTMRs from kernel/cmdline/rootfs) -- it
# only changes dstack's image-bundle digest.
OVMF_SEV_FIRMWARE=${COMMON_IMG_DIR}/ovmf-sev.fd
HAVE_OVMF_SEV=0
BIOS_SEV_JSON=""
if [ -f "$OVMF_SEV_FIRMWARE" ]; then
    $Q cp $OVMF_SEV_FIRMWARE ${OUTPUT_DIR}/
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

GIT_REVISION=$(git rev-parse HEAD 2>/dev/null || echo "<unknown>")

# Lift the OVMF variant tag straight out of the dstack-ovmf recipe so verifiers
# know which RTMR[0] event layout to expect. Required: the recipe must declare
# OVMF_VARIANT alongside PV.
OVMF_VARIANT=$(bitbake-getvar --value OVMF_VARIANT -r dstack-ovmf)
if [ -z "$OVMF_VARIANT" ]; then
    echo "Error: dstack-ovmf recipe is missing OVMF_VARIANT" >&2
    exit 1
fi

echo "Generating metadata.json to ${OUTPUT_DIR}/metadata.json (ovmf_variant=$OVMF_VARIANT)"

KARG0="console=ttyS0 init=/init panic=1 net.ifnames=0 biosdevname=0"
KARG1="mce=off oops=panic pci=noearly pci=nommconf random.trust_cpu=y random.trust_bootloader=n tsc=reliable no-kvmclock"
KARG2="dstack.rootfs_hash=$ROOT_HASH dstack.rootfs_size=$DATA_SIZE"

cat <<EOF > ${OUTPUT_DIR}/metadata.json
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
    if [[ ! -f "$UKI_IMAGE" ]]; then
        echo "Skipping UKI disk image creation because UKI image not found: $UKI_IMAGE" >&2
        echo "Run 'bitbake mc:${FLAVOR}:dstack-uki' to build the UKI first" >&2
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
CHECKSUM_FILES="ovmf.fd bzImage initramfs.cpio.gz metadata.json measurement.tdx.cbor"
if [ "$HAVE_MEASUREMENT_SNP" = "1" ]; then
    CHECKSUM_FILES="$CHECKSUM_FILES measurement.snp.cbor"
fi
if [ "$HAVE_MEASUREMENT_GCP" = "1" ]; then
    CHECKSUM_FILES="$CHECKSUM_FILES measurement.gcp.cbor"
fi
(
    cd "${OUTPUT_DIR}/"
    sha256sum $CHECKSUM_FILES > sha256sum.txt
    sha256sum sha256sum.txt | awk '{print $1}' > digest.txt
)

if [ x$DSTACK_TAR_RELEASE = x1 ]; then
    OUTPUT_DIR=$(realpath ${OUTPUT_DIR})
    PARENT_DIR=$(dirname ${OUTPUT_DIR})

    # Bare metal tarball: all files except disk.raw and auth_hash.txt
    rm -rf ${IMAGE_TAR}
    echo "Archiving bare metal image to ${IMAGE_TAR}"
    BARE_METAL_FILES="rootfs.img.parted.verity bzImage ovmf.fd digest.txt sha256sum.txt initramfs.cpio.gz metadata.json measurement.tdx.cbor"
    if [ "$HAVE_OVMF_SEV" = "1" ]; then
        BARE_METAL_FILES="$BARE_METAL_FILES ovmf-sev.fd"
    fi
    if [ "$HAVE_MEASUREMENT_SNP" = "1" ]; then
        BARE_METAL_FILES="$BARE_METAL_FILES measurement.snp.cbor"
    fi
    if [ "$HAVE_MEASUREMENT_GCP" = "1" ]; then
        BARE_METAL_FILES="$BARE_METAL_FILES measurement.gcp.cbor"
    fi
    (cd "$PARENT_DIR" && tar -czvf ${IMAGE_TAR} $(for f in $BARE_METAL_FILES; do echo "$TAR_DIR_NAME/$f"; done))
    echo

    # UKI tarball: GCP boot disk plus the unified OS-image identity material.
    if [[ "$UKI_CREATED" = "1" ]]; then
        rm -rf ${IMAGE_TAR_UKI}
        echo "Archiving UKI image to ${IMAGE_TAR_UKI}"
        UKI_FILES="disk.raw digest.txt sha256sum.txt measurement.gcp.cbor"
        (cd "$PARENT_DIR" && tar -czvf ${IMAGE_TAR_UKI} $(for f in $UKI_FILES; do echo "$TAR_DIR_NAME/$f"; done))
        echo
    fi
fi
