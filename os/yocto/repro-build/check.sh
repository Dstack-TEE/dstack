#!/bin/bash

THIS_DIR=$(cd $(dirname $0); pwd)

# Create a unique temporary directory and clean it up on exit
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

ACTION=$1

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

IMAGE_NAME=${IMAGE_NAME:-dstack-rootfs}
ROOTFS_PATH=tmp/work/${DSTACK_MACHINE:-dstack}-poky-linux/${IMAGE_NAME}/1.0/rootfs
BUILD_DIR_A=${1:-${THIS_DIR}/build-a}
BUILD_DIR_B=${2:-${THIS_DIR}/build-b}
BB_DIR_A=${BB_DIR_A:-${BUILD_DIR_A}/bb-build}
BB_DIR_B=${BB_DIR_B:-${BUILD_DIR_B}/bb-build}
ROOTFS_A=${BB_DIR_A}/${ROOTFS_PATH}
ROOTFS_B=${BB_DIR_B}/${ROOTFS_PATH}

# Only compare these image paths (relative to $BUILD_DIR_*/images).
# Everything else is ignored to avoid known non-reproducible artifacts.
COMPARE_IMAGE_WHITELIST=(
    "bzImage"
    "digest.txt"
    "initramfs.cpio.gz"
    "metadata.json"
    "measurement.gcp.cbor"
    "measurement.snp.cbor"
    "measurement.tdx.cbor"
    "ovmf.fd"
    "rootfs.img.parted.verity"
    "sha256sum.txt"
    "auth_hash.txt"
    "gcp/efi-root/EFI/BOOT/BOOTX64.EFI"
)

is_whitelisted_image() {
    local rel_path="$1"
    local item
    for item in "${COMPARE_IMAGE_WHITELIST[@]}"; do
        if [ "$rel_path" = "$item" ] || [[ "$rel_path" == */"$item" ]]; then
            return 0
        fi
    done
    return 1
}

check_files() {
    local path_a="$1"
    local path_b="$2"
    local rel_path="$3"
    
    if [ ! -e "$path_a" ]; then
        if [ -e "$path_b" ]; then
            echo -e "${RED}File missing in A: $path_b"
            return 1
        fi
        return 0
    fi
    if [ ! -e "$path_b" ]; then
        if [ -e "$path_a" ]; then
            echo -e "${RED}File missing in B: $path_a"
            return 1
        fi
        return 0
    fi

    if [ -d "$path_a" ]; then
        if [ ! -d "$path_b" ]; then
            echo -e "${RED}Path type mismatch: $rel_path is directory in A but not in B${NC}"
            return 1
        fi
        
        local differences=0
        while IFS= read -r -d '' file; do
            local rel_file="${file#$path_a/}"
            check_files "$path_a/$rel_file" "$path_b/$rel_file" "$rel_path/$rel_file"
            differences=$((differences + $?))
        done < <(find "$path_a" -maxdepth 1 -mindepth 1 -print0)
        
        return $differences
    else
        if [ ! -f "$path_b" ] && [ ! -L "$path_b" ]; then
            echo -e "${RED}Path type mismatch: $rel_path is file in A but not in B${NC}"
            ls -l $path_a
            ls -l $path_b
            return 1
        fi

        # Skip symlinks
        if [ -L "$path_a" ] || [ -L "$path_b" ]; then
            local link_a=$(readlink "$path_a")
            local link_b=$(readlink "$path_b")
            if [ "$link_a" != "$link_b" ]; then
                echo -e "${RED}Symlink mismatch for $rel_path:${NC}"
                echo -e "${RED}A: $link_a${NC}"
                echo -e "${RED}B: $link_b${NC}"
                return 1
            fi
            return 0
        fi

        # Compare regular files
        local hash_a=$(md5sum "$path_a" | cut -d' ' -f1)
        local hash_b=$(md5sum "$path_b" | cut -d' ' -f1)
        
        if [ "$hash_a" != "$hash_b" ]; then
            echo -e "${RED}Hash mismatch for $rel_path:${NC}"
            echo -e "${RED}A: $hash_a${NC}"
            echo -e "${RED}B: $hash_b${NC}"
            analyze "$path_a" "$path_b"
            return 1
        else
            echo -e "${GREEN}Match for $rel_path${NC}"
            return 0
        fi
    fi
}

analyze() {
    local BIN_A=$1
    local BIN_B=$2

    echo -e "\n${GREEN}Analyzing $BIN_A...${NC}"
    ls -l $BIN_A
    file $BIN_A
    readelf -n $BIN_A
    readelf -p .comment $BIN_A 2>/dev/null || true
    
    echo -e "\n${GREEN}Analyzing $BIN_B...${NC}"
    ls -l $BIN_B
    file $BIN_B
    readelf -n $BIN_B
    readelf -p .comment $BIN_B 2>/dev/null || true
    
    echo -e "\n${GREEN}Binary diff analysis:${NC}"
    # Create hex dumps and compare
    objdump -s $BIN_A > "$TEMP_DIR/bin_a.hex"
    objdump -s $BIN_B > "$TEMP_DIR/bin_b.hex"
    
    echo "Differences:"
    diff -u "$TEMP_DIR/bin_a.hex" "$TEMP_DIR/bin_b.hex" | grep -A 5 '^[^+-]' | head -n 100
}

check_images() {
    echo -e "${YELLOW}Checking image files...${NC}"
    local differences=0
    while IFS= read -r file_a; do
        rel_path=$(echo "$file_a" | sed "s#${BUILD_DIR_A}/images/##g")
        file_b="$BUILD_DIR_B/images/$rel_path"
        if ! is_whitelisted_image "$rel_path"; then
            continue
        fi
        if [ ! -f "$file_b" ]; then
            echo -e "${RED}$rel_path is not found in $BUILD_DIR_B/images/${NC}"
            differences=$((differences + 1))
            continue
        fi
        hash_a=$(md5sum "$file_a" | cut -d' ' -f 1)
        hash_b=$(md5sum "$file_b" | cut -d' ' -f 1)
        if [ "$hash_a" != "$hash_b" ]; then
            echo -e "${RED}Hash mismatch for $rel_path:${NC}"
            echo -e "${RED}$hash_a $file_a${NC}"
            echo -e "${RED}$hash_b $file_b${NC}"
            differences=$((differences + 1))
        else
            echo -e "${GREEN}Match for $rel_path${NC}"
        fi
    done < <(find "$BUILD_DIR_A/images" -type f)
    return $differences
}

check() {
    echo -e "${YELLOW}Checking reproducibility...${NC}"

    if check_images; then
        return 0
    fi

    echo -e "${YELLOW}Checking rootfs...${NC}: $ROOTFS_A -> $ROOTFS_B"
    local differences=0
    check_files "$ROOTFS_A" "$ROOTFS_B" ""
    differences=$?

    if [ $differences -eq 0 ]; then
        echo -e "\n${GREEN}All files are identical!${NC}"
        return 0
    else
        echo -e "\n${RED}Found $differences differences${NC}"
        return 1
    fi
}

check
