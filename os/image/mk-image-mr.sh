#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) Hashforest Technology LLC
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Function to display usage
usage() {
    local status=${1:-1}
    echo "Usage: ${0##*/} <url_or_local_file>"
    echo "Example: $0 https://github.com/Dstack-TEE/dstack/releases/download/guest-os-v0.6.0/dstack-0.6.0.tar.gz"
    echo "Example: $0 /path/to/local/file.tar.gz"
    exit "$status"
}

# Check if argument is provided
if [ $# -ne 1 ]; then
    usage
fi
case "$1" in
    -h|--help)
        usage 0
        ;;
esac

INPUT="$1"
TEMP_DIR=$(mktemp -d)
EXTRACT_DIR="$TEMP_DIR/extracted"

# Cleanup function
cleanup() {
    echo "Cleaning up temporary directory: $TEMP_DIR"
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

echo "Working directory: $TEMP_DIR"

# Download or copy the file
if [[ "$INPUT" =~ ^https?:// ]]; then
    echo "Downloading from URL: $INPUT"
    ARCHIVE_FILE="$TEMP_DIR/archive.tar.gz"
    if command -v curl >/dev/null 2>&1; then
        curl -fL -o "$ARCHIVE_FILE" "$INPUT"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$ARCHIVE_FILE" "$INPUT"
    else
        echo "Error: Neither curl nor wget is available for downloading"
        exit 1
    fi
else
    echo "Using local file: $INPUT"
    if [ ! -f "$INPUT" ]; then
        echo "Error: Local file does not exist: $INPUT"
        exit 1
    fi
    ARCHIVE_FILE=$(realpath "$INPUT")
fi

# Create extraction directory
mkdir -p "$EXTRACT_DIR"

# Extract the archive
echo "Extracting archive to: $EXTRACT_DIR"
tar -xzf "$ARCHIVE_FILE" -C "$EXTRACT_DIR" \
    --no-same-owner --no-same-permissions

# Find and read the digest
mapfile -d '' -t DIGEST_FILES < <(find "$EXTRACT_DIR" -name digest.txt -type f -print0)
if [ "${#DIGEST_FILES[@]}" -ne 1 ]; then
    echo "Error: expected exactly one digest.txt in the archive, found ${#DIGEST_FILES[@]}"
    exit 1
fi
DIGEST_FILE=${DIGEST_FILES[0]}

DIGEST=$(tr -d '\n\r' < "$DIGEST_FILE" | tr 'A-F' 'a-f')
if [[ ! "$DIGEST" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Error: digest.txt must contain exactly one SHA-256 hex digest"
    exit 1
fi

echo "Found digest: $DIGEST"

# Remove rootfs file(s)
echo "Removing rootfs files..."
REMOVED_COUNT=$(find "$EXTRACT_DIR" -name "rootfs*" -type f | wc -l)
find "$EXTRACT_DIR" -name "rootfs*" -type f -delete
echo "Removed $REMOVED_COUNT rootfs file(s)"

# Create flattened structure in a new directory
FLATTEN_DIR="$TEMP_DIR/flattened"
mkdir -p "$FLATTEN_DIR"

echo "Flattening directory structure..."
# Find all files (not directories) and copy them to the flattened directory.
# Refuse duplicate basenames instead of silently overwriting an artifact.
declare -A SEEN_BASENAMES=()
while IFS= read -r -d '' file; do
    name=$(basename "$file")
    if [[ -n "${SEEN_BASENAMES[$name]:-}" ]]; then
        echo "Error: duplicate archive basename while flattening: $name" >&2
        exit 1
    fi
    SEEN_BASENAMES[$name]=1
    cp "$file" "$FLATTEN_DIR/$name"
done < <(find "$EXTRACT_DIR" -type f -print0)

# Count files for verification
FILE_COUNT=$(find "$FLATTEN_DIR" -type f | wc -l)
echo "Flattened $FILE_COUNT files"

# Create the final archive with the digest-based name
OUTPUT_FILE="mr_${DIGEST}.tar.gz"
echo "Creating final archive: $OUTPUT_FILE"

# Change to the flattened directory and create archive without directory structure
cd "$FLATTEN_DIR"
LC_ALL=C tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    -czf "../$OUTPUT_FILE" -- *
cd - >/dev/null

# Move the final file to the current working directory
mv "$TEMP_DIR/$OUTPUT_FILE" "./$OUTPUT_FILE"

echo "Successfully created: $OUTPUT_FILE"
echo "Archive contains $FILE_COUNT files with flattened structure"
