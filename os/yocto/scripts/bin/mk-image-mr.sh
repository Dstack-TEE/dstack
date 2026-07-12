#!/bin/bash

set -euo pipefail

# Function to display usage
usage() {
    echo "Usage: $0 <url_or_local_file>"
    echo "Example: $0 https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.6.0/dstack-0.6.0.tar.gz"
    echo "Example: $0 /path/to/local/file.tar.gz"
    exit 1
}

# Check if argument is provided
if [ $# -ne 1 ]; then
    usage
fi

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
        curl -L -o "$ARCHIVE_FILE" "$INPUT"
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
    ARCHIVE_FILE="$INPUT"
fi

# Create extraction directory
mkdir -p "$EXTRACT_DIR"

# Extract the archive
echo "Extracting archive to: $EXTRACT_DIR"
tar -xzf "$ARCHIVE_FILE" -C "$EXTRACT_DIR"

# Find and read the digest
DIGEST_FILE=$(find "$EXTRACT_DIR" -name "digest.txt" -type f | head -1)
if [ -z "$DIGEST_FILE" ]; then
    echo "Error: digest.txt file not found in the extracted archive"
    exit 1
fi

DIGEST=$(cat "$DIGEST_FILE" | tr -d '\n\r' | sed 's/[^a-zA-Z0-9]//g')
if [ -z "$DIGEST" ]; then
    echo "Error: Could not read digest from $DIGEST_FILE"
    exit 1
fi

echo "Found digest: $DIGEST"

# Remove rootfs file(s)
echo "Removing rootfs files..."
find "$EXTRACT_DIR" -name "rootfs*" -type f -delete
REMOVED_COUNT=$(find "$EXTRACT_DIR" -name "rootfs*" -type f 2>/dev/null | wc -l)
if [ $REMOVED_COUNT -eq 0 ]; then
    echo "Rootfs files removed successfully"
else
    echo "Warning: Some rootfs files may still exist"
fi

# Create flattened structure in a new directory
FLATTEN_DIR="$TEMP_DIR/flattened"
mkdir -p "$FLATTEN_DIR"

echo "Flattening directory structure..."
# Find all files (not directories) and copy them to the flattened directory
find "$EXTRACT_DIR" -type f -exec cp {} "$FLATTEN_DIR/" \;

# Count files for verification
FILE_COUNT=$(find "$FLATTEN_DIR" -type f | wc -l)
echo "Flattened $FILE_COUNT files"

# Create the final archive with the digest-based name
OUTPUT_FILE="mr_${DIGEST}.tar.gz"
echo "Creating final archive: $OUTPUT_FILE"

# Change to the flattened directory and create archive without directory structure
cd "$FLATTEN_DIR"
tar -czf "../$OUTPUT_FILE" -- *
cd - >/dev/null

# Move the final file to the current working directory
mv "$TEMP_DIR/$OUTPUT_FILE" "./$OUTPUT_FILE"

echo "Successfully created: $OUTPUT_FILE"
echo "Archive contains $FILE_COUNT files with flattened structure"
