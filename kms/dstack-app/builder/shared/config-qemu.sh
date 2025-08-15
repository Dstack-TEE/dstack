#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

BUILD_DIR="$1"
PREFIX="$2"
if [ -z "$BUILD_DIR" ]; then
  echo "Usage: $0 <build-directory>"
  exit 1
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

export SOURCE_DATE_EPOCH=$(git -C .. log -1 --pretty=%ct)
export CFLAGS="-DDUMP_ACPI_TABLES -Wno-builtin-macro-redefined -D__DATE__=\"\" -D__TIME__=\"\" -D__TIMESTAMP__=\"\""
export LDFLAGS="-Wl,--build-id=none"

../configure \
  --prefix="$PREFIX" \
  --target-list=x86_64-softmmu \
  --disable-werror

echo ""
echo "Build configured for reproducibility in $BUILD_DIR"
echo "To build, run: cd $BUILD_DIR && make"
