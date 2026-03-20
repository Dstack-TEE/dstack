#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Pin APT packages to exact versions from a frozen Debian snapshot.
# Usage: pin-packages.sh <pkg-list-file>
#
# This script:
# 1. Points APT at a frozen snapshot.debian.org mirror (reproducible package sources)
# 2. Reads package=version pairs from the given file and creates APT pin preferences
#    with priority 1001 to force exact versions

set -e

PKG_LIST=$1
SNAPSHOT_DATE=${SNAPSHOT_DATE:-20260317T000000Z}

if [ -z "$PKG_LIST" ]; then
    echo "Usage: $0 <pkg-list-file>" >&2
    exit 1
fi

echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT_DATE} bookworm main" > /etc/apt/sources.list
echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT_DATE} bookworm-security main" >> /etc/apt/sources.list
echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10no-check-valid-until

mkdir -p /etc/apt/preferences.d
while IFS= read -r line; do
    pkg=$(echo "$line" | cut -d= -f1)
    ver=$(echo "$line" | cut -d= -f2)
    if [ -n "$pkg" ] && [ -n "$ver" ]; then
        printf 'Package: %s\nPin: version %s\nPin-Priority: 1001\n\n' "$pkg" "$ver" >> /etc/apt/preferences.d/pinned-packages
    fi
done < "$PKG_LIST"
