#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -e
PKG_LIST=$1

echo 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20250626T204007Z bookworm main' > /etc/apt/sources.list
echo 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20250626T204007Z bookworm-security main' >> /etc/apt/sources.list
echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10no-check-valid-until

mkdir -p /etc/apt/preferences.d
while IFS= read -r line; do
    pkg=$(echo "$line" | cut -d= -f1)
    ver=$(echo "$line" | cut -d= -f2)
    if [ -n "$pkg" ] && [ -n "$ver" ]; then
        printf 'Package: %s\nPin: version %s\nPin-Priority: 1001\n\n' "$pkg" "$ver" >> /etc/apt/preferences.d/pinned-packages
    fi
done < "$PKG_LIST"
