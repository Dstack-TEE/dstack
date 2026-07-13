#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Verify that installed packages in a Docker image match the committed
# pinned-packages file. Detects when Dockerfile changes cause package
# drift without regenerating the pinned-packages list.
#
# Usage: verify-pinned-packages.sh <image> <pinned-packages-file>

set -euo pipefail

IMAGE=$1
PKG_FILE=$2

if [ -z "$IMAGE" ] || [ -z "$PKG_FILE" ]; then
    echo "Usage: $0 <image> <pinned-packages-file>" >&2
    exit 1
fi

ACTUAL=$(docker run --rm --entrypoint bash "$IMAGE" \
    -c "dpkg -l | grep '^ii' | awk '{print \$2\"=\"\$3}' | sort")

EXPECTED=$(sort "$PKG_FILE")

if [ "$ACTUAL" = "$EXPECTED" ]; then
    echo "OK: packages in $IMAGE match $PKG_FILE"
    exit 0
fi

echo "ERROR: packages in $IMAGE differ from $PKG_FILE" >&2
echo "" >&2
diff --unified <(echo "$EXPECTED") <(echo "$ACTUAL") >&2 || true
echo "" >&2
echo "Regenerate pinned packages by running the service's build-image.sh" >&2
exit 1
