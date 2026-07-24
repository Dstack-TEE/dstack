#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SKELETON="$SELF/mkosi.skeleton"
TREE=${1:?rootfs tree required}

# Git tracks regular files as either non-executable or executable, but a
# shared checkout can add group-write bits. mkosi correctly preserves source
# modes, so canonicalize only those two Git-representable classes after the
# native SkeletonTrees= copy.
while IFS= read -r -d '' source; do
    relative=${source#"$SKELETON/"}
    destination="$TREE/$relative"
    [[ -e $destination ]] || {
        echo "skeleton path missing from rootfs: $relative" >&2
        exit 1
    }
    if [[ -x $source ]]; then
        chmod 0755 "$destination"
    else
        chmod 0644 "$destination"
    fi
done < <(find "$SKELETON" -type f ! -name .dstack-keep -print0)

while IFS= read -r -d '' directory; do
    relative=${directory#"$SKELETON"}
    chmod 0755 "$TREE$relative"
done < <(find "$SKELETON" -type d -print0)
