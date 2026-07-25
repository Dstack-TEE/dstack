#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TREE=${1:?rootfs tree required}
FLAVOR=${2:-}

# Git tracks regular files as either non-executable or executable, but a
# shared checkout can add group-write bits. mkosi correctly preserves source
# modes, so canonicalize only those two Git-representable classes after the
# native SkeletonTrees= copy.
skeletons=("$SELF/mkosi.skeleton")
if [[ -n $FLAVOR && -d $SELF/mkosi.profiles/$FLAVOR/mkosi.skeleton ]]; then
    skeletons+=("$SELF/mkosi.profiles/$FLAVOR/mkosi.skeleton")
fi

for skeleton in "${skeletons[@]}"; do
    while IFS= read -r -d '' source; do
        relative=${source#"$skeleton/"}
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
    done < <(find "$skeleton" -type f ! -name .dstack-keep -print0)

    # -mindepth 1 keeps the skeleton root itself out of the loop; without it
    # the empty relative path would chmod the rootfs root as a side effect.
    while IFS= read -r -d '' directory; do
        relative=${directory#"$skeleton"}
        destination="$TREE$relative"
        [[ -d $destination ]] || {
            echo "skeleton directory missing from rootfs: ${relative#/}" >&2
            exit 1
        }
        chmod 0755 "$destination"
    done < <(find "$skeleton" -mindepth 1 -type d -print0)
done
