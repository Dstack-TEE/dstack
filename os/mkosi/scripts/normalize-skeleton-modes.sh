#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SKELETON=os/mkosi/mkosi.skeleton
TREE=${1:?rootfs tree required}

# Git stores only 0644/0755 for regular files, while checkout applies the host
# umask. Restore the canonical index modes after mkosi copies the skeleton.
while IFS=$'\t' read -r metadata path; do
    mode=${metadata%% *}
    relative=${path#"$SKELETON/"}
    destination=$TREE/$relative
    [[ -e $destination || -L $destination ]] || {
        echo "skeleton path missing from rootfs: $relative" >&2
        exit 1
    }
    case $mode in
        100644) chmod 0644 "$destination" ;;
        100755) chmod 0755 "$destination" ;;
        120000) ;;
        *) echo "unsupported Git mode $mode for $path" >&2; exit 1 ;;
    esac
done < <(git -C "$ROOT" ls-files --stage -- "$SKELETON")

# Git does not store directories; git-archive materializes them as 0755.
while IFS= read -r -d '' directory; do
    relative=${directory#"$ROOT/$SKELETON"/}
    [[ $relative == "$directory" ]] && relative=
    chmod 0755 "$TREE${relative:+/$relative}"
done < <(find "$ROOT/$SKELETON" -type d -print0)
