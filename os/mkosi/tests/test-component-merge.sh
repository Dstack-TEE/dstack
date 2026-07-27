#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
D=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/a/usr/bin" "$tmp/b/usr/lib" "$tmp/c/usr/bin"
printf a > "$tmp/a/usr/bin/a"
printf b > "$tmp/b/usr/lib/b"
printf conflict > "$tmp/c/usr/bin/a"
"$D/scripts/merge-component-trees.py" "$tmp/root" \
  "a=$tmp/a" "b=$tmp/b"
[[ $(cat "$tmp/root/usr/bin/a") == a ]]
[[ $(cat "$tmp/root/usr/lib/b") == b ]]

if "$D/scripts/merge-component-trees.py" "$tmp/root" "c=$tmp/c" \
   >"$tmp/conflict.log" 2>&1; then
    echo 'component conflict was not rejected' >&2
    exit 1
fi
grep -q 'component install conflict: c:' "$tmp/conflict.log"

# A component that installs a symlink to a directory must not turn into a
# mergeable directory for the next component: following it would write the
# payload outside the staging root and drop those files from the image.
mkdir -p "$tmp/d/usr" "$tmp/e/usr/lib/pkg" "$tmp/escape"
ln -s "$tmp/escape" "$tmp/d/usr/lib"
printf payload > "$tmp/e/usr/lib/pkg/file"
"$D/scripts/merge-component-trees.py" "$tmp/root2" "d=$tmp/d"
[[ -L $tmp/root2/usr/lib ]]
if "$D/scripts/merge-component-trees.py" "$tmp/root2" "e=$tmp/e" \
   >"$tmp/escape.log" 2>&1; then
    echo 'symlinked directory was not rejected' >&2
    exit 1
fi
grep -q 'component install conflict: e:' "$tmp/escape.log"
if [[ -e $tmp/escape/pkg ]]; then
    echo 'component payload escaped the staging root' >&2
    exit 1
fi

# Directory modes must survive the merge; a private state directory that
# silently widens to 0755 would ship world-traversable in the guest rootfs.
mkdir -p "$tmp/f/etc/secret"
chmod 0700 "$tmp/f/etc/secret"
printf k > "$tmp/f/etc/secret/key"
"$D/scripts/merge-component-trees.py" "$tmp/root3" "f=$tmp/f"
mode=$(stat -c %a "$tmp/root3/etc/secret")
[[ $mode == 700 ]] || { echo "directory mode not preserved: $mode" >&2; exit 1; }

# Unsupported entry types must be rejected rather than silently skipped.
mkdir -p "$tmp/g/usr/bin"
mkfifo "$tmp/g/usr/bin/fifo"
if "$D/scripts/merge-component-trees.py" "$tmp/root4" "g=$tmp/g" \
   >"$tmp/fifo.log" 2>&1; then
    echo 'unsupported entry type was not rejected' >&2
    exit 1
fi
grep -q 'unsupported install entry' "$tmp/fifo.log"

echo 'component merge tests passed'
