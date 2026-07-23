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
echo 'component merge tests passed'
