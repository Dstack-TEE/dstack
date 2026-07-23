#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

TREE=${1:?root tree required}
PROGRAM=${2:?program path required}
shift 2

[[ $PROGRAM == /* ]] || { echo "program path must be absolute" >&2; exit 2; }
[[ -x $TREE$PROGRAM ]] || { echo "program not found in tree: $PROGRAM" >&2; exit 1; }

# Invoke the program with the dynamic loader and libraries from its immutable
# tree. This avoids silently using equivalent-looking host tools with different
# distro patches while requiring neither chroot nor mount privileges.
loader=$(find "$TREE/usr/lib" "$TREE/lib" -type f \
  -name 'ld-linux-x86-64.so.2' -print -quit 2>/dev/null)
[[ -n $loader ]] || { echo "dynamic loader missing from tree" >&2; exit 1; }
library_path="$TREE/usr/lib/x86_64-linux-gnu:$TREE/lib/x86_64-linux-gnu"
exec "$loader" --library-path "$library_path" "$TREE$PROGRAM" "$@"
