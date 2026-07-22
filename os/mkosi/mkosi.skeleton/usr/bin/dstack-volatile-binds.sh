#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

for name in cache lib log spool tmp; do
    source=/var/volatile/$name
    target=/var/$name
    mkdir -p "$source" "$target"
    mountpoint -q "$target" || mount --bind "$source" "$target"
done
