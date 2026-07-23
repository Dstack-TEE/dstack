#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
config=${1:?kernel .config required}
fragment=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/components/kernel/kernel.config
failed=0
while IFS= read -r line; do
    [[ $line =~ ^CONFIG_[A-Z0-9_]+=(y|m|n)$ ]] || continue
    key=${line%%=*}; want=${line#*=}
    if [[ $want == n ]]; then
        grep -qx "# $key is not set" "$config" && continue
    elif grep -qx "$key=$want" "$config" || { [[ $want == m ]] && grep -qx "$key=y" "$config"; }; then
        continue
    fi
    printf 'kernel config mismatch: wanted %s\n' "$line" >&2
    failed=1
done < "$fragment"
exit "$failed"
