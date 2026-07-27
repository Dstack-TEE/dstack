#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
config=${1:?kernel .config required}
fragment=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/components/kernel/kernel.config
failed=0
checked=0
while IFS= read -r line; do
    # Skip comments and blank lines, but nothing else: every remaining line is
    # an assertion. Only matching tristates here silently ignored the string
    # and integer settings, so a dropped CONFIG_LOCALVERSION (which names the
    # module directory the rest of the build looks for) or a clamped
    # CONFIG_NR_CPUS passed the gate and failed much later, or shipped.
    [[ -n ${line// /} ]] || continue
    [[ $line == \#* ]] && continue
    if [[ ! $line =~ ^CONFIG_[A-Za-z0-9_]+= ]]; then
        printf 'unparsable kernel fragment line: %s\n' "$line" >&2
        failed=1
        continue
    fi
    key=${line%%=*}; want=${line#*=}
    checked=$((checked + 1))
    if [[ $want == n ]]; then
        # A symbol whose dependencies went away disappears entirely rather
        # than being recorded as unset; both mean "not enabled".
        grep -qx "# $key is not set" "$config" && continue
        grep -q "^$key=" "$config" || continue
    elif grep -qx "$key=$want" "$config"; then
        continue
    elif [[ $want == m ]] && grep -qx "$key=y" "$config"; then
        continue
    fi
    printf 'kernel config mismatch: wanted %s, got %s\n' \
      "$line" "$(grep -m1 "^$key=" "$config" || echo "$key unset")" >&2
    failed=1
done < "$fragment"
if [[ $checked -lt 100 ]]; then
    printf 'kernel fragment yielded only %d assertions; refusing to proceed\n' \
      "$checked" >&2
    failed=1
fi
exit "$failed"
