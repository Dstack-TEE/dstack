#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Assert that a built kernel .config actually contains what a dstack kconfig
# fragment asked for. Kconfig silently drops a request whose dependencies are
# not met and silently clamps a tristate to the value of what it depends on, so
# a fragment line is a wish, not a guarantee: os/yocto's dstack-docker.cfg
# carried four such lines for a long time -- CONFIG_BRIDGE_NF_EBTABLES=y under
# CONFIG_BRIDGE=m, two xtables matches clamped to =m and a symbol deleted
# upstream -- and the builds kept succeeding. CONFIG_SECURITY_SELINUX=y on a
# tree with CONFIG_SECURITY=n was a fifth, fixed separately by the SELinux
# parity work. Both OS backends run this so neither can drift again.
#
# Usage: check-kernel-config.sh <built .config> [fragment ...]
set -euo pipefail
config=${1:?kernel .config required}
shift
if [[ $# -eq 0 ]]; then
    printf 'at least one kernel fragment required\n' >&2
    exit 1
fi
failed=0
# A fragment that was truncated, moved or emptied would otherwise pass by
# asserting nothing. The floor is per fragment rather than a total, so it stays
# meaningful no matter how many fragments a backend passes: the smallest one
# checked today (dstack-docker.cfg) carries 77 assertions.
MIN_ASSERTIONS_PER_FRAGMENT=10
for fragment in "$@"; do
    [[ -r "$fragment" ]] || { printf 'unreadable kernel fragment: %s\n' "$fragment" >&2; exit 1; }
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
        printf 'kernel config mismatch in %s: wanted %s, got %s\n' \
          "$fragment" "$line" "$(grep -m1 "^$key=" "$config" || echo "$key unset")" >&2
        failed=1
    done < "$fragment"
    if [[ $checked -lt $MIN_ASSERTIONS_PER_FRAGMENT ]]; then
        printf '%s yielded only %d assertions; refusing to proceed\n' \
          "$fragment" "$checked" >&2
        failed=1
    fi
done
exit "$failed"
