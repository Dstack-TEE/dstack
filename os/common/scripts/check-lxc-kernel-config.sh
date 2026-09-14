#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Run LXC's own kernel audit, lxc-checkconfig, against a built .config and
# fail on anything it reports missing. check-kernel-config.sh asserts what
# dstack's fragments ask for; this asserts what the container stack asks for,
# from the list its maintainers keep, so a symbol dstack never thought to
# request (CONFIG_CHECKPOINT_RESTORE was one, #1180) fails the build instead
# of reaching a tenant. lxc-checkconfig knows nothing about traffic control or
# anything else Incus needs beyond LXC, so the fragments still carry those.
#
# Usage: check-lxc-kernel-config.sh <built .config>
set -euo pipefail
config=${1:?kernel .config required}
[[ -r $config ]] || { printf 'unreadable kernel config: %s\n' "$config" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Backwards-compat aliases that only `select NETFILTER_XT_TARGET_MASQUERADE`,
# the module every frontend has used since 5.2 and which both kernels build.
# The IPv6 one is also unreachable on the mkosi kernel: it depends on
# IP6_NF_NAT, which needs the legacy ip6tables that image does not have (see
# docs/guest-netfilter-capabilities.md).
ignored_symbols=(
    CONFIG_IP_NF_TARGET_MASQUERADE
    CONFIG_IP6_NF_TARGET_MASQUERADE
)
# lxc-checkconfig also probes the machine it runs on -- cgroup mounts,
# /proc/self/ns/cgroup, newuidmap -- which says nothing about the kernel being
# built. Only its "<label>: enabled|missing|required" lines are read, and the
# host-state labels among them are skipped.
ignored_labels=("Cgroup namespace" "Cgroup v1 *")

# Stdout is not a terminal inside $(...), so the output carries no colour codes.
if ! output=$(CONFIG="$config" sh "$here/lxc-checkconfig" </dev/null 2>&1); then
    printf 'lxc-checkconfig failed to run:\n%s\n' "$output" >&2
    exit 1
fi

failed=0
enabled=0
while IFS= read -r line; do
    [[ $line == *": "* ]] || continue
    label=${line%%: *}
    status=${line#*: }
    status=${status%%,*}
    case $status in
        enabled) enabled=$((enabled + 1)); continue ;;
        missing | required) ;;
        *) continue ;;
    esac
    for ignored in "${ignored_labels[@]}"; do
        # shellcheck disable=SC2053
        [[ $label == $ignored ]] && continue 2
    done
    for ignored in "${ignored_symbols[@]}"; do
        [[ $label == "$ignored" ]] && continue 2
    done
    printf 'lxc-checkconfig: %s\n' "$line" >&2
    failed=1
done <<< "$output"

# lxc-checkconfig reports about thirty symbols on a 6.x kernel. A run that
# checked nothing -- a config it could not parse, a copy of the script that
# lost its checks -- would otherwise pass vacuously.
MIN_ENABLED=20
if (( enabled < MIN_ENABLED )); then
    printf 'lxc-checkconfig reported only %d enabled symbols; refusing to proceed\n' \
      "$enabled" >&2
    failed=1
fi
exit "$failed"
