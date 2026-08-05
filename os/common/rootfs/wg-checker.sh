#!/bin/sh

# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

HANDSHAKE_TIMEOUT=180
REFRESH_INTERVAL=180
LAST_REFRESH=0
LAST_FORCE=0
STALE_SINCE=0
DSTACK_WORK_DIR=${DSTACK_WORK_DIR:-/dstack}
IFNAME=dstack-wg0

get_latest_handshake() {
    wg show $IFNAME latest-handshakes 2>/dev/null | awk 'BEGIN { max = 0 } NF >= 2 { if ($2 > max) max = $2 } END { print max }'
}

do_refresh() {
    now=$1
    reason=$2
    force=$3

    if ! command -v dstack-util >/dev/null 2>&1; then
        printf 'dstack-util not found; cannot refresh gateway.\n' >&2
        LAST_REFRESH=$now
        return
    fi

    printf '%s; refreshing dstack gateway...\n' "$reason"
    if [ "$force" = "1" ]; then
        cmd="dstack-util gateway-refresh --work-dir $DSTACK_WORK_DIR --force"
    else
        cmd="dstack-util gateway-refresh --work-dir $DSTACK_WORK_DIR"
    fi
    if $cmd; then
        printf 'dstack gateway refresh succeeded.\n'
    else
        printf 'dstack gateway refresh failed.\n' >&2
    fi

    LAST_REFRESH=$now
}

check_and_refresh() {
    if ! command -v wg >/dev/null 2>&1; then
        return
    fi

    now=$(date +%s)

    latest=$(get_latest_handshake)
    if [ -z "$latest" ]; then
        latest=0
    fi

    # A peer that never completed a handshake reports 0, so there is no
    # timestamp to age against; fall back to when we first observed that state.
    # STALE_SINCE is cleared only by an actual handshake, never by a refresh:
    # since HANDSHAKE_TIMEOUT equals REFRESH_INTERVAL, clearing it on every
    # periodic refresh re-arms the timer one tick before it can expire, leaving
    # the forced branch unreachable for a peer that never handshakes.
    if [ "$latest" -gt 0 ]; then
        STALE_SINCE=0
        stale_for=$((now - latest))
    else
        if [ "$STALE_SINCE" -eq 0 ]; then
            STALE_SINCE=$now
        fi
        stale_for=$((now - STALE_SINCE))
    fi

    # Forced refresh bounces the interface and re-requests certificates, so cap
    # it at one attempt per HANDSHAKE_TIMEOUT. Without this, a gateway that
    # stays unreachable would be retried on every 10s tick.
    if [ "$stale_for" -ge $HANDSHAKE_TIMEOUT ]; then
        if [ $((now - LAST_FORCE)) -ge $HANDSHAKE_TIMEOUT ]; then
            do_refresh "$now" "WireGuard handshake stale" 1 >&2
            LAST_FORCE=$now
        fi
        return
    fi

    # Periodic refresh every REFRESH_INTERVAL seconds (not forced).
    if [ "$LAST_REFRESH" -eq 0 ] || [ $((now - LAST_REFRESH)) -ge $REFRESH_INTERVAL ]; then
        do_refresh "$now" "Periodic refresh" 0
    fi
}

while true; do
    if [ -f /etc/wireguard/$IFNAME.conf ]; then
        check_and_refresh
    else
        STALE_SINCE=0
    fi
    sleep 10
done
