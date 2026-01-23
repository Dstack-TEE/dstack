#!/bin/sh

# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

HANDSHAKE_TIMEOUT=180
REFRESH_INTERVAL=180
LAST_REFRESH=0
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
    STALE_SINCE=0
}

check_and_refresh() {
    if ! command -v wg >/dev/null 2>&1; then
        return
    fi

    now=$(date +%s)

    # Periodic refresh every REFRESH_INTERVAL seconds (not forced)
    if [ "$LAST_REFRESH" -eq 0 ] || [ $((now - LAST_REFRESH)) -ge $REFRESH_INTERVAL ]; then
        do_refresh "$now" "Periodic refresh" 0
        return
    fi

    # Check handshake staleness (forced refresh)
    latest=$(get_latest_handshake)
    if [ -z "$latest" ]; then
        latest=0
    fi

    if [ "$latest" -gt 0 ]; then
        if [ $((now - latest)) -ge $HANDSHAKE_TIMEOUT ]; then
            do_refresh "$now" "WireGuard handshake stale" 1 >&2
        fi
    else
        if [ "$STALE_SINCE" -eq 0 ]; then
            STALE_SINCE=$now
        fi
        if [ $((now - STALE_SINCE)) -ge $HANDSHAKE_TIMEOUT ]; then
            do_refresh "$now" "WireGuard handshake stale" 1 >&2
        fi
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
