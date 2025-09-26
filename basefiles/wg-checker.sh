#!/bin/sh

# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

HANDSHAKE_TIMEOUT=180
LAST_REFRESH=0
STALE_SINCE=0
DSTACK_WORK_DIR=${DSTACK_WORK_DIR:-/dstack}
IFNAME=dstack-wg0

get_latest_handshake() {
    wg show $IFNAME latest-handshakes 2>/dev/null | awk 'BEGIN { max = 0 } NF >= 2 { if ($2 > max) max = $2 } END { print max }'
}

maybe_refresh() {
    now=$1

    if [ "$LAST_REFRESH" -ne 0 ] && [ $((now - LAST_REFRESH)) -lt $HANDSHAKE_TIMEOUT ]; then
        return
    fi

    if ! command -v dstack-util >/dev/null 2>&1; then
        printf 'dstack-util not found; cannot refresh gateway.\n' >&2
        LAST_REFRESH=$now
        return
    fi

    printf 'WireGuard handshake stale; refreshing dstack gateway...\n'
    if dstack-util gateway-refresh --work-dir "$DSTACK_WORK_DIR"; then
        printf 'dstack gateway refresh succeeded.\n'
    else
        printf 'dstack gateway refresh failed.\n' >&2
    fi

    LAST_REFRESH=$now
    STALE_SINCE=$now
}

check_handshake() {
    if ! command -v wg >/dev/null 2>&1; then
        return
    fi

    now=$(date +%s)
    latest=$(get_latest_handshake)

    if [ -z "$latest" ]; then
        latest=0
    fi

    if [ "$latest" -gt 0 ]; then
        if [ $((now - latest)) -ge $HANDSHAKE_TIMEOUT ]; then
            maybe_refresh "$now"
        else
            STALE_SINCE=0
        fi
    else
        if [ "$STALE_SINCE" -eq 0 ]; then
            STALE_SINCE=$now
        fi
        if [ $((now - STALE_SINCE)) -ge $HANDSHAKE_TIMEOUT ]; then
            maybe_refresh "$now"
        fi
    fi
}

while true; do
    if [ -f /etc/wireguard/$IFNAME.conf ]; then
        check_handshake
    else
        STALE_SINCE=0
    fi
    sleep 10
done
