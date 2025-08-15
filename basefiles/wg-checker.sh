#!/bin/sh

# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

get_conf_endpoint() {
    grep "Endpoint" /etc/wireguard/wg0.conf | awk "{print \$3}"
}

get_current_endpoint() {
    wg show wg0 endpoints | awk "{print \$2}"
}

check_endpoint() {
    CONF_ENDPOINT=$(get_conf_endpoint)
    CURRENT_ENDPOINT=$(get_current_endpoint)

    if [ "$CURRENT_ENDPOINT" != "$CONF_ENDPOINT" ]; then
        echo "Wg endpoint changed from $CONF_ENDPOINT to $CURRENT_ENDPOINT."
        wg syncconf wg0 <(wg-quick strip wg0)
    fi
}

while true; do
    if [ -f /etc/wireguard/wg0.conf ]; then
        check_endpoint
    fi
    sleep 10
done
