#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# DHCP lease notification script for dnsmasq.
#
# Called by dnsmasq via --dhcp-script on lease events.
# Notifies dstack-vmm of the guest's MAC and IP so that port
# forwarding can be established automatically.
#
# Arguments (set by dnsmasq):
#   $1  action   add | del | old
#   $2  mac      MAC address of the guest NIC
#   $3  ip       IPv4 address assigned by DHCP
#   $4  hostname (optional)
#
# Configuration:
#   VMM_URL  Base URL of dstack-vmm (default: http://127.0.0.1:9080)

ACTION="$1"
MAC="$2"
IP="$3"

VMM_URL="${VMM_URL:-http://127.0.0.1:9080}"

logger -t dhcp-notify "action=$ACTION mac=$MAC ip=$IP"

case "$ACTION" in
    add|old)
        curl -s -X POST "${VMM_URL}/prpc/ReportDhcpLease" \
            -H 'Content-Type: application/json' \
            -d "{\"mac\":\"$MAC\",\"ip\":\"$IP\"}" \
            || logger -t dhcp-notify "failed to notify VMM"
        ;;
    del)
        # Could clear forwarding on lease expiry; not implemented yet.
        ;;
esac
