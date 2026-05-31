#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

set -e

# dstack runs Confidential VMs (CVMs) with QEMU user networking. To prevent VMs from accessing 127.0.0.1,
# we run the VM as a different user and set up iptables rules to DROP traffic to 127.0.0.1.
#
# # How to Use
# This script can be used in a systemd service to set up firewall rules before starting VMs.
# Example systemd service configuration:
# ```
# [Unit]
# Description=dstack Firewall Configuration
# Before=dstack-vmm.service
#
# [Service]
# Type=oneshot
# ExecStart=/path/to/config-fw.sh -u dstack-vmm
# RemainAfterExit=yes
#
# [Install]
# WantedBy=multi-user.target
# ```
#
# # Note
# The dstack supervisor must be run with a dedicated user specified by USERNAME in this script.
# For example, if dstack-gateway is running on the same host, it must use a different user account than USERNAME.
# To allow specific local ports to be accessed by CVMs, add --allow-tcp and --allow-udp.
# For example, if dstack-gateway is running on local host and listening RPC on port 9001, wg on port 9182:
# ```
# ./config-fw.sh -u dstack-vmm --allow-tcp 9001 --allow-udp 9182
# ```
# If the KMS is also running on the same host and listening on port 9002:
# ```
# ./config-fw.sh -u dstack-vmm --allow-tcp 9001 --allow-udp 9182 --allow-tcp 9002
# ```


# Default values
USERNAME=${USERNAME:-""}
ALLOWED_TCP_PORTS=${ALLOWED_TCP_PORTS:-""}
ALLOWED_UDP_PORTS=${ALLOWED_UDP_PORTS:-""}
CLEAR=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
    --allow-tcp)
        ALLOWED_TCP_PORTS="$ALLOWED_TCP_PORTS $2"
        shift
        shift
        ;;
    --allow-udp)
        ALLOWED_UDP_PORTS="$ALLOWED_UDP_PORTS $2"
        shift
        shift
        ;;
    -u | --user)
        USERNAME="$2"
        shift
        shift
        ;;
    -c | --clear)
        CLEAR=true
        shift
        ;;
    -h | --help)
        echo "Usage: $0 [--allow-tcp <port> --allow-udp <port>] -u <username>"
        echo "Options:"
        echo "  -u, --user <username> The user to setup the firewall rules for"
        echo "  --allow-tcp <port> Allow the specified TCP port to be accessed"
        echo "  --allow-udp <port> Allow the specified UDP port to be accessed"
        echo "  -h, --help  Show this help message"
        exit 0
        ;;
    *)
        echo "Error: Unknown argument '$1'"
        echo "Use '$0 --help' for usage information"
        exit 1
        ;;
    esac
done

if [ -z "$USERNAME" ]; then
    echo "Error: Username is required"
    echo "Usage: $0 [--allow-tcp <port> --allow-udp <port>] -u <username>"
    exit 1
fi

CHAIN_NAME="DSTACK_SANDBOX_${USERNAME}"

rule_nums=$(iptables -L OUTPUT --line-numbers | grep $CHAIN_NAME | awk '{print $1}' | sort -r)

if iptables -L $CHAIN_NAME >/dev/null 2>&1; then
    echo "Removing existing firewall rules"
    # Delete each rule (in reverse order to avoid index shifting)
    if [ -n "$rule_nums" ]; then
        echo "Removing rules jumping to $CHAIN_NAME from OUTPUT chain"
        for num in $rule_nums; do
            echo "Removing rule $num"
            iptables -D OUTPUT $num
        done
        echo "All rules jumping to $CHAIN_NAME removed"
    else
        echo "No rules jumping to $CHAIN_NAME found in OUTPUT chain"
    fi
    iptables -F $CHAIN_NAME 2>/dev/null || true
    iptables -X $CHAIN_NAME 2>/dev/null || true
    echo "Removed iptables chain $CHAIN_NAME"
fi

if [ "$CLEAR" = true ]; then
    echo "Cleared firewall rules for user $USERNAME"
    exit 0
fi

# Set up firewall rules
# Use iptables with a dedicated chain
echo "Setting up iptables firewall rules with custom chain"

# Create or flush the custom chain
if ! iptables -L $CHAIN_NAME >/dev/null 2>&1; then
    iptables -N $CHAIN_NAME
else
    iptables -F $CHAIN_NAME
fi

# Add rules to allow specific ports
for port in $ALLOWED_TCP_PORTS; do
    echo "Adding exception for TCP port $port"
    iptables -A $CHAIN_NAME -p tcp -d 127.0.0.1 --dport $port -j ACCEPT
    iptables -A $CHAIN_NAME -p tcp -d 127.0.0.1 --sport $port -j ACCEPT
done
for port in $ALLOWED_UDP_PORTS; do
    echo "Adding exception for UDP port $port"
    iptables -A $CHAIN_NAME -p udp -d 127.0.0.1 --dport $port -j ACCEPT
    iptables -A $CHAIN_NAME -p udp -d 127.0.0.1 --sport $port -j ACCEPT
done

# Add final DROP rule for all other traffic to localhost
iptables -A $CHAIN_NAME -p udp -j DROP
iptables -A $CHAIN_NAME -p tcp -m tcp --syn -j DROP
iptables -A $CHAIN_NAME -p icmp -j DROP

# Ensure our chain is referenced from the OUTPUT chain
if ! iptables -C OUTPUT -o lo -m owner --uid-owner $USERNAME -j $CHAIN_NAME 2>/dev/null; then
    iptables -I OUTPUT -o lo -d 127.0.0.1 -m owner --uid-owner $USERNAME -j $CHAIN_NAME
fi

# Redirect traffic to 10.x.x.x network to our chain
if ! iptables -C OUTPUT -m owner --uid-owner $USERNAME -d 10.0.0.0/8 -j $CHAIN_NAME 2>/dev/null; then
    iptables -I OUTPUT -m owner --uid-owner $USERNAME -d 10.0.0.0/8 -j $CHAIN_NAME
fi

echo "Setup completed for user $USERNAME"
