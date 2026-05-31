#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# dstack currently runs the CVMs with qemu user networking. To prevent the VM to access 127.0.0.1, we need to
# run the VM as a different user and setup the iptables rules to DROP the traffic to 127.0.0.1.

# This script creates a sandbox user for running VMs with restricted network access.
# It sets up iptables rules to prevent the user from accessing localhost (127.0.0.1),
# with optional exceptions for specific ports.
#
# When deploying a new dstack instance, you can follow the following steps:
# 1. Create a new sandbox user and setup the firewall rules:
#    ```
#    sudo ./setup-user.sh dstack-prd1 -g $(id -gn)
#    ```
#
#    If you want allow the VM to access some ports such as local KMS or dstack-gateway, you can use the following command:
#    ```
#    sudo ./setup-user.sh dstack-prd1 -g $(id -gn) --allow-tcp 8080 --allow-udp 3000
#    ```
# 2. Edit the user in the `[cvm]` section of the vmm.yaml file:
#    ```
#    [cvm]
#    user = "dstack-prd1"
#    ```
#
set -e

# Default values
USERNAME=""
GROUP_NAME=""
NO_FW=false
NO_SERVICE=false
ALLOWED_TCP_PORTS=""
ALLOWED_UDP_PORTS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
    --no-fw)
        NO_FW=true
        shift
        ;;
    --no-svc)
        NO_SERVICE=true
        shift
        ;;
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
    -g | --group)
        GROUP_NAME="$2"
        shift
        shift
        ;;
    -h | --help)
        echo "Usage: $0 <username> [-g|--group] [--no-fw] [--no-svc] [--allow-tcp <port> --allow-udp <port>]"
        echo "Options:"
        echo "  --no-fw     Do not setup/clear firewall rules"
        echo "  --no-svc    Do not setup/clear service rules"
        echo "  --allow-tcp Allow the specified TCP port to be accessed"
        echo "  --allow-udp Allow the specified UDP port to be accessed"
        echo "  -g, --group Add the user to the specified group"
        echo "  -h, --help  Show this help message"
        exit 0
        ;;
    *)
        if [[ -z "$USERNAME" ]]; then
            USERNAME="$1"
        else
            echo "Error: Unknown argument '$1'"
            echo "Use '$0 --help' for usage information"
            exit 1
        fi
        shift
        ;;
    esac
done

# Check if username is provided
if [[ -z "$USERNAME" ]]; then
    echo "Error: Username is required"
    echo "Usage: $0 <username> [-g|--group] [--no-fw] [--no-svc] [--allow-tcp <port> --allow-udp <port>]"
    exit 1
fi

CHAIN_NAME="DSTACK_SANDBOX_${USERNAME}"
RULES_FILE="/etc/iptables/dstack-rules-${USERNAME}.v4"

# Create the user if it doesn't exist
if ! id -u $USERNAME >/dev/null 2>&1; then
    echo "Creating user $USERNAME"
    adduser --disabled-password --gecos '' $USERNAME
fi

usermod -aG kvm $USERNAME

# Add the user to specified group
if [ -n "$GROUP_NAME" ]; then
    echo "Adding user $USERNAME to group $GROUP_NAME"
    usermod -aG $GROUP_NAME $USERNAME
fi

rule_nums=$(iptables -L OUTPUT --line-numbers | grep $CHAIN_NAME | awk '{print $1}' | sort -r)
echo $rule_nums

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

rm -f $RULES_FILE

if [ "$NO_SERVICE" = true ]; then
    echo "Removing existing systemd service"
    rm -f /etc/systemd/system/iptables-restore.service
    rm -f /etc/iptables/dstack-rules-${USERNAME}.v4
    systemctl disable iptables-restore.service || true
    systemctl daemon-reload
    echo "Removed systemd service and rules file"
fi

if [ "$NO_FW" = true ]; then
    echo "Skipping firewall rules setup"
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
    iptables -A $CHAIN_NAME -p tcp --dport $port -j ACCEPT
    iptables -A $CHAIN_NAME -p tcp --sport $port -j ACCEPT
done
for port in $ALLOWED_UDP_PORTS; do
    echo "Adding exception for UDP port $port"
    iptables -A $CHAIN_NAME -p udp --dport $port -j ACCEPT
    iptables -A $CHAIN_NAME -p udp --sport $port -j ACCEPT
done

# Add final DROP rule for all other traffic to localhost
iptables -A $CHAIN_NAME -p udp -j DROP
iptables -A $CHAIN_NAME -p tcp -m tcp --syn -j DROP


# Ensure our chain is referenced from the OUTPUT chain
if ! iptables -C OUTPUT -o lo -m owner --uid-owner $USERNAME -j $CHAIN_NAME 2>/dev/null; then
    iptables -I OUTPUT -o lo -d 127.0.0.1 -m owner --uid-owner $USERNAME -j $CHAIN_NAME
fi

if [ "$NO_SERVICE" = true ]; then
    echo "Skipping service rules setup"
    exit 0
fi

# Make iptables rules persistent
if command -v iptables-save >/dev/null 2>&1; then
    echo "Saving iptables rules to make them persistent"

    if [ -d "/etc/iptables" ]; then
        # Debian/Ubuntu style
        iptables-save >$RULES_FILE
        echo "Rules saved to $RULES_FILE"
    else
        # Fallback method
        mkdir -p /etc/iptables
        iptables-save >$RULES_FILE

        # Create a systemd service to load rules at boot if it doesn't exist
        if [ ! -f "/etc/systemd/system/iptables-restore.service" ]; then
            cat >/etc/systemd/system/iptables-restore.service <<EOF
[Unit]
Description=Restore iptables firewall rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'for f in /etc/iptables/*.v4; do /sbin/iptables-restore "$f"; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable iptables-restore.service
            echo "Created and enabled iptables-restore.service"
        fi

        echo "Rules saved to $RULES_FILE"
    fi
else
    echo "Warning: iptables-save not found. Rules will not persist after reboot."
    echo "Please install iptables-persistent package or equivalent for your distribution."
fi

echo "Setup completed for user $USERNAME"
