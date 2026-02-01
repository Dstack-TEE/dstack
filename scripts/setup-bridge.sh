#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Bridge networking setup and diagnostics for dstack-vmm.
#
# Setup modes:
#   libvirt      Use libvirt default network (virbr0, dnsmasq, NAT included)
#   standalone   Create bridge + dnsmasq + NAT without libvirt
#
# Usage:
#   setup-bridge.sh check    [--bridge NAME]
#   setup-bridge.sh setup    --mode libvirt    [--bridge virbr0]
#   setup-bridge.sh setup    --mode standalone [--bridge dstack-br0]
#   setup-bridge.sh destroy  [--bridge NAME]

set -euo pipefail

BRIDGE="virbr0"
SETUP_MODE=""  # libvirt | standalone
DRY_RUN=false
COMMAND=""
PASS=0
FAIL=0
WARN=0

# --- Output helpers ---

red()    { printf '\033[31m%s\033[0m' "$*"; }
green()  { printf '\033[32m%s\033[0m' "$*"; }
yellow() { printf '\033[33m%s\033[0m' "$*"; }
bold()   { printf '\033[1m%s\033[0m' "$*"; }

check_pass() { PASS=$((PASS+1)); echo "  $(green '[PASS]') $*"; }
check_fail() { FAIL=$((FAIL+1)); echo "  $(red '[FAIL]') $*"; }
check_warn() { WARN=$((WARN+1)); echo "  $(yellow '[WARN]') $*"; }
check_info() { echo "  [INFO] $*"; }

run_cmd() {
    if $DRY_RUN; then
        echo "  [DRY-RUN] $*"
    else
        "$@"
    fi
}

# --- Detect qemu-bridge-helper path ---

find_bridge_helper() {
    local paths=(
        /usr/lib/qemu/qemu-bridge-helper
        /usr/libexec/qemu-bridge-helper
        /usr/local/lib/qemu/qemu-bridge-helper
        /usr/local/libexec/qemu-bridge-helper
    )
    for p in "${paths[@]}"; do
        if [[ -f "$p" ]]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

# --- Detect current bridge provider ---

# Returns "libvirt:<net_name>" if bridge is managed by a libvirt network,
# "standalone" otherwise.
detect_bridge_provider() {
    if command -v virsh &>/dev/null; then
        local name br
        while read -r name; do
            [[ -z "$name" ]] && continue
            br=$(virsh net-dumpxml "$name" 2>/dev/null | grep -oP "<bridge name='\K[^']*" | head -1 || true)
            if [[ "$br" == "$BRIDGE" ]]; then
                echo "libvirt:$name"
                return 0
            fi
        done < <(virsh net-list --all --name 2>/dev/null)
    fi
    echo "standalone"
}

# --- Check functions ---

check_bridge_helper() {
    echo
    bold "qemu-bridge-helper"
    local helper
    if ! helper=$(find_bridge_helper); then
        check_fail "qemu-bridge-helper not found"
        check_info "Install QEMU: sudo apt install qemu-system-x86"
        return
    fi
    check_pass "found at $helper"

    if [[ -u "$helper" ]]; then
        check_pass "setuid bit is set"
    else
        check_fail "setuid bit not set"
        check_info "Fix: sudo chmod u+s $helper"
    fi
}

check_bridge_conf() {
    echo
    bold "/etc/qemu/bridge.conf"
    local conf="/etc/qemu/bridge.conf"
    if [[ ! -f "$conf" ]]; then
        check_fail "$conf does not exist"
        check_info "Fix: sudo mkdir -p /etc/qemu && echo 'allow $BRIDGE' | sudo tee $conf"
        return
    fi
    check_pass "$conf exists"

    if grep -qE "^allow[[:space:]]+($BRIDGE|all)[[:space:]]*$" "$conf" 2>/dev/null; then
        check_pass "bridge '$BRIDGE' is allowed"
    else
        check_fail "bridge '$BRIDGE' not found in $conf"
        check_info "Fix: echo 'allow $BRIDGE' | sudo tee -a $conf"
    fi
}

check_bridge_interface() {
    echo
    bold "bridge interface: $BRIDGE"
    if ! ip link show "$BRIDGE" &>/dev/null; then
        check_fail "bridge '$BRIDGE' does not exist"
        check_info "Run: $(basename "$0") setup --mode libvirt"
        check_info " or: $(basename "$0") setup --mode standalone --bridge $BRIDGE"
        return
    fi

    local state
    state=$(ip -j link show "$BRIDGE" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)[0].get('operstate',''))" 2>/dev/null || echo "UNKNOWN")
    if [[ "$state" == "UP" ]]; then
        check_pass "interface is UP"
    else
        check_warn "interface state: $state (expected UP)"
    fi

    local addr
    addr=$(ip -4 -o addr show "$BRIDGE" 2>/dev/null | awk '{print $4}' | head -1)
    if [[ -n "$addr" ]]; then
        check_pass "has IP address: $addr"
    else
        check_fail "no IPv4 address assigned"
    fi
}

check_dhcp() {
    echo
    bold "DHCP service"

    local provider
    provider=$(detect_bridge_provider)

    if [[ "$provider" == libvirt:* ]]; then
        local net_name="${provider#libvirt:}"
        if virsh net-info "$net_name" 2>/dev/null | grep "Active:.*yes" >/dev/null; then
            check_pass "libvirt network '$net_name' active on $BRIDGE (includes DHCP)"
            return
        else
            check_fail "libvirt network '$net_name' exists but not active"
            check_info "Fix: sudo virsh net-start $net_name"
            return
        fi
    fi

    # Standalone: check dnsmasq
    if pgrep -f "dnsmasq.*$BRIDGE" &>/dev/null; then
        local pid
        pid=$(pgrep -f "dnsmasq.*$BRIDGE" | head -1)
        check_pass "dnsmasq running for $BRIDGE (pid $pid)"
        return
    fi

    if [[ -d /etc/dnsmasq.d ]]; then
        if [[ -f "/etc/dnsmasq.d/dstack-${BRIDGE}.conf" ]] || grep -rl "interface=$BRIDGE" /etc/dnsmasq.d/ &>/dev/null 2>&1; then
            if systemctl is-active dnsmasq &>/dev/null; then
                check_pass "dnsmasq service active with $BRIDGE config"
                return
            else
                check_fail "dnsmasq config exists but service not running"
                check_info "Fix: sudo systemctl start dnsmasq"
                return
            fi
        fi
    fi

    check_fail "no DHCP server found for $BRIDGE"
    check_info "Run: $(basename "$0") setup --mode standalone --bridge $BRIDGE"
}

check_ip_forward() {
    echo
    bold "IP forwarding"
    local val
    val=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
    if [[ "$val" == "1" ]]; then
        check_pass "net.ipv4.ip_forward = 1"
    else
        check_fail "net.ipv4.ip_forward = $val"
        check_info "Fix: sudo sysctl -w net.ipv4.ip_forward=1"
    fi
}

check_nat_rules() {
    echo
    bold "NAT / masquerade rules"

    local subnet
    subnet=$(ip -4 -o addr show "$BRIDGE" 2>/dev/null | awk '{print $4}' | head -1)
    if [[ -z "$subnet" ]]; then
        check_warn "cannot determine subnet (bridge has no IP)"
        return
    fi

    local net_cidr
    net_cidr=$(python3 -c "
import ipaddress
iface = ipaddress.ip_interface('$subnet')
print(iface.network)
" 2>/dev/null || echo "")

    if [[ -z "$net_cidr" ]]; then
        check_warn "cannot parse subnet $subnet"
        return
    fi

    local nft_rules=""
    if command -v nft &>/dev/null; then
        nft_rules=$(sudo nft list ruleset 2>/dev/null || true)
    fi

    if [[ -n "$nft_rules" ]]; then
        if echo "$nft_rules" | grep -q "masquerade" && \
           echo "$nft_rules" | grep -q "${net_cidr%/*}"; then
            check_pass "nftables masquerade rules found for $net_cidr"
            return
        fi
    fi

    if command -v iptables &>/dev/null; then
        if sudo iptables -t nat -L -n 2>/dev/null | grep -i "masquerade" >/dev/null && \
           sudo iptables -t nat -L -n 2>/dev/null | grep "${net_cidr%/*}" >/dev/null; then
            check_pass "iptables masquerade rules found for $net_cidr"
            return
        fi
    fi

    check_fail "no NAT masquerade rules found for $net_cidr"
    check_info "Libvirt adds these automatically."
    check_info "For standalone: systemd-networkd IPMasquerade=both or manual nftables rules."
}

check_forward_rules() {
    echo
    bold "forwarding rules"

    local nft_rules=""
    if command -v nft &>/dev/null; then
        nft_rules=$(sudo nft list ruleset 2>/dev/null || true)
    fi

    if [[ -n "$nft_rules" ]] && echo "$nft_rules" | grep -q "iifname \"$BRIDGE\".*accept"; then
        check_pass "nftables forward accept rule for $BRIDGE"
        return
    fi

    if command -v iptables &>/dev/null; then
        if sudo iptables -L FORWARD -n 2>/dev/null | grep -i "$BRIDGE.*ACCEPT" >/dev/null; then
            check_pass "iptables forward accept rule for $BRIDGE"
            return
        fi
    fi

    local policy
    policy=$(sudo iptables -L FORWARD 2>/dev/null | head -1 | grep -oP '\(policy \K[^)]+' || echo "")
    if [[ "$policy" == "ACCEPT" ]]; then
        check_pass "forward policy is ACCEPT"
        return
    fi

    check_warn "no explicit forward rules found for $BRIDGE (may still work via libvirt chains)"
}

# --- Setup: common ---

setup_bridge_conf() {
    echo
    bold "Setting up /etc/qemu/bridge.conf"
    run_cmd sudo mkdir -p /etc/qemu
    if [[ -f /etc/qemu/bridge.conf ]] && grep -qE "^allow[[:space:]]+($BRIDGE|all)" /etc/qemu/bridge.conf 2>/dev/null; then
        echo "  already configured"
    else
        run_cmd bash -c "echo 'allow $BRIDGE' | sudo tee -a /etc/qemu/bridge.conf"
    fi
}

setup_bridge_helper() {
    echo
    bold "Setting up qemu-bridge-helper"
    local helper
    if ! helper=$(find_bridge_helper); then
        echo "  $(red 'ERROR'): qemu-bridge-helper not found. Install QEMU first."
        return 1
    fi
    if [[ -u "$helper" ]]; then
        echo "  setuid already set on $helper"
    else
        run_cmd sudo chmod u+s "$helper"
        echo "  setuid set on $helper"
    fi
}

setup_ip_forward() {
    echo
    bold "Enabling IP forwarding"
    local val
    val=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
    if [[ "$val" == "1" ]]; then
        echo "  already enabled"
    else
        run_cmd sudo sysctl -w net.ipv4.ip_forward=1
        run_cmd bash -c "echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-dstack-bridge.conf"
    fi
}

# --- Setup: libvirt mode ---

setup_libvirt() {
    echo
    bold "Setting up libvirt network"

    if ! command -v virsh &>/dev/null; then
        echo "  $(red 'ERROR'): virsh not found. Install libvirt first:"
        echo "    sudo apt install -y libvirt-daemon-system"
        return 1
    fi

    # Find existing libvirt network for this bridge
    local existing_net=""
    local name br
    while read -r name; do
        [[ -z "$name" ]] && continue
        br=$(virsh net-dumpxml "$name" 2>/dev/null | grep -oP "<bridge name='\K[^']*" | head -1 || true)
        if [[ "$br" == "$BRIDGE" ]]; then
            existing_net="$name"
            break
        fi
    done < <(virsh net-list --all --name 2>/dev/null)

    if [[ -n "$existing_net" ]]; then
        echo "  found libvirt network '$existing_net' for bridge $BRIDGE"
        if virsh net-info "$existing_net" 2>/dev/null | grep "Active:.*yes" >/dev/null; then
            echo "  already active"
        else
            run_cmd sudo virsh net-start "$existing_net"
            echo "  started network '$existing_net'"
        fi
        if ! virsh net-info "$existing_net" 2>/dev/null | grep "Autostart:.*yes" >/dev/null; then
            run_cmd sudo virsh net-autostart "$existing_net"
        fi
    elif [[ "$BRIDGE" == "virbr0" ]]; then
        if virsh net-info default &>/dev/null; then
            if ! virsh net-info default 2>/dev/null | grep "Active:.*yes" >/dev/null; then
                run_cmd sudo virsh net-start default
            fi
            run_cmd sudo virsh net-autostart default
            echo "  libvirt default network active on virbr0"
        else
            echo "  $(red 'ERROR'): no libvirt default network found"
            echo "  Recreate it or use --mode standalone"
            return 1
        fi
    else
        echo "  $(red 'ERROR'): no libvirt network found for bridge '$BRIDGE'"
        echo "  Create a libvirt network XML or use --mode standalone"
        return 1
    fi

    echo
    echo "  libvirt provides: bridge, DHCP (dnsmasq), NAT, forwarding rules"
}

# --- Setup: standalone mode ---

setup_standalone() {
    echo
    bold "Setting up standalone bridge: $BRIDGE"

    # 1. Create bridge via systemd-networkd
    if ip link show "$BRIDGE" &>/dev/null; then
        echo "  bridge $BRIDGE already exists"
    else
        echo "  creating bridge $BRIDGE via systemd-networkd"

        local netdev="/etc/systemd/network/50-dstack-${BRIDGE}.netdev"
        local network="/etc/systemd/network/51-dstack-${BRIDGE}.network"

        if [[ ! -f "$netdev" ]]; then
            run_cmd bash -c "cat > /tmp/.dstack-br-netdev <<'HEREDOC'
[NetDev]
Name=$BRIDGE
Kind=bridge
HEREDOC
sudo mv /tmp/.dstack-br-netdev $netdev"
            echo "  created $netdev"
        fi

        if [[ ! -f "$network" ]]; then
            run_cmd bash -c "cat > /tmp/.dstack-br-network <<'HEREDOC'
[Match]
Name=$BRIDGE

[Network]
Address=10.0.100.1/24
ConfigureWithoutCarrier=yes
IPMasquerade=both
HEREDOC
sudo mv /tmp/.dstack-br-network $network"
            echo "  created $network"
        fi

        run_cmd sudo systemctl restart systemd-networkd
        echo "  restarted systemd-networkd"

        echo "  waiting for bridge to come up..."
        local i
        for i in $(seq 1 10); do
            if ip link show "$BRIDGE" &>/dev/null; then
                break
            fi
            sleep 0.5
        done
    fi

    # 2. DHCP server (dnsmasq)
    echo
    bold "Setting up dnsmasq for $BRIDGE"

    if ! command -v dnsmasq &>/dev/null; then
        echo "  installing dnsmasq..."
        run_cmd sudo apt install -y dnsmasq
    fi

    local conf="/etc/dnsmasq.d/dstack-${BRIDGE}.conf"
    if [[ -f "$conf" ]]; then
        echo "  dnsmasq config already exists at $conf"
    else
        # Derive DHCP range from bridge IP
        local bridge_ip="10.0.100.1"
        local dhcp_start="10.0.100.10"
        local dhcp_end="10.0.100.254"
        local addr
        addr=$(ip -4 -o addr show "$BRIDGE" 2>/dev/null | awk '{print $4}' | head -1 || true)
        if [[ -n "$addr" ]]; then
            bridge_ip="${addr%/*}"
            local prefix="${bridge_ip%.*}"
            dhcp_start="${prefix}.10"
            dhcp_end="${prefix}.254"
        fi

        run_cmd bash -c "cat > /tmp/.dstack-dnsmasq <<HEREDOC
interface=$BRIDGE
bind-interfaces
dhcp-range=${dhcp_start},${dhcp_end},255.255.255.0,12h
dhcp-option=option:router,${bridge_ip}
dhcp-option=option:dns-server,8.8.8.8,1.1.1.1
HEREDOC
sudo mv /tmp/.dstack-dnsmasq $conf"
        echo "  created $conf"
        run_cmd sudo systemctl restart dnsmasq
        echo "  restarted dnsmasq"
    fi

    echo
    echo "  standalone provides: bridge, DHCP (dnsmasq), NAT (systemd-networkd IPMasquerade)"
}

# --- Main ---

usage() {
    cat <<'USAGE'
Usage: setup-bridge.sh <command> [options]

Commands:
  check   Check bridge networking prerequisites
  setup   Configure bridge networking prerequisites
  destroy Tear down bridge networking configuration

Options:
  --bridge NAME   Bridge interface name (default: virbr0)
  --mode MODE     Setup mode: libvirt or standalone (required for setup)
  --dry-run       Show what would be done without executing (setup only)
  -h, --help      Show this help

Setup modes:
  libvirt       Use libvirt network. Provides bridge, DHCP, NAT, and
                firewall rules automatically. Recommended if libvirt is
                already installed. Default bridge: virbr0.

  standalone    Create bridge with systemd-networkd and dnsmasq. Does
                not require libvirt. Use a custom bridge name to avoid
                conflicts with libvirt.

Examples:
  setup-bridge.sh check
  setup-bridge.sh check --bridge dstack-br0
  setup-bridge.sh setup --mode libvirt
  setup-bridge.sh setup --mode standalone --bridge dstack-br0
  setup-bridge.sh setup --mode standalone --bridge dstack-br0 --dry-run
  setup-bridge.sh destroy
  setup-bridge.sh destroy --bridge dstack-br0 --dry-run
USAGE
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            check|setup|destroy)
                COMMAND="$1"; shift ;;
            --bridge)
                BRIDGE="${2:?--bridge requires a value}"; shift 2 ;;
            --mode)
                SETUP_MODE="${2:?--mode requires a value}"; shift 2 ;;
            --dry-run)
                DRY_RUN=true; shift ;;
            -h|--help)
                usage; exit 0 ;;
            *)
                echo "unknown argument: $1"; usage; exit 1 ;;
        esac
    done

    if [[ -z "$COMMAND" ]]; then
        usage
        exit 1
    fi
}

cmd_check() {
    echo
    echo "$(bold 'dstack bridge networking diagnostics')"
    echo "target bridge: $(bold "$BRIDGE")"

    local provider
    provider=$(detect_bridge_provider)
    if [[ "$provider" == libvirt:* ]]; then
        echo "provider: $(bold 'libvirt') (network: ${provider#libvirt:})"
    else
        echo "provider: $(bold 'standalone')"
    fi

    check_bridge_helper
    check_bridge_conf
    check_bridge_interface
    check_dhcp
    check_ip_forward
    check_nat_rules
    check_forward_rules

    echo
    echo "---"
    echo "$(green "PASS: $PASS")  $(red "FAIL: $FAIL")  $(yellow "WARN: $WARN")"

    if [[ $FAIL -gt 0 ]]; then
        echo
        echo "Run '$(basename "$0") setup --mode <libvirt|standalone> --bridge $BRIDGE' to fix issues."
        return 1
    fi
}

cmd_setup() {
    if [[ -z "$SETUP_MODE" ]]; then
        echo
        echo "$(red 'ERROR'): --mode is required for setup."
        echo
        echo "Choose a mode:"
        echo "  --mode libvirt      Use libvirt (provides bridge + DHCP + NAT)"
        echo "  --mode standalone   No libvirt (systemd-networkd + dnsmasq)"
        echo
        echo "Example:"
        echo "  $(basename "$0") setup --mode libvirt"
        echo "  $(basename "$0") setup --mode standalone --bridge dstack-br0"
        exit 1
    fi

    if [[ "$SETUP_MODE" != "libvirt" && "$SETUP_MODE" != "standalone" ]]; then
        echo "$(red 'ERROR'): unknown mode '$SETUP_MODE'. Use 'libvirt' or 'standalone'."
        exit 1
    fi

    echo
    echo "$(bold 'dstack bridge networking setup')"
    echo "target bridge: $(bold "$BRIDGE")"
    echo "mode: $(bold "$SETUP_MODE")"
    $DRY_RUN && echo "dry-run: $(yellow 'yes')"

    # Common setup
    setup_bridge_conf
    setup_bridge_helper
    setup_ip_forward

    # Mode-specific setup
    case "$SETUP_MODE" in
        libvirt)    setup_libvirt ;;
        standalone) setup_standalone ;;
    esac

    echo
    echo "---"
    echo "$(bold 'Setup complete.')"
    echo
    echo "Add to vmm.toml:"
    echo
    echo "  [cvm.networking]"
    echo "  mode = \"bridge\""
    echo "  bridge = \"$BRIDGE\""
    echo
    echo "Verify: $(basename "$0") check --bridge $BRIDGE"
}

cmd_destroy() {
    local provider
    provider=$(detect_bridge_provider)

    echo
    echo "$(bold 'dstack bridge networking destroy')"
    echo "target bridge: $(bold "$BRIDGE")"
    if [[ "$provider" == libvirt:* ]]; then
        echo "provider: $(bold 'libvirt') (network: ${provider#libvirt:})"
    else
        echo "provider: $(bold 'standalone')"
    fi
    $DRY_RUN && echo "dry-run: $(yellow 'yes')"

    if [[ "$provider" == libvirt:* ]]; then
        local net_name="${provider#libvirt:}"
        echo
        bold "Stopping libvirt network '$net_name'"
        if virsh net-info "$net_name" 2>/dev/null | grep "Active:.*yes" >/dev/null; then
            run_cmd sudo virsh net-destroy "$net_name"
            echo "  stopped"
        else
            echo "  already inactive"
        fi
        if virsh net-info "$net_name" 2>/dev/null | grep "Autostart:.*yes" >/dev/null; then
            run_cmd sudo virsh net-autostart --disable "$net_name"
            echo "  autostart disabled"
        fi
    else
        # Standalone: remove dnsmasq config and systemd-networkd units
        local dnsmasq_conf="/etc/dnsmasq.d/dstack-${BRIDGE}.conf"
        if [[ -f "$dnsmasq_conf" ]]; then
            echo
            bold "Removing dnsmasq config"
            run_cmd sudo rm -f "$dnsmasq_conf"
            echo "  removed $dnsmasq_conf"
            run_cmd sudo systemctl restart dnsmasq 2>/dev/null || true
            echo "  restarted dnsmasq"
        fi

        local netdev="/etc/systemd/network/50-dstack-${BRIDGE}.netdev"
        local network="/etc/systemd/network/51-dstack-${BRIDGE}.network"
        if [[ -f "$netdev" ]] || [[ -f "$network" ]]; then
            echo
            bold "Removing systemd-networkd units"
            [[ -f "$netdev" ]] && { run_cmd sudo rm -f "$netdev"; echo "  removed $netdev"; }
            [[ -f "$network" ]] && { run_cmd sudo rm -f "$network"; echo "  removed $network"; }
            run_cmd sudo systemctl restart systemd-networkd
            echo "  restarted systemd-networkd"
        fi

        # Delete bridge interface if it still exists
        if ip link show "$BRIDGE" &>/dev/null; then
            echo
            bold "Deleting bridge interface $BRIDGE"
            run_cmd sudo ip link set "$BRIDGE" down
            run_cmd sudo ip link delete "$BRIDGE" type bridge
            echo "  deleted"
        fi
    fi

    # Remove bridge.conf entry
    local conf="/etc/qemu/bridge.conf"
    if [[ -f "$conf" ]] && grep -qE "^allow[[:space:]]+${BRIDGE}[[:space:]]*$" "$conf" 2>/dev/null; then
        echo
        bold "Removing '$BRIDGE' from $conf"
        run_cmd sudo sed -i "/^allow[[:space:]]\+${BRIDGE}[[:space:]]*$/d" "$conf"
        echo "  removed"
    fi

    echo
    echo "---"
    echo "$(bold 'Destroy complete.')"
}

parse_args "$@"

case "$COMMAND" in
    check)   cmd_check ;;
    setup)   cmd_setup ;;
    destroy) cmd_destroy ;;
esac
