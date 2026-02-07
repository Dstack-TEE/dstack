# Bridge Networking for VMM

By default, dstack-vmm uses **user** networking (QEMU's built-in SLIRP stack, no host setup required). Bridge networking is an alternative that provides better performance for high-connection workloads by using kernel-level bridging with TAP devices.

## When to use bridge networking

- High connection concurrency (passt becomes CPU-bound at ~25K+ concurrent connections)
- Workloads that need full L2 network access
- Environments where VMs need to be directly reachable on the LAN

## Configuration

### VMM global config (`vmm.toml`)

```toml
[cvm.networking]
mode = "bridge"
bridge = "virbr0"
```

### Per-VM override

Individual VMs can override the global networking mode via:
- **CLI**: `vmm-cli.py deploy --net bridge` or `--net passt`
- **Web UI**: Networking dropdown in the deploy dialog
- **API**: `networking: { mode: "bridge" }` in `VmConfiguration`

Only the mode is per-VM; the bridge interface name always comes from the global config.

## Host setup

### Option A: Using libvirt default network

libvirt's default network provides a bridge (`virbr0`) with DHCP (dnsmasq) and NAT out of the box.

```bash
# Install libvirt (if not already present)
sudo apt install -y libvirt-daemon-system

# Ensure default network is active
sudo virsh net-start default 2>/dev/null
sudo virsh net-autostart default
```

Verify:
```bash
ip addr show virbr0
# Should show 192.168.122.1/24

virsh net-dhcp-leases default
# Lists DHCP leases for connected VMs
```

### Option B: Manual bridge without libvirt

Create a bridge with systemd-networkd and run a standalone DHCP server.

**1. Create the bridge:**

```bash
# /etc/systemd/network/10-dstack-br.netdev
[NetDev]
Name=dstack-br0
Kind=bridge

# /etc/systemd/network/11-dstack-br.network
[Match]
Name=dstack-br0

[Network]
Address=10.0.100.1/24
ConfigureWithoutCarrier=yes
IPMasquerade=both
```

```bash
sudo systemctl restart systemd-networkd
```

**2. Enable IP forwarding:**

```bash
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-dstack-bridge.conf
sudo sysctl -p /etc/sysctl.d/99-dstack-bridge.conf
```

**3. Run a DHCP server (dnsmasq):**

```bash
sudo apt install -y dnsmasq
```

Install the DHCP notification script (notifies VMM when a VM gets an IP so port forwarding can be established):

```bash
sudo cp scripts/dhcp-notify.sh /usr/local/bin/dhcp-notify.sh
sudo chmod +x /usr/local/bin/dhcp-notify.sh
```

Create dnsmasq config:

```ini
# /etc/dnsmasq.d/dstack-br0.conf
interface=dstack-br0
bind-interfaces
dhcp-range=10.0.100.10,10.0.100.254,255.255.255.0,12h
dhcp-option=option:router,10.0.100.1
dhcp-option=option:dns-server,8.8.8.8,1.1.1.1
dhcp-script=/usr/local/bin/dhcp-notify.sh
```

The `dhcp-script` option tells dnsmasq to call the notification script on every lease event. The script sends the MAC and IP to VMM's `ReportDhcpLease` RPC, which triggers automatic port forwarding for the VM.

```bash
sudo systemctl restart dnsmasq
```

**4. Firewall rules (nftables):**

When the host firewall has a restrictive INPUT policy (e.g. `drop`), the bridge's DHCP and DNS traffic will be silently blocked. libvirt handles this automatically for virbr0, but a standalone bridge needs explicit rules.

```bash
BRIDGE=dstack-br0
SUBNET=10.0.100.0/24

# Allow DHCP and DNS from VMs (INPUT/OUTPUT)
sudo nft add rule ip filter INPUT iifname "$BRIDGE" udp dport 67 counter accept
sudo nft add rule ip filter INPUT iifname "$BRIDGE" udp dport 53 counter accept
sudo nft add rule ip filter INPUT iifname "$BRIDGE" tcp dport 53 counter accept
sudo nft add rule ip filter OUTPUT oifname "$BRIDGE" udp dport 68 counter accept
sudo nft add rule ip filter OUTPUT oifname "$BRIDGE" udp dport 53 counter accept

# Allow forwarding for VM traffic
sudo nft add rule ip filter FORWARD ip saddr "$SUBNET" iifname "$BRIDGE" counter accept
sudo nft add rule ip filter FORWARD ip daddr "$SUBNET" oifname "$BRIDGE" ct state related,established counter accept
sudo nft add rule ip filter FORWARD iifname "$BRIDGE" oifname "$BRIDGE" counter accept

# NAT masquerade for outbound traffic
sudo nft add rule ip nat POSTROUTING ip saddr "$SUBNET" ip daddr 224.0.0.0/24 counter return
sudo nft add rule ip nat POSTROUTING ip saddr "$SUBNET" ip daddr 255.255.255.255 counter return
sudo nft add rule ip nat POSTROUTING ip saddr "$SUBNET" ip daddr != "$SUBNET" counter masquerade
```

If the host uses libvirt, nftables rules may be in custom chains (`LIBVIRT_INP`, `LIBVIRT_FWO`, etc.) instead of the default `INPUT`/`FORWARD` chains. Adjust the chain names accordingly.

To make these rules persistent across reboots, save them with `nft list ruleset > /etc/nftables.conf` or add them to a systemd service.

**5. Update vmm.toml:**

```toml
[cvm.networking]
mode = "bridge"
bridge = "dstack-br0"
```

### QEMU bridge helper setup (required for both options)

The bridge helper allows QEMU to create and attach TAP devices without VMM needing root privileges.

```bash
# Allow QEMU to use the bridge
sudo mkdir -p /etc/qemu
echo "allow virbr0" | sudo tee /etc/qemu/bridge.conf
# Or for manual bridge: echo "allow dstack-br0" | sudo tee /etc/qemu/bridge.conf

# Set setuid on bridge helper
sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper
```

## How it works

- VMM passes `-netdev bridge,id=net0,br=<bridge>` to QEMU
- QEMU's bridge helper (setuid) creates a TAP device and attaches it to the bridge
- Guest MAC address is derived from SHA256 of the VM ID, with an optional configurable prefix (stable across restarts for DHCP IP consistency)
- The host DHCP server (dnsmasq) assigns an IP and calls `dhcp-notify.sh`, which notifies VMM via the `ReportDhcpLease` RPC
- VMM matches the MAC address to identify the VM and establishes port forwarding rules
- When QEMU exits, the TAP device is automatically destroyed
- VMM does not need root or `CAP_NET_ADMIN`

### MAC address prefix

You can configure a fixed MAC address prefix (0–3 bytes) in vmm.toml:

```toml
[cvm.networking]
mode = "bridge"
bridge = "dstack-br0"
mac_prefix = "52:54:00"
```

The remaining bytes are derived from the VM ID hash. The prefix applies to all networking modes, not just bridge. The locally-administered bit is always set on the first byte.

## Operational notes

### Do not restart the bridge while VMs are running

`virsh net-destroy`/`net-start` (or removing/recreating the bridge) will detach all TAP interfaces from the bridge, breaking VM networking. If this happens, affected VMs must be restarted.

### Firewall considerations

- libvirt automatically injects nftables rules for INPUT (DHCP/DNS), FORWARD, and NAT masquerade into its own chains (`LIBVIRT_INP`, `LIBVIRT_FWO`, `LIBVIRT_FWI`, `LIBVIRT_PRT`)
- A standalone bridge requires **all** of these rules to be added manually (see Option B step 4 above). The most common failure mode is a restrictive INPUT policy silently dropping DHCP requests from VMs — if VMs on a custom bridge don't get an IP, check `sudo nft list chain ip filter INPUT` first
- Docker's nftables chains (`DOCKER-FORWARD`) run before libvirt's but do not block virbr0 traffic
- Use `setup-bridge.sh check --bridge <name>` to diagnose missing rules

### Mixing networking modes

Bridge and passt VMs can coexist. Set the global default in `vmm.toml` and override per-VM as needed:

```bash
# Global default is bridge, but deploy this VM with passt
vmm-cli.py deploy --name my-vm --image dstack-0.5.6 --compose app.yaml --net passt
```

### vhost-net and TDX

vhost-net (kernel data plane offload for virtio-net) is **not enabled** for bridge mode. TDX encrypts guest memory, which prevents the host kernel from performing DMA-based packet offload. The default QEMU userspace virtio backend is used instead.
