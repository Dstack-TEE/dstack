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

### Option A: Using libvirt default network (recommended)

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

# /etc/dnsmasq.d/dstack-br0.conf
interface=dstack-br0
bind-interfaces
dhcp-range=10.0.100.10,10.0.100.254,255.255.255.0,12h
dhcp-option=option:router,10.0.100.1
dhcp-option=option:dns-server,8.8.8.8,1.1.1.1
```

```bash
sudo systemctl restart dnsmasq
```

**4. Update vmm.toml:**

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
- Guest MAC address is derived from SHA256 of the VM ID (stable across restarts for DHCP IP consistency)
- When QEMU exits, the TAP device is automatically destroyed
- VMM does not need root or `CAP_NET_ADMIN`

## Operational notes

### Do not restart the bridge while VMs are running

`virsh net-destroy`/`net-start` (or removing/recreating the bridge) will detach all TAP interfaces from the bridge, breaking VM networking. If this happens, affected VMs must be restarted.

### Firewall considerations

- libvirt injects nftables rules for NAT masquerade and forwarding automatically
- If using a manual bridge, ensure your firewall allows forwarding for the bridge subnet and has masquerade rules for outbound NAT
- Docker's nftables chains (`DOCKER-FORWARD`) run before libvirt's but do not block virbr0 traffic

### Mixing networking modes

Bridge and passt VMs can coexist. Set the global default in `vmm.toml` and override per-VM as needed:

```bash
# Global default is bridge, but deploy this VM with passt
vmm-cli.py deploy --name my-vm --image dstack-0.5.6 --compose app.yaml --net passt
```

### vhost-net and TDX

vhost-net (kernel data plane offload for virtio-net) is **not enabled** for bridge mode. TDX encrypts guest memory, which prevents the host kernel from performing DMA-based packet offload. The default QEMU userspace virtio backend is used instead.
