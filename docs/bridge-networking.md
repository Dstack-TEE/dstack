# Bridge Networking for VMM

By default, dstack-vmm uses **user** networking (QEMU's built-in SLIRP stack, no host setup required). Bridge networking is an alternative that provides better performance for high-connection workloads by using kernel-level bridging with TAP devices.

## When to use bridge networking

- High connection concurrency (user-mode networking becomes CPU-bound at ~25K+ concurrent connections)
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
- **CLI**: `vmm-cli.py deploy --net bridge`, `--net user`, or `--net macvtap`
- **Web UI**: Networking dropdown in the deploy dialog
- **API**: `networking: { mode: "bridge" }` in `VmConfiguration`

The bridge interface name comes from the global config unless the node lists it in `cvm.allowed_bridges`. VMs may also override the vhost and queue settings — see [network-data-plane.md](network-data-plane.md).

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

Create dnsmasq config:

```ini
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

### QEMU bridge helper setup (needed unless every bridge NIC goes through netd)

The bridge helper allows QEMU to create and attach TAP devices without VMM needing root privileges.
It is used only on the single-queue bridge paths; a NIC that `netd` builds never touches it, so a
node that runs `netd` for all of its bridge VMs does not need it at all.

The VMM probes `/usr/lib/qemu/qemu-bridge-helper`, `/usr/libexec/qemu-bridge-helper` and
`/usr/local/libexec/qemu-bridge-helper`. Set `cvm.qemu_bridge_helper` in `vmm.toml` for a path
outside that list.

```bash
# Allow QEMU to use the bridge
sudo mkdir -p /etc/qemu
echo "allow virbr0" | sudo tee /etc/qemu/bridge.conf
# Or for manual bridge: echo "allow dstack-br0" | sudo tee /etc/qemu/bridge.conf

# Set setuid on bridge helper
sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper
```

## How it works

- With more than one queue pair, or with libvirt filtering on, `netd` creates the TAP and the VMM passes `-netdev tap,id=net0,ifname=<tap>,...` — this is the usual case on a node running `netd` with multi-vCPU VMs, since queue pairs default to the VM's vCPU count. Without `netd`, a bridge NIC that took that default drops back to one queue pair and takes a helper path below
- Otherwise the VMM passes `-netdev tap,id=net0,br=<bridge>,helper=<qemu-bridge-helper>,vhost=on`, or `-netdev bridge,id=net0,br=<bridge>` when vhost is off or no helper is found
- QEMU's bridge helper (setuid) creates a TAP device and attaches it to the bridge on the two helper paths
- Guest MAC address is derived from SHA256 of the VM ID, with an optional configurable prefix (stable across restarts for DHCP IP consistency)
- The host DHCP server (dnsmasq) assigns an IP to the VM
- On the two bridge-helper paths the TAP disappears when QEMU exits; a `netd`-created TAP is persistent and is deleted when the VMM tears the VM's networking down
- The VMM process itself needs neither root nor `CAP_NET_ADMIN` on any path; the `netd` path moves that privilege into a separate root service instead

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

### Host port mappings

A VM's `port_map` has always been implemented as QEMU `hostfwd=` entries on a
user-mode netdev. A bridge NIC has no such netdev, so **the VMM does not forward
host ports for bridge VMs** — it is deliberately run without `CAP_NET_ADMIN`,
and a userspace proxy on the host would give back the per-packet cost that
moving off user mode was meant to escape.

What the VMM does instead is carry the requirement to `netd`, which is
privileged and is the only component that sees every VMM instance on the host —
and therefore the only one that can arbitrate a host port between them. Whether
a given `netd` implements forwarding is its own business; the one in this
repository does not, and says so through `hello` rather than accepting ports it
will not forward.

So on a node whose `netd` does not forward:

- the VM starts normally and its bridge networking works
- its port mappings do not apply, and the VMM says so in its log at every launch
- `GetInfo` reports an empty `ingress` on the interface, against the non-empty
  `ports` on the configuration — that difference is the signal

Expose such a VM by reaching its address on the bridge directly, by putting an
L7 proxy in front of it, or by running a `netd` that forwards. `GetInfo` reports
the interface's `guest_ip` when `netd` is the authority for addresses on that
segment; a bridge NIC otherwise takes its address from a DHCP server the VMM
does not run and cannot ask.

`macvtap` and `custom` NICs can never carry host port mappings — the first
bypasses the host bridge, and the second hands the whole netdev string to the
operator. The VMM warns rather than refusing to start, because a VM deployed
before any of this existed has been running with its ports dropped, and turning
that into a failed launch on upgrade would make an outage out of a
misconfiguration that was already there.

### Mixing networking modes

Bridge and user-mode VMs can coexist. Set the global default in `vmm.toml` and override per-VM as needed:

```bash
# Global default is bridge, but deploy this VM with user networking
vmm-cli.py deploy --name my-vm --image dstack-0.5.6 --compose app.yaml --net user
```

### vhost-net and multiqueue

Bridge NICs can run on the host kernel's vhost-net data plane and expose several virtio-net queue pairs. Both are off by default and enabled per node or per VM — see [network-data-plane.md](network-data-plane.md) for the knobs, the enablement checklist, the mode support matrix, and how to pick a queue count.

vhost-net works in a TDX guest: the virtio rings and buffers live in shared, unencrypted memory so that a host-side backend can reach them, which is the same mechanism `vhost-vsock-pci` has always relied on.
