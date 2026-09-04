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

### netd is required

Bridge networking needs `netd`, the privileged helper that owns every host
interface a bridge or macvtap NIC uses. It is the same binary:

```bash
sudo dstack-vmm netd -c vmm.toml
```

Nothing else on the node needs `CAP_NET_ADMIN`: the VMM itself still runs
unprivileged, and `netd` holds the privilege behind a Unix socket whose
filesystem permissions authorize callers.

This used to be conditional — `netd` built the TAP when libvirt filtering was on
or when the NIC wanted more than one queue pair, and otherwise QEMU's setuid
`qemu-bridge-helper` did. Two owners meant two answers to the same questions:
which netdev QEMU gets, whether vhost is really on, and where a bridge NIC's
published ports go. Only `netd` can answer the last one, because only `netd`
sees every VMM instance on the host and can arbitrate a port between them. So a
bridge NIC's host interface has one owner now, on every node.

`qemu-bridge-helper` is no longer used, and `/etc/qemu/bridge.conf` no longer
needs an `allow` line for the bridge.

## How it works

- `netd` creates a persistent TAP, attaches it to the bridge, binds the nwfilter if the node filters, and the VMM passes `-netdev tap,id=net0,ifname=<tap>,...`
- Guest MAC address is derived from SHA256 of the VM ID, with an optional configurable prefix (stable across restarts for DHCP IP consistency)
- The host DHCP server (dnsmasq) assigns an IP to the VM
- The TAP outlives QEMU and is deleted when the VMM tears the VM's networking down, so a VM that crashes does not leave its filter rules attached to a name the next VM could take
- Every interface `netd` creates records which VM of which VMM instance it belongs to, in the kernel's interface alias — see [Who owns an interface](#who-owns-an-interface)
- The VMM process needs neither root nor `CAP_NET_ADMIN`; `netd` holds that privilege in a separate service

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

### Which NIC a port mapping uses

A port mapping says which NIC its traffic enters through:

```bash
vmm-cli.py deploy ... --port udp:0.0.0.0:7483:51820@0 --port tcp:127.0.0.1:7484:8001@0
```

Leave `@<nic>` off and the VMM picks the first user-mode NIC — where QEMU's
`hostfwd=` entries have always gone — and failing that the first bridge NIC. A
single-NIC VM never needs it.

With several NICs the choice used to be made silently, and not always the way an
operator would have. A bridge NIC for external traffic beside a user-mode NIC for
management — the topology multi-NIC was added for — put every published port on
the *management* NIC: the traffic reached the guest, but over slirp, bypassing
whatever the bridge NIC's nwfilter was there to enforce and hiding the client's
address behind the slirp gateway. A second user-mode NIC could never publish
anything at all, because only the first was ever selected.

A mapping resolves to exactly one NIC, and that NIC's backend decides the
mechanism: `hostfwd=` for user mode, `netd` for a bridge. Nothing can be claimed
by both.

### Which ports are actually published

A port mapping is a *request*. Whether it is met depends on which NIC carries
it: QEMU publishes a user-mode NIC's mappings itself, while a bridge NIC's can
only be published by `netd`, and the `netd` in this repository builds
interfaces and does not forward host ports.

`GetInfo` reports `published` per mapping so the difference is visible rather
than assumed. A deployment that asks for something this node cannot publish is
refused outright — nothing is running on the answer yet — while a VM deployed
before the node could answer only gets a warning at launch, so an upgrade never
turns a silent misconfiguration into an outage.

To publish a bridge NIC's ports, run a `netd` that forwards. It reports
`ingress: true` in its `hello` and echoes what it established in each prepare;
the VMM records that answer and holds it to it per mapping.

## Who owns an interface

`netd` names an interface `dt<12 hex>`, a digest of (VMM instance, VM, NIC
index). That answers "where is this VM's interface" but not "whose is this
interface" — and the second question is the one a leaked interface poses. So
`netd` also records the identity on the interface itself:

```console
$ ip -d link show dtc41d9e0b7a52 | grep alias
    alias dstack1:0:path-3f9a1c8e7d2b4a60:0a1b2c3d4e5f6071
```

The kernel holds that for exactly the interface's lifetime, so unlike a file on
disk it cannot be written late, lost, or left behind. It is a hint, never an
authority: a record is believed only when re-deriving the interface name from
it reproduces the name it is written on, so a forged, truncated or ambiguous
record reads the same as no record at all.

```bash
# What netd holds on this host
sudo dstack-vmm netd list

# Everything one VM holds, for a VM whose VMM will never ask again
sudo dstack-vmm netd remove-vm --instance path-3f9a1c8e7d2b4a60 --vm 0a1b2c3d4e5f6071
```

### Collection

The VMM reconciles what `netd` holds against the VMs it has: once at startup,
after loading them, and then every `netd.reconcile_interval_secs`. That is what
reaches an interface no per-VM teardown can — one whose VM was removed while
the VMM was down, or whose workdir was deleted by hand.

It asks `netd list` and decides for itself, rather than asking `netd` to decide.
The decision is only safe under the VMM's per-VM launch lock, which `netd` has
no way to take: a collection decided inside `netd` would be decided against a
set of live VMs that was true when the request was *sent*, and `netd` runs it
when it wins the operation lock — possibly much later, by which time a VM
created in between is absent from the set and present on the host. Here each
VM is re-checked while holding the lock its own launch holds, so a launch and a
collection of the same VM cannot both believe they are alone.

| What the interface is recorded as | What happens |
| --- | --- |
| Another VMM instance's | Never touched. Several VMM instances share one `netd`, and the record is the only thing that can tell that instance's *running* VM from garbage |
| This instance's, for a VM it no longer has | Collected, by the same whole-VM sweep a stop uses |
| Nothing that checks out | Left alone. No VMM can tell whose it is, so no VMM decides about it |

An interface with no record is not nobody's: before `netd` recorded ownership
every interface looked like this, and on a host with two VMM instances one of
them may be the other's running VM. They are reported at each pass and listed
by `netd list` with `-` for instance and VM; an operator who can tell what one
is removes it by name:

```bash
sudo dstack-vmm netd remove-interface dtc41d9e0b7a52
```

Nothing accumulates: each interface gains a record the next time its VM
launches, so the set only shrinks.

Changing `cvm.instance_id` — or `run_path`, which it is derived from — is the
one move that strands interfaces on purpose. They stay recorded under the old
namespace, so no VMM collects them and running VMs keep working until they
stop. `netd list` still shows the old instance ID, which is what
`netd remove-vm --instance <old> --vm <id>` needs.

### Mixing networking modes

Bridge and user-mode VMs can coexist. Set the global default in `vmm.toml` and override per-VM as needed:

```bash
# Global default is bridge, but deploy this VM with user networking
vmm-cli.py deploy --name my-vm --image dstack-0.5.6 --compose app.yaml --net user
```

### vhost-net and multiqueue

Bridge NICs can run on the host kernel's vhost-net data plane and expose several virtio-net queue pairs. Both are off by default and enabled per node or per VM — see [network-data-plane.md](network-data-plane.md) for the knobs, the enablement checklist, the mode support matrix, and how to pick a queue count.

vhost-net works in a TDX guest: the virtio rings and buffers live in shared, unencrypted memory so that a host-side backend can reach them, which is the same mechanism `vhost-vsock-pci` has always relied on.
