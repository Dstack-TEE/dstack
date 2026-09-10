# Optional libvirt network filtering

## Goal

Allow bridge-backed VMs to opt into an existing libvirt `nwfilter` without
allowing libvirt to create or launch the QEMU domain. QEMU remains entirely
owned by `dstack-vmm`, so its command line and attestation inputs do not change
outside the explicitly selected network backend.

This integration applies only to bridge interfaces. It does not filter user,
custom, or macvtap networking. In particular, macvtap bypasses the Linux
bridge and requires policy enforcement in the physical network or a separate
host mechanism.

The measurable acceptance criteria are:

- `network_filter = "none"` installs no nwfilter binding. It does not remove
  the `netd` dependency: `netd` creates the TAP for every bridge NIC either
  way, and the VMM uses `-netdev tap` either way. What changes is only whether
  that TAP carries a binding.
- `network_filter = "libvirt"` creates the TAP and filter binding before QEMU
  is submitted to Supervisor, and uses QEMU `-netdev tap`.
- An nwfilter binding outlives the TAP it was bound to, so a teardown clears
  the binding at every name that VM could have used, whether or not the
  interface is still there. `dstack-vmm netd list` shows a binding whose
  interface is already gone as a `binding` row; remove one with
  `dstack-vmm netd remove-interface <name>`.
- A failed TAP or filter setup prevents QEMU from starting and rolls back all
  interfaces prepared for that VM.
- Normal stop and removal delete the filter binding and TAP.
- One host `netd` can serve multiple VMM instances. Resource names include a
  stable VMM instance namespace, VM ID, and NIC index.
- Development builds can run the VMM and `netd` directly, with explicit socket
  and allowed-UID command-line options; systemd is not required.

## Configuration

Filtering is a VMM host policy, not a field accepted from a VM manifest:

```toml
[cvm.network_filter]
mode = "none" # or "libvirt"
filter = "clean-traffic"
parameters = {}

[netd]
socket = "/run/dstack/netd.sock"
socket_mode = 0o660 # used when netd binds the socket itself
libvirt_uri = "qemu:///system"
```

Deployment RPC network choices are separately constrained by node policy:

```toml
[cvm]
allowed_network_modes = ["user", "bridge"]
allowed_bridges = ["tenant-br0"]
allowed_macvtap_parents = []
```

Macvtap is excluded from `allowed_network_modes` by default. Empty bridge and
macvtap-parent allowlists prevent RPC callers from overriding the respective
node defaults. If macvtap is explicitly enabled, callers may select a
parent listed in `allowed_macvtap_parents`, the node's own configured parent, or
one this VM already holds — restating a value the node would have supplied
anyway grants nothing new. The same applies to `bridge_name` and
`allowed_bridges`. The macvtap forwarding mode always comes
from `[cvm.networking].macvtap_mode` and cannot be selected through deployment
RPCs. These allowlists authorize attachment targets; an nwfilter is not a
substitute for that authorization.

Each VMM instance also has an `instance_id`. It must be unique among VMMs that
share a host. If omitted, the VMM derives a stable namespace from its absolute
run directory.

## Architecture

`netd` is a host-level privilege broker. It accepts a small, bounded JSON
protocol over a Unix stream socket. The socket's filesystem owner, group, and
mode are the authorization boundary: every process that can connect is fully
trusted to use the netd protocol. A single process can serve multiple VMMs; a
dedicated process can use another socket for development or isolation.

When netd creates the socket itself, `socket_mode` defaults to `0o660`. Ensure
that each authorized VMM process can reach the socket through its owning group
or another deliberately configured ownership arrangement. Never make the
socket accessible to an untrusted local user.

For libvirt mode, startup is:

1. Derive the TAP name from instance namespace, VM ID, and NIC index.
2. Create the TAP for the configured QEMU UID and attach it to the bridge.
3. Create a libvirt nwfilter binding for the TAP.
4. Bring the TAP up and return success.
5. Start QEMU directly with `-netdev tap,script=no,downscript=no`, carrying
   `vhost=on|off` and, above one queue pair, `queues=N`.

Teardown stops QEMU first, removes the binding, and deletes the TAP. Operations
are serialized by `netd`. The design intentionally does not add ownership
aliases; deployments must use unique instance IDs.

The protocol does not pin a client to an instance namespace, so any process
with socket access can prepare, check, or remove any deterministic identity.
Deploy VMM instances that do not share this trust boundary with dedicated netd
sockets and distinct filesystem permissions.

`netd` invokes fixed absolute `ip` and `virsh` executables with separate
arguments. It never accepts a command, executable path, TAP name, or raw XML
from a client. Filter XML is generated internally with XML escaping and is
validated by libvirt.

Teardown by identity only reaches the NIC indices its caller still has a record
of, and that record is written *after* the interface exists — a VMM killed in
between leaves a TAP nothing on disk points at, and a manifest that lost a NIC
leaves the same thing behind. `remove_all` names a VM instead of an interface
and derives every name that VM could occupy, so neither has to be recorded for
teardown to work. The VMM sweeps before preparing a launch as well as on stop,
which makes a launch self-healing regardless of what the record says.

A bridge prepare also carries two things `netd` does not need to build the TAP.
`workdir` names the VM's directory on the host: untrusted, never read for a
decision, and present only so an operator reading `netd`'s log can get from an
opaque TAP name back to the VM. `ingress` states the host ports that NIC should make
reachable at its guest, which the VMM cannot arrange itself — it runs without
`CAP_NET_ADMIN` by design, and QEMU's `hostfwd=` entries need a user-mode netdev
that a bridge NIC does not have. The `netd` in this repository builds interfaces
and does not forward ports; it says so by leaving `ingress` out of its response,
the same reading `queues` gets, so a caller can tell "this netd does not do that"
from "nothing was asked for" instead of assuming ports were forwarded because a
TAP came back.

## Deployment modes

Production should run one shared service. `netd` reads the `[netd]` section,
plus `cvm.network_filter.mode` if the file has one, so its root-owned
configuration can be small and independent of every VMM instance:

```toml
# /etc/dstack/netd.toml
[netd]
socket = "/run/dstack/netd.sock"
socket_mode = 0o660
libvirt_uri = "qemu:///system"

# Required here because this file has no [cvm] section for netd to read the
# node's policy from.
[netd.network_filter]
mode = "libvirt"
filter = "clean-traffic"
parameters = {}
```

`[netd.network_filter]` is netd's own copy of the invariant, not a convenience.
netd is the privileged side of the socket, and anything that can reach the
socket can ask for an unfiltered TAP on a host bridge — a request a filtering
node has to refuse in the daemon rather than in its caller. When netd and the
VMM share one `vmm.toml`, leaving it unset derives it from
`[cvm.network_filter]` so the two cannot drift apart; a malformed section is a
startup error rather than a silent fallback to "filter nothing".

The request says only *whether* to bind a filter, never which one. A caller that
named the filter could name `allow-arp`, which contains no drop rule at all, or
pin `clean-traffic` to the gateway's MAC and IP through its parameters, and
still satisfy a policy that asked for "some filter".

A macvtap parent is refused when filtering is required and the parent is a host
bridge or is enslaved to one: nwfilter does not apply to macvtap, so that
request is the same unfiltered access to the same segment, spelled with a
different operation.

Production deployments can use systemd socket activation. The socket unit
owns the filesystem mode and ownership; `netd.socket_mode` applies only to the
standalone bind path.

```ini
# /etc/systemd/system/dstack-netd.socket
[Unit]
Description=dstack host networking socket

[Socket]
ListenStream=/run/dstack/netd.sock
SocketMode=0660
SocketUser=root
SocketGroup=dstack-vmm
RemoveOnStop=true

[Install]
WantedBy=sockets.target
```

```ini
# /etc/systemd/system/dstack-netd.service
[Unit]
Description=dstack host networking service
After=libvirtd.service

[Service]
ExecStart=/usr/bin/dstack-vmm --config /etc/dstack/netd.toml netd
Restart=on-failure
```

The service accepts exactly one Unix stream listener through the systemd
`LISTEN_FDS` protocol. With no activated descriptor it falls back to binding
`netd.socket` itself. More than one descriptor, or a descriptor of the wrong
socket type, is rejected.

All VMM instance configurations point to the same socket and use distinct
`cvm.instance_id` values. A dedicated netd uses a different socket. A
host-wide lock serializes mutations made by shared and dedicated netd
processes.

Development mode is two ordinary commands:

```bash
sudo dstack-vmm --config ./vmm.toml netd \
  --socket /run/dstack-dev/netd.sock
sudo dstack-vmm --config ./vmm.toml \
  --netd-socket /run/dstack-dev/netd.sock
```

User networking and a caller-supplied netdev never ask `netd` to build an
interface. The VMM still contacts the socket for such a VM -- every launch and
every stop releases whatever the VM held, before it decides whether it needs
anything built -- but nothing about the VM depends on the answer. Bridge and
macvtap do ask, and fail closed if `netd` is unavailable.

Filtered TAP netdevs follow the node's `vhost` and `queues` settings like any
other TAP-backed NIC (see [network-data-plane.md](network-data-plane.md)). The
nwfilter binding is installed on the host TAP interface, so packets traverse it
whether they were written by QEMU or by a vhost worker; filtering is unaffected
by the data plane choice. Enabling vhost does require the QEMU user to be able
to open `/dev/vhost-net`.

`netd` creates the TAP for unfiltered bridge NICs too. Those TAPs carry no
nwfilter binding, so a bridge node needs `netd` even when
`network_filter.mode = "none"` — see
[bridge-networking.md](bridge-networking.md) for why the host interface has a
single owner.

An empty filter name is what selects that unfiltered TAP, so `mode = "libvirt"`
with an empty `filter` is rejected at config load rather than quietly producing
an unbound TAP.

Removal carries the same distinction: the VMM tells `netd` whether the interface
it is asking about was created with a binding, from a record made when it was
built rather than from configuration that may have changed since. A binding it
was told about must be gone before `netd` returns; otherwise `netd` still asks
libvirt to clear one — an interface name is reused by the same VM, and a
leftover binding's rules would be inherited — but a `libvirtd` it cannot reach
is a warning rather than a failure. So a node with `virsh` installed and no
running `libvirtd` can create and destroy multiqueue TAPs. The flag defaults to
true on the wire, so an older VMM's removals still drop their bindings.

`netd` requires the `virsh` binary to be present whatever the filter mode; it is
`libvirtd` that unfiltered work does not need.
