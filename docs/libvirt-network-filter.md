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

- `network_filter = "none"` preserves the existing QEMU `-netdev bridge`
  behavior and does not require `netd` or libvirt.
- `network_filter = "libvirt"` creates the TAP and filter binding before QEMU
  is submitted to Supervisor, and uses QEMU `-netdev tap`.
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
node defaults. If macvtap is explicitly enabled, callers may select only a
parent in `allowed_macvtap_parents`; the macvtap forwarding mode always comes
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
5. Start QEMU directly with `-netdev tap,script=no,downscript=no`.

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

## Deployment modes

Production should run one shared service. `netd` reads only the `[netd]`
section, so its root-owned configuration can be small and independent of every
VMM instance:

```toml
# /etc/dstack/netd.toml
[netd]
socket = "/run/dstack/netd.sock"
socket_mode = 0o660
libvirt_uri = "qemu:///system"
```

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

User networking and bridge networking with `mode = "none"` never connect to
`netd`. Libvirt mode fails closed if `netd` is unavailable.

Filtered TAP netdevs currently set `vhost=off`. This keeps the initial backend
on the directly bound TAP path and avoids adding `/dev/vhost-net` permissions
to the QEMU user. It is a deliberate security-first throughput tradeoff; a
future configurable vhost mode requires equivalent filter integration tests.
