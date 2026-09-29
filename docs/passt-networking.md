# passt networking

[passt](https://passt.top/) gives a CVM outbound connectivity and published
host ports without any privileged host setup, like user mode, but through
passt's network stack instead of QEMU's built-in slirp. Install the `passt`
package on the host before enabling it.

## Configuration

```toml
[cvm]
allowed_network_modes = ["user", "bridge", "passt"]
# Empty finds `passt` in PATH at startup.
passt_path = ""

[cvm.networking]
mode = "passt"
address = "10.0.2.10"
netmask = "255.255.255.0"
gateway = "10.0.2.2"
dns = ["1.1.1.1", "1.0.0.1"]
no_map_gw = true
ipv4_only = true
```

The `[cvm.networking]` fields map to the passt options of the same name
(`interface`, `address`, `netmask`, `gateway`, `dns`, `map_host_loopback`,
`map_guest_addr`, `no_map_gw`, `ipv4_only`); an empty value leaves passt's own
default in place. These are node settings: a deployment RPC may pick `passt`
as a NIC's mode but cannot change them. passt has no vhost data plane and runs
a single queue pair, so `vhost` and `queues` do not apply.

Keep `no_map_gw = true` (or `map_host_loopback = "none"` on passt releases
that support it). Otherwise the guest reaches services bound to the host's
loopback interface through the gateway address.

## Port mappings

A passt NIC publishes `port_map` entries the way a user-mode NIC does. An
unpinned mapping goes to the first user-mode or passt NIC; a mapping pinned
with `nic_index` must name one of those.

## Several CVMs on one host

Upstream passt keeps a guest's UDP source port on the host side, and binds it
with `SO_REUSEADDR`. When two CVMs send from the same source port to the same
peer, for example WireGuard clients with a fixed listen port talking to one
gateway, their host sockets are identical and the kernel delivers every reply
to one of them. One CVM loses its replies and the other receives both.

Run a passt build that lets the kernel pick the host source port for guest
UDP flows (for example the `dstack` branch of
<https://github.com/kvinwang/passt>) and point `passt_path` at it. On Ubuntu,
a passt outside `/usr/bin/passt` also needs an AppArmor profile of its own:
unconfined programs may not create the user namespaces passt sandboxes itself
in (`kernel.apparmor_restrict_unprivileged_userns`). Build that profile from
the policy shipped with the same passt source (`contrib/apparmor`), since
newer passt releases need rules older distribution policies lack.

## Process lifecycle

Every passt NIC runs its own passt process, started by the VM's
`vm-launcher` before QEMU and stopped with it. The launcher connects the two
over a socketpair (`passt --fd`), so no socket file is created and the
AppArmor profile Ubuntu ships for passt does not get in the way. passt runs
with `--quiet`, so only its warnings and errors reach the VM's `stderr.log`:
under that profile passt cannot reach syslog once sandboxed, and each
informational message would otherwise log a "Failed to send ... to syslog"
line instead.

It is not a separate supervisor process, so stopping or removing a VM cannot
leave a passt process behind.
