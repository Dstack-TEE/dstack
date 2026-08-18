# Macvtap networking

Macvtap mode gives each CVM a layer-2 identity on an existing host network
without adding the parent interface to a Linux bridge. The VMM delegates the
privileged interface lifecycle to `dstack-vmm netd`; manifests never contain
the unstable `/dev/tapN` device path.

## Configuration

Configure a NIC through the manifest or VMM RPC:

```json
{
  "mode": "macvtap",
  "parent": "eth0",
  "macvtap_mode": "private"
}
```

`parent` must name an existing host interface. `macvtap_mode` may be
`private`, `bridge`, `vepa`, or `passthru`; an empty value selects `private`.
The configured netd socket permissions apply in the same way as for
libvirt-filtered bridge networking.

## Lifecycle

For every macvtap NIC, the VMM sends netd the VM identity, NIC index, parent,
and the same deterministic MAC address passed to QEMU. Netd then:

1. derives the stable `dt<hash>` interface name;
2. replaces any stale interface with that name;
3. creates and activates the macvtap interface;
4. reads its kernel-assigned ifindex and waits for `/dev/tap<ifindex>`; and
5. returns that runtime device path to the VMM.

The per-VM launcher opens the character device, places it at the fd referenced
by QEMU's `-netdev tap,fd=...` argument, and then execs QEMU. This keeps device
paths out of persistent VM
configuration, works with both Supervisor and systemd process managers, and
does not pass network fds through `sudo`.

VM shutdown removes the interface by its deterministic identity. The device
node disappears with the interface; its numeric path is never reused as an
identity or cleanup key.

## Limitations

- The host and a macvtap guest do not communicate directly through the parent
  interface by default. Add a host macvlan/macvtap endpoint if that path is
  required.
- Libvirt nwfilter bindings apply only to bridge mode. Macvtap deployments
  must enforce network policy in the physical network or with another host
  mechanism.
- Real-host testing requires `CAP_NET_ADMIN`, a working udev setup for
  `/dev/tapN`, and an upstream network that accepts multiple MAC addresses.
