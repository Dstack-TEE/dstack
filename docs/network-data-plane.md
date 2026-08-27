# virtio-net data plane tuning

Every CVM NIC has two knobs that decide how many packets it can move: whether
the host kernel's vhost-net data plane is used, and how many virtio-net queue
pairs the device exposes. vhost is set per node and overridable per VM; queue
pairs have no node-wide setting at all, for the reason given under
Configuration.

## Why it matters

Without vhost-net, QEMU drains every received packet on its single main-loop
thread. That thread is the ceiling, and it does not grow with vCPUs:

```
maximum packets per second ≈ 1 core ÷ per-packet main-loop cost
```

The per-packet cost varies with traffic shape — a few microseconds for uniform
synthetic streams, tens of microseconds for bidirectional short-connection
traffic — so the ceiling is a property of the workload, not a fixed number.
What is fixed is the shape of the failure: throughput climbs normally until the
main loop saturates at 100% of one core, then packets are dropped at the TAP
before they ever reach the guest. Guest-side counters stay clean, which makes
the cliff easy to misdiagnose as a network problem.

Guest-side outbound traffic uses the same thread, so a busy guest pays the
cost twice over.

`vhost=on` moves that work into the host kernel. That returns a whole core, but
it relocates the ceiling rather than removing
it: packets now arrive faster than a single guest receive queue can drain, and
the drops reappear at a higher rate. More queue pairs is what removes them,
which is why enabling vhost also enables a queue count that follows the VM's
vCPU count — the two travel together.

vhost is **off by default** and enabled per node (or per VM). Two things make
it an opt-in rather than a default: turning it on changes the virtio-net device
of every bridge/macvtap VM on its next boot, and it requires `/dev/vhost-net`
to be accessible to the account QEMU runs under, which the VMM cannot verify on
the operator's behalf — see [Enabling vhost on a node](#enabling-vhost-on-a-node).

## Configuration

```toml
[cvm]
# Ceiling for both the default and what a deployment may request.
max_net_queues = 16

[cvm.networking]
mode = "bridge"
bridge = "dstack-br0"
vhost = true
```

Queue pairs are not a node setting. With vhost on they default to the VM's vCPU
count, capped at 16, because the useful number follows the VM rather than the
host — the guest driver uses at most one queue pair per vCPU. A deployment
overrides that per VM, up to `max_net_queues`.

Raising `max_net_queues` above 16 widens what a deployment may ask for without
moving the default's cap, so a larger VM never silently acquires a worse
default. Lowering it below 16 does lower the default too, because a node that
refuses a request for four queue pairs should not hand out sixteen by itself.
The hard ceiling from any source is 64.

Without vhost the default is a single queue pair. The QEMU main loop drains
every queue on one thread, so extra queues buy little while still costing a
netd interface, more MSI-X vectors, and a changed guest device. An explicit
queue count is still honoured without vhost, since that combination is a
deliberate request rather than a default. The two defaults travelling together
also means a node that never sets `vhost` keeps building the device its VMs
have always had.

A VM overrides either value at deploy time, and `UpdateVm` changes them
afterwards — the new values apply from the VM's next boot:

```bash
vmm-cli.py deploy --name my-vm --image dstack-0.5.9 --compose app.yaml \
  --net bridge --net-queues 4
vmm-cli.py deploy --name latency-vm --image dstack-0.5.9 --compose app.yaml \
  --net bridge --net-no-vhost

# retune an existing VM
vmm-cli.py update <vm-id> --net-queues 8 --net-vhost

# stop pinning either value and follow the node and the vCPU count again
vmm-cli.py update <vm-id> --net-queues auto
vmm-cli.py update <vm-id> --net-vhost-default

# stop pinning the backend too, and follow whatever the node runs
vmm-cli.py update <vm-id> --net default
```

Every pin has an un-pin. A VM keeps reporting whatever it pinned, and the
deployment RPC accepts a VM's own held values back even after the node's
policy moves, so a read-modify-write update never strands a VM.

The web UI exposes both per NIC in the deploy and update dialogs, alongside the
networking mode. Both fields are also on `NetworkingConfig` in the deployment
and update RPCs. A request that
sets only `vhost`/`queues` keeps the node's own networking mode, so tuning does
not force a caller to restate — or be allowed to choose — a backend. `queues` is
rejected above the node's `max_net_queues`; `vhost` is not otherwise restricted,
since it only affects the requesting VM. `GetMeta` reports
`networking.max_queues` so a client can present the real bound.

The data plane settings are recorded only when a deployment asks for them.
Leave one out and it stays owned by the node, so changing `[cvm.networking]`
later — including setting `vhost = false` to roll the whole node back — still
reaches VMs deployed with some other networking override.

Naming a backend is different: it pins that NIC's *backend*, resolved at
deployment. Its mode, and the bridge or macvtap parent that names it, are fixed
for the life of the VM, so a later edit to those fields in `[cvm.networking]`
does not move it to another segment. Nothing else is pinned — the MAC prefix,
the user-mode subnet and DHCP start, and the macvtap forwarding mode stay node
settings and are re-read at every launch, so editing them changes every VM's
next boot, including its MAC and therefore its DHCP lease. A request that only
tunes pins nothing at all, including the backend it inherited.

`GetInfo` reports that configuration back, and both `vmm-cli.py update` and the
web UI read it, change one field, and resend the rest. Two things follow. A
request may name a bridge or macvtap parent the node itself configured even when
the allowlists are empty: leaving the field out already yields exactly that
value, so echoing it grants nothing policy was withholding. And an update may
restate whatever its own VM already pinned, so that moving the node's default
out from under a VM does not leave that VM's configuration unsendable. A NIC
that inherited its backend reports an empty mode, which is the same thing it was
deployed with.

Neither field reaches the CVM's measurement. The measured VM configuration the
VMM controls covers the OS image, the vCPU and memory counts, several QEMU
layout flags, the *number* of NICs, and `mr_config_id`; the queue count and the
vhost state are not part of it, so retuning a NIC does not change app identity
or require an on-chain update. Adding or removing a NIC does: the NIC count
changes the guest's ACPI tables and therefore RTMR0.

## Enabling vhost on a node

Setting `vhost = true` in `[cvm.networking]` is a node-wide behaviour change:
every bridge or macvtap VM that has not pinned its own data plane gets a
different virtio-net device on its next boot — `vhost=on`, `mq=on` with
vCPU-scaled queue pairs, and the matching MSI-X vector count. The device is not
measured, so attestation and app identity are unaffected. Before flipping it:

1. **Verify `/dev/vhost-net` is accessible to the account QEMU runs under.**
   It is `root:kvm 0660` on Debian-family hosts, where adding the account to
   the `kvm` group suffices, and `root:root 0600` on several others. If the
   account lacks access, QEMU exits at launch and every affected VM stops
   restarting. The VMM warns at startup when its own access fails, but it
   cannot refuse on that basis — QEMU need not share its credentials.

2. **Restart `netd` before or together with the VMM.** Multiqueue bridge NICs
   are prepared by `netd`, and the VMM checks that `netd` echoes the queue
   count it built. An older `netd` fails that check; the launch is rolled back
   and fails with the reason in the VMM log, but the VM does not start until
   `netd` is upgraded.

3. **Roll back by setting `vhost = false`.** The node value reaches every VM
   that did not pin `vhost` explicitly, from its next boot; a VM that pinned
   `vhost = true` keeps it until updated.

## What each mode supports

| Mode | netdev | vhost | queues > 1 |
|---|---|---|---|
| `user` | `user,...` | no backend | not supported |
| `bridge` | `tap,ifname=` via netd, else `tap,br=,helper=`, else `bridge,br=` | yes | yes, through netd |
| `bridge` with libvirt filtering | `tap,ifname=` | yes | yes, through netd |
| `macvtap` | `tap,fd=` / `tap,fds=` | yes | yes |
| `custom` | operator's own string | operator's own string | no, not settable |

QEMU's `bridge` netdev accepts neither `vhost=` nor `queues=`, so enabling
vhost switches bridge mode to a `tap` netdev driven by the same setuid
`qemu-bridge-helper`. The VMM still needs no network privileges. The helper has
no compiled-in default path for the `tap` netdev, so the VMM probes the known
distribution locations; set `cvm.qemu_bridge_helper` if yours is elsewhere. If
no helper is found the NIC falls back to the non-vhost `bridge` netdev with a
warning, because a node-wide setting must not stop a node from booting VMs
that never asked for it.

The helper returns exactly one descriptor, which is why more than one queue
pair in bridge mode is created by `netd` instead: it adds a persistent
`multi_queue` TAP that QEMU then opens once per queue. `netd` requires the
`virsh` binary to be installed even when nothing is filtered, though it does
not require a reachable `libvirtd`. That applies whether or
not libvirt filtering is on, so a bridge node needs `netd` to get the default
queue count (see [libvirt-network-filter.md](libvirt-network-filter.md)).
Without it, bridge NICs fall back to a single queue pair with a warning rather
than failing to launch; a VM that asked for a queue count explicitly still
fails, so the caller learns their request was not met. `netd` is probed by
connecting, not by looking for its socket file, because a `netd` that died
leaves the socket behind. One-shot `dstack-vmm run` has no netd lifecycle at
all and behaves like a node without it. `netd` reports back the
queue count it created, and the VMM refuses to launch on a mismatch — a `netd`
deployed separately as a root service can be older than the VMM asking it for
multiqueue, and QEMU would otherwise reject the interface from inside the
per-VM launcher.

For macvtap, the per-VM launcher opens the `/dev/tapN` character device once
per queue pair and hands QEMU the descriptors as `fds=`. `netd` creates the
interface with matching `numtxqueues`/`numrxqueues`.

Custom mode owns its whole netdev string, including any `vhost=`/`queues=`
options, and its guest device stays single-queue: the VMM cannot edit that
string, so it has no way to make a multiqueue device line agree with it. For the
same reason `GetInfo` reports no vhost state and no queue count for a custom
NIC, rather than asserting the resolved defaults over a string it never read. A
hand-written multiqueue netdev will not pair with a multiqueue guest device
today.

Naming a backend that cannot carry vhost or a queue count, and then asking for
one, is refused — the request is yours to correct. Inheriting such a backend is
not, because the node chose it and may choose another tomorrow; the request
reads as off, or as one queue pair, until then.

## Choosing a queue count

The default suits bandwidth-bound workloads. Latency-sensitive ones should ask
for fewer: more queues spread receive processing over more vCPUs, and under TDX
a cross-vCPU wakeup costs an IPI and a VM exit. Measured on one 8-vCPU TDX CVM,
changing only the guest's channel count:

| Queue pairs | Short-connection throughput |
|---|---|
| 1 | 22.3k conn/s |
| 2 | ~20k conn/s |
| 4 | 15–21k conn/s |
| 8 | 6.2–7.7k conn/s |

The same CVM with 8 queues moved 3.0 Mpps of 64-byte UDP with no loss, against
roughly 600k with one queue. The trade is real in both directions, so a VM
serving many short connections should set `--net-queues 1` and measure.

A VM with fewer vCPUs than queues leaves the extra pairs idle — `ethtool -l
eth0` reports the smaller number. An explicit over-provision is not rejected at
deployment, because `vmm-cli.py resize` can raise the vCPU count later.

Queue pairs also cost guest memory — each RX ring keeps 256 page-sized buffers
posted, about 1 MB per queue pair plus per-queue NAPI and socket state — but at
any realistic RAM/vCPU shape this is noise. Pushed to a shape no deployment
uses (1 GB of RAM with 16 vCPUs, so 16 queue pairs by default), sustained load
did produce atomic order-0 page-allocation failures in RX refill
(`try_fill_recv` in the guest log); 2 GB at the same shape ran clean. Since the
queue default follows the vCPU count and a VM with that many vCPUs carries far
more memory in practice, this needs no tuning — it is recorded here so the
symptom is searchable. The TDX bounce-buffer pool is not a constraint either:
the guest kernel sizes swiotlb at 6% of RAM clamped to [64 MB, 1 GB] with no
`swiotlb=` parameter, while peak demand is bounded by ring size at about 2 MB
per queue pair — a deliberately undersized 32 MB pool sustained full
multiqueue line rate with zero `swiotlb buffer is full` events.

`vectors` is derived, never configured: `2N + 2`, one vector per queue
direction plus config and control. One queue pair emits no `mq=on` or
`vectors=` at all, leaving the guest device line byte for byte identical to the
one before this feature. The `-netdev` half does change wherever vhost is on,
since that is what selects the backend.

## Requirements

The account running QEMU must be able to open `/dev/vhost-net`, which is
`root:kvm 0660` on a stock host — add that account to the `kvm` group. The
`vhost_net` module autoloads on first open.

`GetInfo` reports the data plane each interface actually got, so a bridge NIC
that fell back for want of a helper reads as `vhost: false` rather than
advertising something it is not using. For a VM that is not running there is no
interface to describe, so it reports what the next launch would build instead --
the same calculation, against the node configuration and manifest as they stand
now, rather than the ones a finished boot ran under.

If that account lacks access, QEMU exits at startup and the VM never boots —
there is no fallback to the userspace backend at this point, on any QEMU
version (verified on 8.2.2 and 10.2). What the per-VM launcher log shows
depends on the version: QEMU 8.2 prints `warning: tap: open vhost char device
failed: Permission denied` (once per queue) and then dies on `net/net.c:1185:
net_client_init1: Assertion 'nc' failed` — an upstream bug
([qemu#1486](https://gitlab.com/qemu-project/qemu/-/issues/1486)); later
versions exit cleanly with `Could not open '/dev/vhost-net'`. Grep for either.
The VMM does not refuse a launch over this: QEMU need not share the VMM's
credentials, so a refusal based on the VMM's own access would block deployments
the host can run. It warns instead — when the device node is missing outright,
and when the VMM's own open is denied, since QEMU usually does share its
account.

QEMU does have a *runtime* fallback, at a different failure point: once the
netdev initialized with vhost, a later `vhost_net_start()` failure at guest
driver activation logs `unable to start vhost net: <errno>: falling back on
userspace virtio` and keeps the NIC working on the userspace data path. That
path is reachable only after `/dev/vhost-net` was opened successfully at
launch, so an access problem never lands there. If it does fire, it is the one
case where `GetInfo` can overstate the data plane — the interface reports the
vhost state the launch settled while the packets take the userspace path — and
that QEMU log line is the indicator.

vhost-net works normally in a TDX guest: the virtio rings and buffers live in
shared, unencrypted memory precisely so a host-side backend can reach them.
This is the same mechanism behind `vhost-vsock-pci`, which dstack has always
used.

On host kernels older than 6.4 the vhost worker is a free-standing kernel
thread: it is attached to the owner's cgroups, so `cpu.max` and cgroup
accounting do apply, but it is outside QEMU's thread group and so invisible to
`top -H` and to anything reading `/proc/<qemu>/task`. Since 6.4 it is a
`vhost_task` inside that thread group and shows up everywhere the VM's other
threads do.
