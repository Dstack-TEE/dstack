# Secure Bridge Networking for dstack VMs

Status: proposed design
Scope: `dstack-vmm` bridge-mode networking
Primary objective: prevent a malicious guest from impersonating another guest,
the host, or the gateway at Layer 2 or Layer 3 without granting the VMM broad
host-network privileges.

## 1. Executive decision

Bridge mode must no longer use QEMU's dynamically named TAP path when strict
isolation is enabled. Each VM NIC must have a host-assigned identity established
before QEMU starts:

```text
VM ID + NIC index
        |
        v
approved bridge + deterministic TAP + unique MAC + reserved IP addresses
        |
        v
bridge-port controls + nftables bridge-ingress enforcement
```

The recommended production design is:

1. The unprivileged VMM selects a network policy and requests a NIC attachment.
2. A small root service, `dstack-netd`, validates the request against its own
   root-owned policy and creates a deterministic TAP on an approved bridge.
3. The host reserves a stable address before boot and publishes a static DHCP
   reservation.
4. `dstack-netd` installs bridge-port controls and nftables bindings before QEMU
   can open the TAP.
5. QEMU uses `-netdev tap,ifname=...,script=no,downscript=no`.
6. Any validation, allocation, TAP, DHCP, or firewall failure rejects VM start.
7. IPv6, VLANs, guest-to-guest traffic, and guest-to-host traffic are denied by
   default unless an explicit administrator policy enables them.

For high-assurance multi-tenant deployments, a routed `/32` per VM is preferable
to a shared bridge because it removes the shared Layer-2 broadcast domain. This
document nevertheless makes bridge mode safe enough for deployments that need
DHCP or Layer-2 compatibility.

## 2. Goals and non-goals

### 2.1 Security goals

The design must enforce all of the following on every protected bridge NIC:

- Ethernet source MAC equals the host-assigned MAC.
- ARP sender hardware address equals that MAC.
- ARP sender IPv4 is either the assigned address or a narrowly defined address
  probe using `0.0.0.0`.
- IPv4 source equals the assigned address, except for a strict DHCP client
  bootstrap exchange.
- A guest cannot act as a DHCP, DHCPv6, IPv6 router-advertisement, or STP server.
- A guest cannot inject VLAN-tagged or unexpected Layer-2 protocols.
- A tenant cannot select an unapproved bridge or switch to an unapproved network
  mode to bypass port-exposure policy.
- A compromised VMM cannot use the privileged networking backend to administer
  arbitrary host interfaces, routes, or firewall tables.
- There is no interval in which a running guest can transmit before enforcement
  is installed.
- VMM or helper restart never converts a protected VM into an unprotected VM.
- Every allocation, rule change, failure, and spoofing drop is attributable to a
  VM and NIC.

### 2.2 Availability and operational goals

- VM restart preserves its MAC and IP reservation.
- Multi-NIC VMs receive an independent identity per NIC.
- Network preparation and cleanup are idempotent.
- A VMM crash does not remove enforcement from running VMs.
- Reconciliation safely removes orphaned resources without touching foreign
  TAPs or firewall tables.
- Policy updates use atomic nftables transactions.
- Operators can deploy in audit mode before enabling strict enforcement.

### 2.3 Non-goals

This design does not:

- trust guest-agent configuration as a security control;
- make a physical or management bridge safe for arbitrary tenant attachment;
- inspect application-layer traffic;
- replace security groups or host service access control;
- provide a complete IPv6 address-management design in the first release;
- protect an operator-trusted raw `custom` QEMU netdev configuration.

## 3. Current implementation and security gaps

### 3.1 Configuration and request path

The current networking configuration is defined by `Networking` in
`dstack/vmm/src/config.rs`. The RPC conversion in
`dstack/vmm/src/main_service.rs` accepts `user` or `bridge` and copies the
requested bridge name. `resolve_networking()` in
`dstack/vmm/src/app/network.rs` allows a non-empty request value to override the
global bridge.

Current bridge validation checks only that the value is non-empty and that
`/sys/class/net/<value>` exists. It does not establish that:

- the value is a valid Linux interface name;
- the interface is a Linux bridge;
- the bridge is approved for tenants;
- bridge mode itself is allowed for the caller or deployment;
- the value is safe to interpolate into a QEMU option string.

The bridge name must therefore be treated as hostile input. Validation must
reject absolute paths, path separators, commas, equals signs, whitespace,
control characters, and names longer than `IFNAMSIZ - 1`. Whether the current
string construction is exploitable as QEMU option injection depends on the
complete path and host configuration; the ambiguity is itself unacceptable and
is removed by typed validation plus allowlisting.

### 3.2 MAC generation

`mac_address_for_vm_index()` derives a stable locally administered unicast MAC
from the VM ID and NIC index, optionally replacing up to three prefix bytes.
This supplies an initial virtio-net address but does not constrain frames emitted
by the guest.

A configured three-byte prefix leaves only 24 derived bits. At large scale MAC
collisions are plausible, so allocation must check uniqueness within the Layer-2
domain and persist the selected address. A collision must cause deterministic
re-derivation with a stored salt or fail allocation; it must never overwrite an
existing static FDB entry.

### 3.3 QEMU bridge backend

Bridge mode currently produces arguments equivalent to:

```text
-netdev bridge,id=net0,br=<bridge>
-device virtio-net-pci,netdev=net0,mac=<derived-mac>
```

QEMU invokes `qemu-bridge-helper`, which creates a dynamically named TAP,
attaches it to the bridge, and passes its file descriptor to QEMU. The VMM does
not know the TAP name before the guest starts and records neither TAP nor guest
IP in its runtime network state.

This prevents a race-free per-port identity policy. The `mac=` device option is
not a security boundary: privileged guest software can change the interface MAC
or emit arbitrary raw Ethernet frames.

### 3.4 Threats in the current shared broadcast domain

A malicious or compromised guest can currently attempt:

- MAC impersonation and bridge FDB poisoning;
- ARP poisoning of peer VMs, the gateway, and the host;
- IPv4 or IPv6 source spoofing;
- rogue DHCP, DHCPv6, router advertisements, and neighbour advertisements;
- STP/BPDU topology attacks;
- VLAN-tagged policy bypass;
- broadcast, multicast, neighbour-discovery, or MAC-churn denial of service;
- direct access to host services bound to the bridge or wildcard addresses;
- lateral traffic to every peer when the bridge forwarding policy permits it;
- attachment to a physical or management bridge when control-plane policy is
  weaker than `/etc/qemu/bridge.conf`.

Bridge mode can also bypass user-mode `restrict` and host port-mapping policy.
Network mode is therefore an authorization decision, not a tenant-selected
transport detail.

## 4. Security invariants and trust boundaries

### 4.1 Per-NIC invariant

For each protected NIC, the control plane persists:

```text
(vm_id, nic_index, policy_id, bridge, tap, mac, ipv4[], ipv6[], generation)
```

The data plane enforces:

```text
ingress port == tap
AND Ethernet source == mac
AND protocol-specific source identity belongs to ipv4[] or ipv6[]
```

No tenant-supplied MAC, TAP name, bridge, or IP becomes authoritative merely
because it appeared in an RPC request or DHCP packet.

### 4.2 Trusted components

- The host administrator and root-owned policy are trusted.
- `dstack-netd` is trusted only for its narrow networking operations.
- The VMM is trusted to request VM lifecycle operations, but is not given general
  `CAP_NET_ADMIN`.
- QEMU and the guest are not trusted to enforce network identity.
- dnsmasq or the configured DHCP authority is trusted to publish reservations,
  not to invent identity independently of the allocator.
- `qemu-bridge-helper` is not used by strict bridge mode.

### 4.3 Privilege containment

`dstack-netd` runs as root under systemd and exposes a Unix socket owned by
`root:dstack-vmm` with mode `0660`. Socket ownership authenticates the VMM
service, but is not sufficient authorization: the daemon validates every field
against its own root-owned configuration and persistent state.

The daemon exposes typed operations, not shell fragments:

```text
PrepareNic(vm_id, nic_index, policy_id, expected_generation) -> NicAttachment
ActivateNic(attachment_id, expected_generation)
QuiesceNic(attachment_id, expected_generation)
RemoveNic(attachment_id, expected_generation)
Reconcile(live_vm_generations) -> ReconcileReport
```

The daemon must not accept:

- arbitrary commands, nftables text, interface names, or executable paths;
- arbitrary bridges, addresses, routes, tables, chains, or sysctls;
- caller-selected TAP names;
- requests outside the configured address pools;
- deletion of resources without the daemon's ownership marker.

It may modify only:

- TAP names generated with the reserved `dst` prefix;
- bridges named by the referenced root-owned policy;
- the dedicated nftables table `bridge dstack_antispoof`;
- DHCP reservation files in a dedicated directory;
- FDB entries and bridge flags on TAPs it owns;
- optional dedicated IP filter sets explicitly defined by policy.

The systemd unit should use hardening such as `NoNewPrivileges`, a restricted
capability bounding set containing only required capabilities, filesystem write
allowlists, syscall filtering where practical, a private temporary directory,
and no network listener other than the Unix socket.

Granting `CAP_NET_ADMIN` to the full VMM is supported only as an explicit
single-tenant compatibility mode and must never be the multi-tenant default. A
custom setuid helper is not recommended because it combines privileged parsing
with a difficult lifecycle and teardown interface.

## 5. Control-plane policy

### 5.1 Root-owned policy

A representative configuration is:

```toml
[cvm.networking]
allowed_modes = ["user", "bridge"]
default_mode = "user"

[[cvm.networking.bridge_policies]]
id = "tenant-nat-v4"
bridge = "dstack-br0"
subnet = "10.0.100.0/24"
gateway = "10.0.100.1"
allocation_range = "10.0.100.10-10.0.100.254"
anti_spoof = "strict"          # disabled | audit | strict
ipv6 = "disabled"              # disabled | static
allow_guest_to_guest = false
allow_guest_to_host = ["dhcp", "dns"]
allow_vlan = false
allow_other_ethertypes = false
arp_rate_per_second = 20
broadcast_rate_per_second = 100
```

Policies, not raw bridge names, should be exposed to callers. If RPC compatibility
requires `bridge_name`, the VMM maps it to exactly one approved policy; arbitrary
host interfaces remain inaccessible.

### 5.2 Validation order

Validation is performed twice: once in the VMM for useful errors and again in
`dstack-netd` for security.

1. Parse the network mode as a closed enum.
2. Authorize the mode for the deployment and caller.
3. Resolve a policy ID; do not trust caller-supplied policy contents.
4. Validate the configured bridge name against
   `[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}`.
5. Verify `/sys/class/net/<name>/bridge` exists.
6. Reject physical, management, Docker, libvirt, or other bridges unless that
   exact interface is intentionally configured.
7. Ensure the address pool excludes network, broadcast, gateway, host services,
   and administrator reservations.
8. Allocate a unique MAC and address under a transactional lock.
9. Reject `custom` mode whenever anti-spoofing is required.

The QEMU process must receive structured, internally generated values only. No
user-controlled string may be concatenated into `-netdev` options.

## 6. Identity allocation

### 6.1 TAP naming

The host generates a deterministic name no longer than 15 bytes, for example:

```text
dst<vm-hash-8>n<index>
```

The hash is derived from the full server-generated VM ID. The daemon checks that
the existing interface, if any, has its ownership alias and expected kind before
reusing or deleting it. It never acts on a same-named foreign interface.

### 6.2 MAC allocation

The existing stable derivation may be retained, with these additions:

- persist the final MAC and derivation salt;
- check uniqueness within the target bridge policy before activation;
- perform allocation while holding the same transaction as IP allocation;
- reject multicast, broadcast, all-zero, gateway, host, and reserved MACs;
- never allow a tenant to override the result.

### 6.3 IPv4 allocation and DHCP

Strict filtering requires the expected address before QEMU starts. The preferred
model is allocator-owned static DHCP reservation:

1. Allocate and persist an address from the policy pool.
2. Write a reservation keyed by the assigned MAC into a dedicated
   `dhcp-hostsdir` directory using write-fsync-rename.
3. Ask the DHCP authority to reload if required.
4. Confirm that the reservation is visible before activating the TAP.
5. Preserve the reservation across VM stop/start; release it only when the VM is
   deleted or the administrator explicitly reallocates it.

Libvirt-backed networks should use an equivalent transactional `net-update`
path. A DHCP lease hook may support legacy installations, but the TAP must begin
in bootstrap-only state and ordinary IPv4 must remain blocked until the trusted
lease event is committed. Learning from `ip neigh`, guest traffic, or an
untrusted DHCP response is not an identity mechanism.

### 6.4 IPv6

The first production release defaults to `ipv6 = "disabled"` and drops all IPv6
from protected TAPs. This avoids partial NDP security that appears safe but still
permits link-local or privacy-address impersonation.

A future `static` policy must allocate exact permitted IPv6 addresses and cover:

- source-address binding;
- duplicate-address detection using source `::` without allowing general use of
  the unspecified address;
- neighbour solicitation and advertisement link-layer option validation;
- rejection of guest router advertisements, redirects, and DHCPv6 server
  packets;
- extension-header and fragmentation behavior;
- multicast requirements and rate limits.

Do not allow all of `fe80::/10` or a shared `/64` as a per-NIC identity rule.

## 7. Data-plane enforcement

### 7.1 Defense layers

Use complementary controls:

1. **Bridge-port controls** prevent FDB learning attacks and optional lateral
   forwarding.
2. **nftables bridge prerouting** validates every frame from a protected TAP,
   including traffic delivered locally to the host.
3. **Host INPUT/FORWARD policy** controls destinations and services after source
   identity is established.
4. **Rate limits and counters** constrain abuse and provide attribution.

L3-only iptables or nftables rules are insufficient because same-subnet ARP and
VM-to-VM traffic may never traverse an IP forwarding hook.

### 7.2 Bridge-port controls

For each protected TAP:

```text
learning off
locked on
mab off
guard on
root_block on
isolated on        # when guest-to-guest is disabled
```

Install exactly one static FDB entry for the assigned MAC. Feature-detect
`locked`; if unsupported, strict mode may rely on the nftables MAC binding, but
must emit a capability warning and record the reduced defense-in-depth state.
It must not silently disable nftables enforcement.

`guard` is required because bridge control frames may be consumed before the
expected netfilter path. Unknown-unicast and multicast flood suppression may be
enabled only after DHCP, neighbour discovery, and operational traffic have been
qualified on supported kernels.

### 7.3 nftables ownership model

`dstack-netd` exclusively owns `table bridge dstack_antispoof`. Static base
chains and maps are installed at service initialization. Per-NIC lifecycle
changes only set elements, preferably in one atomic transaction.

The ingress hook is `prerouting`, not only `forward`, because traffic addressed
to the host bridge must also be validated. Host and uplink ports are untouched;
only daemon-owned protected TAPs enter the strict chain.

A representative IPv4-only policy is below. It is a design template; the
implementation should generate and syntax-check the final ruleset for the
minimum supported nftables version.

```nft
table bridge dstack_antispoof {
    set protected_ports {
        type ifname
    }

    set allowed_mac {
        type ifname . ether_addr
    }

    set allowed_ip4 {
        type ifname . ipv4_addr
    }

    chain ingress {
        type filter hook prerouting priority -300; policy accept;
        iifname @protected_ports jump validate_guest
    }

    chain validate_guest {
        # This check precedes every protocol exception, including DHCP.
        iifname . ether saddr != @allowed_mac counter jump reject_spoof

        ether type arp jump validate_arp
        ether type ip  jump validate_ip4
        ether type ip6 counter jump reject_spoof

        # Reject VLAN, 802.1ad, PPPoE, LLDP, and all unapproved EtherTypes.
        counter jump reject_spoof
    }

    chain validate_arp {
        arp htype != 1 counter jump reject_spoof
        arp ptype != ip counter jump reject_spoof
        arp hlen != 6 counter jump reject_spoof
        arp plen != 4 counter jump reject_spoof
        arp operation != { request, reply } counter jump reject_spoof
        iifname . arp saddr ether != @allowed_mac counter jump reject_spoof

        # RFC 5227 probe: request only, SPA 0.0.0.0, valid outer and inner MAC.
        arp operation request arp saddr ip 0.0.0.0 counter accept
        arp saddr ip 0.0.0.0 counter jump reject_spoof

        iifname . arp saddr ip != @allowed_ip4 counter jump reject_spoof
        limit rate over 20/second burst 50 packets counter jump reject_abuse
        counter accept
    }

    chain validate_ip4 {
        # A client without an address may perform only DHCP bootstrap.
        ip saddr 0.0.0.0 ip daddr 255.255.255.255 \
            udp sport 68 udp dport 67 \
            limit rate 10/second burst 20 packets counter accept

        ip saddr 0.0.0.0 counter jump reject_spoof
        udp sport 67 counter jump reject_spoof
        iifname . ip saddr != @allowed_ip4 counter jump reject_spoof
        counter accept
    }

    chain reject_abuse {
        limit rate 5/minute burst 5 packets log prefix "dstack-net-abuse " level warn
        drop
    }

    chain reject_spoof {
        limit rate 5/minute burst 5 packets log prefix "dstack-net-spoof " level warn
        drop
    }
}
```

Important rule-order properties:

- MAC binding happens before DHCP acceptance.
- ARP inner sender MAC is checked before accepting an address probe.
- `0.0.0.0` is accepted only for an ARP request probe or strict DHCP client
  bootstrap, not for arbitrary IP or ARP replies.
- Rogue DHCP server traffic is rejected.
- IPv6 and all unexpected EtherTypes fail closed.

An implementation may use verdict maps or generated per-port chains if required
by the minimum nftables version. The security behavior, ordering, and atomicity
must remain equivalent.

### 7.4 Guest-to-guest and guest-to-host policy

Source validation does not decide where a valid guest may connect.

- When `allow_guest_to_guest = false`, enable bridge-port isolation and enforce
  an explicit bridge forwarding policy. Do not retain a blanket
  `iifname <bridge> oifname <bridge> accept` rule.
- Host INPUT from protected TAPs defaults to drop. Permit only DHCP, DNS, and
  explicitly configured host services with destination-address and port checks.
- Host FORWARD applies security-group or deployment egress policy after ingress
  identity validation.
- Never attach tenant VMs to the management or physical uplink bridge; use a
  dedicated tenant bridge with routing/NAT at a controlled boundary.

Static permanent neighbour entries may be used as defense in depth for host
traffic, but are not the primary ARP control and must follow the same allocation
lifecycle to avoid stale-address failures.

### 7.5 Resource-abuse controls

Anti-spoofing does not stop a guest from flooding using its valid identity.
Strict policies should additionally provide:

- per-port broadcast, multicast, ARP, and DHCP rate limits;
- optional egress bandwidth policing;
- counters by VM/NIC and rejection reason;
- bounded logging to avoid log-based denial of service;
- alerts for sustained drops, MAC churn attempts, DHCP-server attempts, and
  reconciliation failures.

## 8. Lifecycle and failure semantics

### 8.1 State machine

Each attachment follows an explicit state machine:

```text
Allocated -> Prepared -> Enforced -> Active -> Quiesced -> Removed
                 \            \          \
                  +-----------> Failed <---+
```

Only `Active` attachments may be opened by QEMU. State transitions carry a
monotonic generation to reject stale retries and ABA-style cleanup races.

### 8.2 VM start

The secure order is:

1. Resolve and authorize the root-owned policy.
2. Allocate or load the persisted MAC and IP identity.
3. Publish and confirm the DHCP reservation.
4. Create the TAP down, set ownership and an ownership alias.
5. Attach it to the approved bridge while no QEMU process holds it.
6. Configure port flags and the static FDB entry.
7. Atomically install all nftables set elements.
8. Bring the TAP up and return the generated QEMU configuration.
9. Persist the attachment generation in runtime state.
10. Start QEMU with the exact generated TAP name.

If any step fails, QEMU is not started. Rollback first keeps or sets the TAP down,
then removes policy state and daemon-owned resources. Allocation records are
released only according to VM create/delete semantics, not merely because a boot
attempt failed.

### 8.3 VM stop and delete

The secure stop order is:

1. Stop QEMU and confirm it no longer holds the TAP.
2. Set the TAP down and detach it from the bridge.
3. Atomically remove nftables elements and the static FDB entry.
4. Delete the daemon-owned TAP.
5. Mark the attachment removed.
6. Preserve MAC/IP/DHCP reservation on stop; release it only on VM deletion.

There is never a phase where an attached, guest-controlled TAP is up after its
source-validation rules have been removed.

### 8.4 Crash recovery and reconciliation

Firewall state and persistent TAPs survive a VMM crash, so running guests remain
protected. On restart:

1. Load VM runtime generations and allocator state.
2. Ask `dstack-netd` for daemon-owned attachments and enforcement elements.
3. Cross-check TAP kind, alias, bridge, MAC, IP, FDB, flags, and nftables state.
4. For a running VM with incomplete enforcement, immediately set the TAP down or
   stop the VM before attempting repair.
5. Repair missing state only from persisted authoritative identity.
6. Quiesce and remove confirmed orphan attachments after a configurable safety
   interval.
7. Never delete unknown interfaces or nftables objects outside the dedicated
   namespace.

If reconciliation cannot prove that a running attachment is protected, the
system fails closed and raises a high-severity operational alert.

### 8.5 Concurrent operations

Create, update, stop, delete, and reconcile may race. The implementation needs:

- a per-VM lifecycle lock;
- a bridge-policy allocation lock;
- attachment generations/idempotency keys;
- atomic allocator persistence;
- atomic nftables updates;
- compare-and-delete semantics so an old cleanup cannot remove a new attachment.

A network-policy update that changes bridge, MAC, or IP is a replace operation,
not an in-place mutation of an active identity.

## 9. API and persistence changes

### 9.1 VMM configuration

Add closed, typed configuration for:

- allowed network modes;
- bridge policy definitions;
- anti-spoofing mode: `disabled`, `audit`, or `strict`;
- IPv4 pool and DHCP integration;
- IPv6 policy;
- guest-to-guest and guest-to-host access;
- privileged backend socket and timeout;
- rate limits and feature requirements.

Bridge anti-spoofing should default to `strict` for new multi-tenant deployments.
Legacy installations must opt into an explicitly named unsafe compatibility mode
rather than silently falling back.

### 9.2 Runtime state

Persist at least:

```json
{
  "vm_id": "...",
  "nic_index": 0,
  "policy_id": "tenant-nat-v4",
  "attachment_id": "...",
  "generation": 3,
  "tap": "dst1234abcdn0",
  "bridge": "dstack-br0",
  "mac": "02:aa:bb:cc:dd:ee",
  "ipv4": ["10.0.100.20"],
  "ipv6": [],
  "enforcement": "strict"
}
```

State files must be root/VMM-owned as appropriate, written atomically, and must
not accept guest modifications as authoritative. `vm_info` may expose identity,
policy, enforcement status, and counters to authorized operators without
exposing unrelated host configuration.

### 9.3 Backward compatibility

- `user` networking remains unchanged.
- Existing unprotected `bridge` mode is renamed or represented as
  `anti_spoof = "disabled"` and emits a prominent warning.
- Strict mode refuses `custom` netdev.
- Existing bridge-name RPC fields may be mapped to approved policies during a
  deprecation period.
- The deployment script must not install blanket bridge-to-bridge accept rules
  that override the new isolation policy.

## 10. Alternatives

| Alternative | Decision | Reason |
|---|---|---|
| Guest-agent enforcement | Reject | Guest workloads and raw-frame capability are untrusted. |
| QEMU `mac=` only | Reject | It configures an initial address but does not filter frames. |
| L3 iptables/nftables only | Reject | It cannot stop ARP or same-bridge Layer-2 attacks. |
| Dynamic TAP discovery after QEMU starts | Reject | It creates a first-packet race and ambiguous ownership. |
| Full VMM `CAP_NET_ADMIN` | Compatibility only | Excessive blast radius for a tenant-facing service. |
| Custom setuid helper | Not recommended | Narrow code is possible, but parsing and lifecycle cleanup remain high risk. |
| ebtables/libvirt nwfilter | Compatibility option | Proven model, but legacy tooling and integration complexity are less attractive than nftables. |
| tc/eBPF ingress | Future option | Powerful and scalable, but increases verifier, program, map, and observability complexity. |
| Open vSwitch/OVN | Reject for current scope | Strong capabilities but disproportionate operational complexity. |
| macvtap | Reject as anti-spoof solution | Does not establish IP/ARP identity by itself. |
| Routed `/32` TAP | Preferred high-assurance mode | Removes the shared L2 domain; requires different DHCP/routing integration. |

## 11. Rollout plan

### Phase 0: close control-plane escapes

- Add `allowed_modes` and bridge policies.
- Validate interface names and verify bridge type.
- Reject raw or unapproved bridge values.
- Check MAC uniqueness.
- Add explicit guest-to-host INPUT policy.
- Remove unconditional intra-bridge forwarding.
- Document `custom` and legacy bridge mode as trusted/unsafe.

These controls should ship independently because they reduce severe risk without
waiting for the complete per-port implementation.

### Phase 1: deterministic TAP and MAC enforcement

- Implement and harden `dstack-netd`.
- Pre-create deterministic TAPs.
- Change QEMU to `-netdev tap`.
- Install bridge flags, static FDB, MAC binding, EtherType allowlist, rogue DHCP,
  RA, BPDU, and VLAN controls.
- Implement lifecycle generations, rollback, and reconciliation.

### Phase 2: IPAM and ARP/IPv4 enforcement

- Add transactional address allocation.
- Integrate static DHCP reservations.
- Enable strict ARP and IPv4 bindings.
- Add audit-to-strict migration tooling and per-VM counters.

### Phase 3: hardening and optional features

- Add resource-abuse policing and alerts.
- Add security groups.
- Implement fully specified static IPv6 if required.
- Add the routed `/32` mode for high-assurance multi-tenant deployments.
- Benchmark nftables set/map scaling and data-plane performance.

## 12. Test and acceptance plan

### 12.1 Functional security tests

For two test guests on the same bridge, strict mode must demonstrate:

1. Assigned DHCP and normal IPv4 connectivity work.
2. Changing the guest interface MAC does not transmit traffic.
3. Raw frames with another VM, gateway, host, multicast, or broadcast source MAC
   are dropped.
4. ARP replies claiming another VM or gateway IPv4 are dropped.
5. ARP with correct outer MAC but forged inner sender MAC is dropped.
6. RFC 5227 request probes with valid MAC and SPA `0.0.0.0` work; replies with
   SPA `0.0.0.0` do not.
7. Packets using another VM, gateway, host, pool, or external spoofed IPv4 source
   are dropped.
8. DHCP discover/request works only with the assigned Ethernet source MAC.
9. DHCP server offers from a guest are dropped.
10. IPv6, RA, NDP, redirects, and DHCPv6 are dropped when IPv6 is disabled.
11. 802.1Q, 802.1ad, PPPoE, LLDP, and unexpected EtherTypes are dropped.
12. BPDU injection cannot alter bridge topology.
13. Guest-to-guest traffic is denied by default and works only after explicit
    policy authorization.
14. Guest-to-host traffic reaches only explicitly allowed host services.
15. Broadcast, ARP, and DHCP floods are rate-limited without unbounded logs.

### 12.2 Control-plane and failure tests

- Reject absolute, overlong, comma-containing, equals-containing, whitespace,
  non-bridge, and non-allowlisted bridge values.
- Reject disallowed network modes and strict `custom` mode.
- Detect and safely handle MAC/IP allocation collisions.
- Simulate failure at every start step; QEMU must not run with an unprotected
  attached TAP.
- Kill VMM and `dstack-netd` at every lifecycle transition and verify recovery.
- Corrupt or remove one FDB, flag, set element, reservation, or runtime record;
  reconciliation must quiesce or correctly repair the attachment.
- Race start/stop/delete/update/reconcile and verify generation safety.
- Verify an old cleanup request cannot remove a newer attachment.
- Verify the daemon refuses arbitrary interfaces, bridges, tables, chains,
  addresses, and deletions.
- Verify a same-named foreign TAP is never modified.
- Verify multi-NIC and concurrent allocation uniqueness.

### 12.3 Compatibility and performance tests

- Supported kernels and nftables versions load the generated ruleset.
- Unsupported bridge-port features follow the documented strict fallback.
- dnsmasq and libvirt reservation updates do not disrupt existing VMs.
- VM stop/start preserves identity; VM deletion releases it.
- Rule-set update time and packet throughput meet defined fleet targets at the
  maximum supported VM/NIC count.
- Counters and logs identify the correct VM/NIC without leaking unrelated tenant
  information.

### 12.4 Release acceptance criteria

Strict bridge mode is releasable only when:

- all functional security tests pass;
- all lifecycle failure injection tests pass;
- VMM runs without broad `CAP_NET_ADMIN` in the default deployment;
- no tenant-provided string reaches QEMU network option construction;
- helper authorization is independently tested against a compromised-VMM model;
- startup is demonstrably fail-closed;
- reconciliation quiesces any attachment whose protection cannot be proven;
- legacy unsafe behavior requires explicit administrator opt-in;
- operational documentation includes rollback, alert response, and recovery.

## 13. Recommended implementation boundary

The implementation should be split into independently reviewable changes:

1. Control-plane validation and policy authorization.
2. Persistent NIC identity and collision-safe IPAM.
3. `dstack-netd` protocol, authorization, and systemd hardening.
4. Deterministic TAP QEMU backend and lifecycle integration.
5. Bridge-port and nftables enforcement.
6. DHCP reservation integration.
7. Reconciliation, observability, and failure injection tests.
8. Optional routed and IPv6 modes.

Each change should preserve a closed security invariant. Do not land a state in
which strict mode is advertised but silently runs without one of its required
enforcement layers.
