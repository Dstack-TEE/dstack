// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! VM network resolution, validation, and interface identity.

use std::path::Path;

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

use super::{Manifest, PortMapping};
use crate::config::{
    CvmConfig, NetdInterface, NetworkFilterMode, Networking, NetworkingMode, NicNetworking,
    MAX_NET_QUEUES,
};

/// Node configuration merged with what one NIC pins.
///
/// The node half is taken wholesale and the NIC half overrides it where it is
/// set. Nothing the node owns -- the macvtap forwarding mode, the MAC prefix,
/// the user-mode network parameters, a custom netdev string -- can be
/// overridden here any more, because a [`NicNetworking`] cannot carry one.
pub(crate) fn resolve_networking(
    networking: &NicNetworking,
    cfg: &CvmConfig,
    vcpu: u32,
) -> Networking {
    let mut resolved = cfg.networking.clone();
    // A deployment that only tuned the data plane never named a backend, so
    // the node keeps deciding which one this NIC uses -- including after the
    // operator changes it.
    resolved.nic.inherit_mode = networking.inherit_mode;
    resolved.nic.mode = if networking.inherit_mode {
        cfg.networking.nic.mode
    } else {
        networking.mode
    };
    // Runtime state, never inherited from configuration or from a previous
    // launch. Interface preparation sets both for the NICs it builds, and a
    // node configuration that names either is rejected at startup.
    resolved.netd_interface = crate::config::NetdInterface::None;
    resolved.device.clear();
    if !networking.bridge.is_empty() {
        resolved.nic.bridge = networking.bridge.clone();
    }
    if !networking.parent.is_empty() {
        resolved.nic.parent = networking.parent.clone();
    }
    if networking.vhost.is_some() {
        resolved.nic.vhost = networking.vhost;
    }
    // Make the vCPU-scaled default concrete here, so every later stage --
    // netd preparation, the QEMU arguments, and removal after a VMM restart --
    // reads one number instead of recomputing it from a vCPU count it may no
    // longer have.
    resolved.nic.queues = Some(match networking.queues {
        // An explicit count is honoured whatever the data plane: multiqueue
        // without vhost is a valid, if unusual, thing to ask for.
        Some(queues) => queues,
        // Without vhost the QEMU main loop drains every queue on one thread,
        // so scaling up buys almost nothing while still costing a netd
        // interface, extra vectors, and a changed device. Anyone turning vhost
        // off is asking for the old data plane; give them the old shape too.
        None if resolved.vhost_enabled() => {
            Networking::default_queue_pairs(vcpu, cfg.max_net_queues)
        }
        None => 1,
    });
    resolved
}

pub(crate) fn resolved_networks(manifest: &Manifest, cfg: &CvmConfig) -> Vec<Networking> {
    let node_default = [cfg.networking.nic.clone()];
    let requested = if manifest.networks.is_empty() {
        &node_default[..]
    } else {
        &manifest.networks[..]
    };
    requested
        .iter()
        .map(|networking| resolve_networking(networking, cfg, manifest.vcpu))
        .collect()
}

/// Whether netd must pre-create the host interface for this NIC.
///
/// Every macvtap and every bridge NIC. The alternative was a set of conditions
/// -- libvirt filtering, multiqueue -- under which netd was consulted and
/// outside of which the VMM built the interface some other way. Each of those
/// paths had to answer the same questions again and answer them differently:
/// which netdev QEMU gets, whether vhost is really on, and, once port mappings
/// grew a NIC, where a bridge NIC's host ports go. A host interface has one
/// owner now, and `port_map` on a bridge reaches netd on every node rather than
/// only on the ones that happened to filter or to have scaled their queues.
///
/// The cost is stated plainly: bridge and macvtap need a netd on the host. User
/// mode and a caller-supplied netdev still need nothing.
pub(crate) fn needs_netd_interface(networking: &Networking) -> bool {
    matches!(
        networking.nic.mode,
        NetworkingMode::Macvtap | NetworkingMode::Bridge
    )
}

/// Whether this NIC's host interface carries a libvirt nwfilter binding.
/// Macvtap never does, and a bridge NIC only does when the node filters.
pub(crate) fn filters_bridge_traffic(networking: &Networking, cfg: &CvmConfig) -> bool {
    networking.nic.mode == NetworkingMode::Bridge
        && cfg.network_filter.mode == NetworkFilterMode::Libvirt
}

/// Whether netd built this NIC's host interface, and if so whether it carries
/// an nwfilter binding.
///
/// Interface preparation records this, because it is not derivable afterwards:
/// an operator can change `network_filter.mode` or `max_net_queues` while a VM
/// runs, and teardown has to undo what was built rather than what would be
/// built now.
pub(crate) fn netd_teardown(networking: &Networking, cfg: &CvmConfig) -> Option<bool> {
    match networking.netd_interface {
        NetdInterface::Filtered => Some(true),
        NetdInterface::Unfiltered => Some(false),
        // Either nothing was built, or this entry was persisted before
        // preparation recorded the fact. Fall back to the derivation such an
        // entry was created by; a Remove for an interface that does not exist
        // is a no-op.
        NetdInterface::None if needs_netd_interface(networking) => {
            Some(filters_bridge_traffic(networking, cfg))
        }
        NetdInterface::None => None,
    }
}

/// Makes the data plane concrete on a launch-time NIC list.
///
/// `vhost` on a freshly resolved entry is still a *request*: `None` means
/// inherit from the node, which can change under a VM that is already running.
/// Settling it once, here, is what lets the QEMU arguments and the reported
/// status read the same value for the life of a boot.
pub(crate) fn settle_vhost(networks: &mut [Networking]) {
    for networking in networks.iter_mut() {
        networking.nic.vhost = Some(networking.vhost_enabled());
    }
}

pub(crate) fn validate_resolved_network(networking: &Networking) -> Result<()> {
    // The vCPU-scaled default is bounded by construction; only an explicit
    // request can exceed the hard cap.
    if networking
        .nic
        .queues
        .is_some_and(|queues| queues > MAX_NET_QUEUES)
    {
        bail!("networking queues must not exceed {MAX_NET_QUEUES}");
    }
    if networking.nic.mode != NetworkingMode::Bridge {
        return Ok(());
    }
    if networking.nic.bridge.is_empty() {
        bail!("bridge networking requested but no bridge is configured");
    }
    if !Path::new("/sys/class/net")
        .join(&networking.nic.bridge)
        .exists()
    {
        bail!(
            "bridge interface '{}' does not exist",
            networking.nic.bridge
        );
    }
    Ok(())
}

pub(crate) fn validate_resolved_networks(networks: &[Networking]) -> Result<()> {
    for networking in networks {
        validate_resolved_network(networking)?;
    }
    Ok(())
}

/// Warns when a vhost NIC is about to launch on a host that has no
/// `/dev/vhost-net` at all.
///
/// QEMU exits when `vhost=on` cannot open the device, and it does so from
/// inside the per-VM launcher where the reason is easy to miss. This puts the
/// remediation in the VMM log instead.
///
/// Both checks are warnings, never refusals. QEMU is not necessarily this
/// process — an externally started supervisor can run it under another account
/// — so neither answers the question that decides the launch. They are the two
/// cheap statements that catch the two ways this actually goes wrong.
///
/// The permission check matters because the node's mode is not uniform. It is
/// `root:kvm 0660` on Debian-family hosts, where a VMM in the `kvm` group is
/// fine, and `root:root 0600` on several others — where every bridge VM stops
/// restarting after an upgrade turns vhost on node-wide, with the only
/// explanation buried in a per-VM launcher's QEMU output. Existence alone says
/// nothing about that case, which is the likelier of the two.
pub(crate) fn warn_if_vhost_net_missing(networks: &[Networking]) {
    const VHOST_NET: &str = "/dev/vhost-net";
    if !networks.iter().any(Networking::vhost_enabled) {
        return;
    }
    // The node is a kmod static device node, so it is present even before
    // vhost_net is loaded; QEMU's open autoloads the module.
    if !Path::new(VHOST_NET).exists() {
        tracing::warn!(
            "{VHOST_NET} is missing; vhost networking will fail to start. load the vhost_net \
             module, or set vhost = false in [cvm.networking]"
        );
        return;
    }
    if let Err(error) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(VHOST_NET)
    {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            tracing::warn!(
                "{VHOST_NET} is not accessible to this process; if QEMU runs under the same \
                 account, vhost networking will fail to start. add that account to the device's \
                 group, or set vhost = false in [cvm.networking]"
            );
        }
    }
}

/// Which NIC an unpinned port mapping's traffic enters through.
///
/// The first user-mode NIC, because that is where QEMU's `hostfwd=` entries
/// have always gone and existing VMs must keep behaving the same way; failing
/// that the first bridge NIC, which is the only other backend with a path into
/// the guest. `macvtap` bypasses the host bridge and `custom` owns its own
/// netdev string, so neither can carry one.
pub(crate) fn default_ingress_nic(networks: &[Networking]) -> Option<usize> {
    networks
        .iter()
        .position(|network| network.nic.mode == NetworkingMode::User)
        .or_else(|| {
            networks
                .iter()
                .position(|network| network.nic.mode == NetworkingMode::Bridge)
        })
}

/// Whether a NIC of this mode has a mechanism to publish a host port at all.
///
/// `hostfwd=` for user mode and netd for a bridge. Macvtap bypasses the host
/// bridge and a custom netdev is a string the VMM does not interpret, so
/// neither has anywhere to put one. Naming one of those is refused at
/// deployment rather than resolved to nothing here.
pub(crate) fn mode_carries_ingress(mode: NetworkingMode) -> bool {
    matches!(mode, NetworkingMode::User | NetworkingMode::Bridge)
}

/// Which NIC a port mapping's traffic enters through.
///
/// One mapping resolves to at most one NIC, and that NIC's backend decides the
/// mechanism: `hostfwd=` for user mode, netd for a bridge. That is what keeps
/// QEMU and netd from both claiming one host port.
///
/// `None` is a mapping with nowhere to go. Deployment refuses every way of
/// asking for one, so reaching it means a manifest wrote a NIC out from under a
/// mapping that named it; the launch says so rather than dropping it in
/// silence.
pub(crate) fn ingress_nic(mapping: &PortMapping, networks: &[Networking]) -> Option<usize> {
    mapping
        .nic_index
        .or_else(|| default_ingress_nic(networks))
        .filter(|index| {
            networks
                .get(*index)
                .is_some_and(|network| mode_carries_ingress(network.nic.mode))
        })
}

/// Names the mappings that resolve to no NIC, for a launch to warn about.
pub(crate) fn stranded_ingress<'a>(
    port_map: &'a [PortMapping],
    networks: &'a [Networking],
) -> impl Iterator<Item = &'a PortMapping> {
    port_map
        .iter()
        .filter(|mapping| ingress_nic(mapping, networks).is_none())
}

/// The host ports one NIC carries, as netd requests.
pub(crate) fn ingress_for(
    port_map: &[PortMapping],
    networks: &[Networking],
    nic_index: usize,
) -> Vec<crate::netd::IngressRequest> {
    port_map
        .iter()
        .filter(|mapping| ingress_nic(mapping, networks) == Some(nic_index))
        .map(|mapping| crate::netd::IngressRequest {
            protocol: mapping.protocol.as_str().to_string(),
            host_address: mapping.address.to_string(),
            host_port: mapping.from,
            guest_port: mapping.to,
        })
        .collect()
}

/// Derives a deterministic, locally administered unicast MAC address.
///
/// Index zero preserves the legacy single-NIC derivation. Later interfaces
/// hash `vm_id:index`, preventing an upgrade from changing the primary NIC.
pub(crate) fn mac_address_for_vm_index(vm_id: &str, prefix: &[u8], index: usize) -> String {
    let hash_input = if index == 0 {
        vm_id.to_string()
    } else {
        format!("{vm_id}:{index}")
    };
    let hash = Sha256::digest(hash_input.as_bytes());
    let prefix_len = prefix.len().min(3);
    let mut bytes = [0_u8; 6];
    bytes[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
    for index in prefix_len..bytes.len() {
        bytes[index] = hash[index - prefix_len];
    }
    bytes[0] = (bytes[0] & 0xfe) | 0x02;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

#[cfg(test)]
mod tests {
    use super::{
        default_ingress_nic, ingress_for, ingress_nic, mac_address_for_vm_index,
        needs_netd_interface, netd_teardown, resolve_networking, resolved_networks, settle_vhost,
        stranded_ingress, validate_resolved_networks,
    };
    use crate::app::PortMapping;
    use crate::config::Protocol;
    use crate::config::{Networking, NetworkingMode, NicNetworking};

    fn macvtap_network() -> NicNetworking {
        NicNetworking {
            mode: NetworkingMode::Macvtap,
            parent: "eth0".into(),
            // Most tests here exercise the vhost data plane, which the
            // shipped default leaves off; opt in the way a real node would.
            vhost: Some(true),
            ..NicNetworking::default()
        }
    }

    /// The same NIC as a resolved value, for the checks that run against what
    /// a launch would see rather than against what a VM pins.
    fn macvtap_resolved() -> Networking {
        Networking {
            nic: macvtap_network(),
            ..Networking::default()
        }
    }

    fn node_config(mode: NetworkingMode) -> crate::config::CvmConfig {
        use rocket::figment::providers::Format as _;
        let config: crate::config::Config = rocket::figment::Figment::from(
            rocket::figment::providers::Toml::string(crate::config::DEFAULT_CONFIG),
        )
        .extract()
        .unwrap();
        let mut cvm = config.cvm;
        cvm.networking.nic.mode = mode;
        cvm.networking.nic.bridge = "br0".into();
        cvm.networking.nic.parent = "eth0".into();
        // The shipped default leaves vhost off; the tests here are about the
        // vhost data plane, so this node opts in the way a real one would.
        cvm.networking.nic.vhost = Some(true);
        cvm
    }

    /// A node whose configuration never names `vhost` — the upgrade case,
    /// where the toml predates the key entirely.
    fn unconfigured_vhost_node(mode: NetworkingMode) -> crate::config::CvmConfig {
        let mut cvm = node_config(mode);
        cvm.networking.nic.vhost = None;
        cvm
    }

    fn manifest_with(vcpu: u32, networks: Vec<NicNetworking>) -> crate::app::Manifest {
        let mut manifest: crate::app::Manifest = serde_json::from_value(serde_json::json!({
            "id": "vm-1", "name": "n", "app_id": "a", "vcpu": vcpu, "memory": 2048,
            "disk_size": 10, "image": "i", "port_map": [], "created_at_ms": 0,
        }))
        .unwrap();
        manifest.networks = networks;
        manifest
    }

    #[test]
    fn queue_pairs_default_to_the_vcpu_count_up_to_the_cap() {
        let cvm = node_config(NetworkingMode::Bridge);
        for (vcpu, want) in [(1, 1), (2, 2), (8, 8), (16, 16), (32, 16), (128, 16)] {
            let resolved = resolved_networks(&manifest_with(vcpu, vec![]), &cvm);
            assert_eq!(
                resolved[0].queue_pairs(),
                want,
                "vcpu {vcpu} should give {want} queue pairs"
            );
        }
    }

    /// An upgraded node must keep building the device its VMs have always
    /// had: userspace virtio, one queue pair. Both the toml that predates the
    /// `vhost` key and the shipped default say so.
    #[test]
    fn a_node_that_never_asked_for_vhost_keeps_the_old_device_shape() {
        let shipped = {
            use rocket::figment::providers::Format as _;
            let config: crate::config::Config = rocket::figment::Figment::from(
                rocket::figment::providers::Toml::string(crate::config::DEFAULT_CONFIG),
            )
            .extract()
            .unwrap();
            config.cvm.networking.nic.vhost
        };
        for vhost in [None, shipped] {
            let mut cvm = unconfigured_vhost_node(NetworkingMode::Bridge);
            cvm.networking.nic.vhost = vhost;
            let resolved = resolved_networks(&manifest_with(16, vec![]), &cvm);
            assert!(!resolved[0].vhost_enabled());
            assert_eq!(resolved[0].queue_pairs(), 1);
        }
    }

    #[test]
    fn turning_vhost_off_also_turns_off_the_multiqueue_default() {
        let mut cvm = node_config(NetworkingMode::Bridge);
        cvm.networking.nic.vhost = Some(false);
        let resolved = resolved_networks(&manifest_with(8, vec![]), &cvm);
        assert!(!resolved[0].vhost_enabled());
        assert_eq!(resolved[0].queue_pairs(), 1);

        // Per-VM opt-out does the same thing.
        let cvm = node_config(NetworkingMode::Bridge);
        let mut asked = cvm.networking.nic.clone();
        asked.vhost = Some(false);
        let resolved = resolved_networks(&manifest_with(8, vec![asked]), &cvm);
        assert_eq!(resolved[0].queue_pairs(), 1);

        // But an explicit queue count is still honoured without vhost.
        let mut asked = cvm.networking.nic.clone();
        asked.vhost = Some(false);
        asked.queues = Some(4);
        let resolved = resolved_networks(&manifest_with(8, vec![asked]), &cvm);
        assert!(!resolved[0].vhost_enabled());
        assert_eq!(resolved[0].queue_pairs(), 4);
    }

    #[test]
    fn lowering_the_request_ceiling_also_lowers_the_default() {
        let mut cvm = node_config(NetworkingMode::Bridge);
        cvm.max_net_queues = 2;
        let resolved = resolved_networks(&manifest_with(16, vec![]), &cvm);
        assert_eq!(resolved[0].queue_pairs(), 2);

        // Raising it past the scaling cap widens requests, not the default.
        cvm.max_net_queues = 32;
        let resolved = resolved_networks(&manifest_with(24, vec![]), &cvm);
        assert_eq!(resolved[0].queue_pairs(), 16);
    }

    /// One owner for a host interface, with no condition attached. What used
    /// to decide this -- libvirt filtering, a scaled queue count -- decided it
    /// per node, so the same VM definition got a netd-built TAP on one host and
    /// a `qemu-bridge-helper` TAP on the next.
    #[test]
    fn every_bridge_and_macvtap_nic_is_netds_to_build() {
        let mut cvm = node_config(NetworkingMode::Bridge);
        let mut single = cvm.networking.nic.clone();
        single.queues = Some(1);
        let resolved = resolved_networks(&manifest_with(8, vec![single.clone()]), &cvm);
        assert!(needs_netd_interface(&resolved[0]));

        // Unfiltered, single queue, no vhost -- the shape that used to need no
        // netd at all -- is netd's too.
        cvm.networking.nic.vhost = Some(false);
        single.vhost = Some(false);
        let resolved = resolved_networks(&manifest_with(8, vec![single]), &cvm);
        assert!(!resolved[0].vhost_enabled());
        assert_eq!(resolved[0].queue_pairs(), 1);
        assert!(needs_netd_interface(&resolved[0]));

        let cvm = node_config(NetworkingMode::Macvtap);
        let resolved = resolved_networks(&manifest_with(8, vec![]), &cvm);
        assert!(needs_netd_interface(&resolved[0]));

        // The two backends the VMM builds itself still need nothing.
        for mode in [NetworkingMode::User, NetworkingMode::Custom] {
            let cvm = node_config(mode);
            let resolved = resolved_networks(&manifest_with(8, vec![]), &cvm);
            assert!(!needs_netd_interface(&resolved[0]));
        }
    }

    #[test]
    fn an_explicit_queue_count_survives_resolution() {
        let cvm = node_config(NetworkingMode::Bridge);
        let mut asked = macvtap_network();
        asked.mode = NetworkingMode::Bridge;
        asked.queues = Some(2);
        let resolved = resolved_networks(&manifest_with(16, vec![asked]), &cvm);
        assert_eq!(resolved[0].queue_pairs(), 2);
    }

    #[test]
    fn user_mode_stays_single_queue_whatever_the_vcpu_count() {
        let cvm = node_config(NetworkingMode::User);
        let resolved = resolved_networks(&manifest_with(32, vec![]), &cvm);
        assert_eq!(resolved[0].queue_pairs(), 1);
    }

    #[test]
    fn validation_never_depends_on_this_process_reaching_vhost_net() {
        // QEMU may run under different credentials, so a NIC that asks for
        // vhost must validate on hosts where the VMM itself cannot open the
        // device. Both of these hold whether or not /dev/vhost-net exists here.
        let mut networking = macvtap_resolved();
        assert!(networking.vhost_enabled());
        validate_resolved_networks(&[networking.clone()]).unwrap();

        networking.nic.queues = Some(4);
        validate_resolved_networks(&[networking]).unwrap();
    }

    #[test]
    fn queue_counts_above_the_hard_bound_are_rejected() {
        let mut networking = macvtap_resolved();
        networking.nic.queues = Some(super::MAX_NET_QUEUES + 1);
        let error = validate_resolved_networks(&[networking]).unwrap_err();
        assert!(error.to_string().contains("must not exceed"));
    }

    /// The data plane a NIC actually gets is decided once, at launch, and
    /// written into the runtime entry. Recomputing it later would let a report
    /// about a running VM change under an operator's edit to node
    /// configuration, describing a data plane QEMU is not using.
    #[test]
    fn settling_vhost_records_what_the_launch_decided() {
        let mut cvm = node_config(NetworkingMode::Bridge);
        let manifest = manifest_with(8, vec![]);
        let mut networks = resolved_networks(&manifest, &cvm);
        assert_eq!(networks[0].nic.vhost, Some(true));
        settle_vhost(&mut networks);
        assert_eq!(networks[0].nic.vhost, Some(true));

        // The node turns vhost off under a VM that is already running. The
        // entry the launch settled keeps its answer; the next boot gets the
        // new one.
        cvm.networking.nic.vhost = Some(false);
        assert_eq!(networks[0].nic.vhost, Some(true));
        let mut next_boot = resolved_networks(&manifest, &cvm);
        settle_vhost(&mut next_boot);
        assert_eq!(next_boot[0].nic.vhost, Some(false));

        // An inherited `None` becomes a decision rather than staying a request.
        let mut unset = resolved_networks(&manifest, &cvm);
        unset[0].nic.vhost = None;
        settle_vhost(&mut unset);
        assert_eq!(unset[0].nic.vhost, Some(false));
    }

    /// Teardown has to undo what was built. Node configuration is mutable and
    /// a VM outlives an edit to it, so re-deriving "did netd build this?" at
    /// removal time orphans TAPs and leaks nwfilter bindings whose ebtables
    /// rules the next VM at the same deterministic interface name inherits.
    #[test]
    fn teardown_follows_what_was_built_not_what_configuration_now_says() {
        use crate::config::{NetdInterface, NetworkFilterMode};

        let filtering = {
            let mut cvm = node_config(NetworkingMode::Bridge);
            cvm.network_filter.mode = NetworkFilterMode::Libvirt;
            cvm
        };
        let unfiltered = node_config(NetworkingMode::Bridge);

        let mut built_filtered = filtering.networking.clone();
        built_filtered.nic.queues = Some(1);
        built_filtered.netd_interface = NetdInterface::Filtered;
        // The operator turns filtering off while the VM runs. The binding is
        // still there and still has to be deleted.
        assert_eq!(netd_teardown(&built_filtered, &unfiltered), Some(true));

        let mut built_unfiltered = unfiltered.networking.clone();
        built_unfiltered.nic.queues = Some(4);
        built_unfiltered.netd_interface = NetdInterface::Unfiltered;
        // The operator turns filtering on. There is no binding to delete, and
        // asking libvirt for one would fail the removal.
        assert_eq!(netd_teardown(&built_unfiltered, &filtering), Some(false));

        // A backend netd never builds stays untouched, whatever the node says.
        let mut untouched = unfiltered.networking.clone();
        untouched.nic.mode = NetworkingMode::User;
        untouched.nic.queues = Some(1);
        assert_eq!(netd_teardown(&untouched, &unfiltered), None);

        // A bridge NIC with no record is netd's by derivation, because netd is
        // now the only thing that could have built it. Teardown deletes by
        // deriving names, so being wrong about a VM from an older build costs
        // a sweep that finds nothing.
        let mut unrecorded = unfiltered.networking.clone();
        unrecorded.nic.queues = Some(1);
        assert_eq!(unrecorded.netd_interface, NetdInterface::None);
        assert_eq!(netd_teardown(&unrecorded, &unfiltered), Some(false));

        // An entry persisted before preparation recorded the fact still gets
        // torn down by the rule that created it.
        let mut legacy = filtering.networking.clone();
        legacy.nic.queues = Some(1);
        assert_eq!(legacy.netd_interface, NetdInterface::None);
        assert_eq!(netd_teardown(&legacy, &filtering), Some(true));
    }

    /// Resolution produces launch input, never a claim about what exists.
    #[test]
    fn resolution_never_carries_a_stale_interface_record() {
        use crate::config::NetdInterface;

        let cvm = node_config(NetworkingMode::Bridge);
        // The node does not filter, so only a stale record could make teardown
        // ask libvirt to delete a binding.
        let mut previous = cvm.networking.clone();
        previous.nic.queues = Some(1);
        previous.netd_interface = NetdInterface::Filtered;
        assert_eq!(netd_teardown(&previous, &cvm), Some(true));

        let resolved = resolve_networking(&previous.nic, &cvm, 4);
        assert_eq!(resolved.netd_interface, NetdInterface::None);
        // Back to the derivation the node's own configuration gives.
        assert_eq!(netd_teardown(&resolved, &cvm), Some(false));
    }

    #[test]
    fn primary_mac_keeps_legacy_derivation_and_later_nics_are_distinct() {
        assert_eq!(
            mac_address_for_vm_index("vm-123", &[], 0),
            "96:b1:d8:b9:08:e6"
        );
        assert_eq!(
            mac_address_for_vm_index("vm-123", &[], 1),
            "c6:74:2c:65:14:b9"
        );
    }

    fn nic(mode: NetworkingMode) -> Networking {
        Networking {
            nic: NicNetworking {
                mode,
                ..NicNetworking::default()
            },
            ..Networking::default()
        }
    }

    fn mapping(host_port: u16, nic_index: Option<usize>) -> PortMapping {
        PortMapping {
            address: "0.0.0.0".parse().unwrap(),
            protocol: Protocol::Tcp,
            from: host_port,
            to: host_port,
            nic_index,
        }
    }

    #[test]
    fn an_unpinned_mapping_still_lands_where_hostfwd_always_put_it() {
        // Existing VMs must not move. QEMU's `hostfwd=` has always gone to the
        // first user-mode NIC, so that stays the answer wherever there is one.
        let networks = [nic(NetworkingMode::Bridge), nic(NetworkingMode::User)];
        assert_eq!(default_ingress_nic(&networks), Some(1));
        assert_eq!(ingress_nic(&mapping(443, None), &networks), Some(1));

        // With no user-mode NIC there was nowhere at all, which is the hole
        // this closes: a bridge NIC is the only other backend with a path.
        let networks = [nic(NetworkingMode::Bridge), nic(NetworkingMode::Bridge)];
        assert_eq!(default_ingress_nic(&networks), Some(0));

        // macvtap bypasses the host bridge and custom owns its netdev string.
        let networks = [nic(NetworkingMode::Macvtap), nic(NetworkingMode::Custom)];
        assert_eq!(default_ingress_nic(&networks), None);
        assert_eq!(ingress_nic(&mapping(443, None), &networks), None);
    }

    #[test]
    fn a_pinned_mapping_goes_where_it_says() {
        let networks = [nic(NetworkingMode::Bridge), nic(NetworkingMode::User)];
        assert_eq!(ingress_nic(&mapping(443, Some(0)), &networks), Some(0));
        // Out of range resolves to nothing rather than to something arbitrary.
        // Deployment refuses it outright; a manifest that lost a NIC lands here.
        assert_eq!(ingress_nic(&mapping(443, Some(7)), &networks), None);
    }

    /// A pin has to be checked against the backend, not just the count.
    /// Naming a macvtap or custom NIC used to resolve to that index and then
    /// fall out of every branch that could act on it: no `hostfwd=`, no netd
    /// request, and no warning either.
    #[test]
    fn a_pin_to_a_backend_with_no_ingress_resolves_to_nothing() {
        let networks = [
            nic(NetworkingMode::Macvtap),
            nic(NetworkingMode::Custom),
            nic(NetworkingMode::Bridge),
        ];
        assert_eq!(ingress_nic(&mapping(443, Some(0)), &networks), None);
        assert_eq!(ingress_nic(&mapping(443, Some(1)), &networks), None);
        assert_eq!(ingress_nic(&mapping(443, Some(2)), &networks), Some(2));

        // And an unpinned mapping on a VM with nowhere to put it is named,
        // rather than counted as delivered.
        let networks = [nic(NetworkingMode::Macvtap)];
        let port_map = [mapping(443, None), mapping(8080, Some(0))];
        let stranded: Vec<_> = stranded_ingress(&port_map, &networks)
            .map(|mapping| mapping.from)
            .collect();
        assert_eq!(stranded, vec![443, 8080]);
    }

    #[test]
    fn one_mapping_reaches_exactly_one_nic() {
        // The property that keeps QEMU and netd from both claiming a host port:
        // every mapping appears under one NIC and no other.
        let networks = [nic(NetworkingMode::Bridge), nic(NetworkingMode::User)];
        let port_map = [
            mapping(443, Some(0)),
            mapping(8080, None),
            mapping(9090, Some(1)),
        ];
        let per_nic: Vec<_> = (0..networks.len())
            .map(|index| ingress_for(&port_map, &networks, index))
            .collect();
        // Only NIC 0 is a bridge, so only its list becomes netd requests; the
        // other two ride QEMU's hostfwd on NIC 1.
        assert_eq!(per_nic[0].len(), 1);
        assert_eq!(per_nic[0][0].host_port, 443);
        assert_eq!(per_nic[1].len(), 2);
        let total: usize = per_nic.iter().map(Vec::len).sum();
        assert_eq!(total, port_map.len());
    }
}
