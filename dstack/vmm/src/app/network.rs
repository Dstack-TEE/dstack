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
/// Macvtap always needs one. A bridge NIC needs one when libvirt filtering
/// binds an nwfilter to the TAP, and when multiqueue requires a persistent
/// `IFF_MULTI_QUEUE` device that `qemu-bridge-helper` cannot create.
pub(crate) fn needs_netd_interface(networking: &Networking, cfg: &CvmConfig) -> bool {
    match networking.nic.mode {
        NetworkingMode::Macvtap => true,
        NetworkingMode::Bridge => {
            cfg.network_filter.mode == NetworkFilterMode::Libvirt || networking.queue_pairs() > 1
        }
        NetworkingMode::User | NetworkingMode::Custom => false,
    }
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
        NetdInterface::None if needs_netd_interface(networking, cfg) => {
            Some(filters_bridge_traffic(networking, cfg))
        }
        NetdInterface::None => None,
    }
}

/// Drops a NIC back to one queue pair when multiqueue would need a netd
/// interface this node cannot provide.
///
/// Queue pairs are a default now, not something the operator asked for, so a
/// node that has never deployed netd must keep launching bridge VMs. An
/// explicit per-VM request is left alone: the caller asked for it, and failing
/// at prepare tells them why far better than silently halving their throughput.
/// Returns how many NICs it dropped, so a launch can say so and a status
/// query, which runs the same calculation to describe a stopped VM, stays
/// silent.
pub(crate) fn clamp_queues_without_netd(
    requested: &[NicNetworking],
    resolved: &mut [Networking],
    cfg: &CvmConfig,
    netd_available: bool,
) -> usize {
    if netd_available {
        return 0;
    }
    let mut clamped = 0;
    for (networking, asked) in resolved.iter_mut().zip(requested) {
        // Macvtap has nothing to fall back to: netd is the only thing that can
        // create the device, so clamping one would describe a VM that cannot
        // start either way.
        if networking.nic.mode != NetworkingMode::Bridge
            || asked.queues.is_some()
            || !needs_netd_interface(networking, cfg)
            // Filtering needs netd whatever the queue count, so dropping this
            // NIC to one queue pair would not make it launchable. It would only
            // describe it as something no launch can produce, and warn about a
            // fallback that is not happening.
            || filters_bridge_traffic(networking, cfg)
        {
            continue;
        }
        networking.nic.queues = Some(1);
        clamped += 1;
    }
    clamped
}

/// Locations distributions install `qemu-bridge-helper` in. The helper is
/// setuid root and attaches an unprivileged TAP to a whitelisted bridge, which
/// is how bridge mode avoids giving the VMM `CAP_NET_ADMIN`.
const BRIDGE_HELPER_CANDIDATES: [&str; 3] = [
    "/usr/lib/qemu/qemu-bridge-helper",
    "/usr/libexec/qemu-bridge-helper",
    "/usr/local/libexec/qemu-bridge-helper",
];

/// Absolute path of `qemu-bridge-helper`, which QEMU's `tap` netdev, unlike its
/// `bridge` netdev, has no compiled-in default for.
///
/// A configured path is passed through unchecked: the operator is naming a
/// binary for QEMU to exec, and QEMU need not see this filesystem.
pub(crate) fn find_bridge_helper<'a>(
    configured: &'a str,
    candidates: &[&'a str],
) -> Option<&'a str> {
    let configured = configured.trim();
    if !configured.is_empty() {
        return Some(configured);
    }
    candidates
        .iter()
        .copied()
        .find(|candidate| Path::new(candidate).exists())
}

pub(crate) fn bridge_helper(cfg: &CvmConfig) -> Option<&str> {
    find_bridge_helper(&cfg.qemu_bridge_helper, &BRIDGE_HELPER_CANDIDATES)
}

/// Whether this NIC will actually run on the vhost-net data plane.
///
/// A bridge NIC that neither needs a netd interface nor can find
/// `qemu-bridge-helper` falls back to QEMU's `bridge` netdev, which has no
/// vhost support. Both the QEMU arguments and the reported status read this,
/// so a VM is never described as using a data plane it did not get.
pub(crate) fn effective_vhost(networking: &Networking, cfg: &CvmConfig) -> bool {
    if !networking.vhost_enabled() {
        return false;
    }
    networking.nic.mode != NetworkingMode::Bridge
        || needs_netd_interface(networking, cfg)
        || bridge_helper(cfg).is_some()
}

/// Makes the effective data plane concrete on a launch-time NIC list, and
/// returns how many interfaces asked for vhost and did not get it.
///
/// `vhost` on a freshly resolved entry is still a *request*: `None` means
/// inherit, and a bridge NIC that cannot reach `qemu-bridge-helper` runs on the
/// non-vhost netdev whatever it asked for. Settling it once, here, is what lets
/// the QEMU arguments and the reported status read the same value -- and keeps
/// them reading it after the operator moves the helper out from under a VM that
/// is already running.
pub(crate) fn settle_vhost(networks: &mut [Networking], cfg: &CvmConfig) -> usize {
    let mut denied = 0;
    for networking in networks.iter_mut() {
        let effective = effective_vhost(networking, cfg);
        if networking.vhost_enabled() && !effective {
            denied += 1;
        }
        networking.nic.vhost = Some(effective);
    }
    denied
}

/// Whether netd is reachable. A netd that died leaves its socket behind, so
/// existence alone would report a node as capable and fail every launch.
///
/// A connect and nothing more, deliberately: netd serves connections serially,
/// so anything that waits for an answer reads a *busy* netd as a missing one
/// and silently drops the VM to a single queue pair. Accepting the connection
/// is the one signal that does not depend on what netd is doing right now.
pub(crate) fn netd_available(socket: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
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

/// Which NIC a port mapping's traffic enters through.
///
/// One mapping resolves to at most one NIC, and that NIC's backend decides the
/// mechanism: `hostfwd=` for user mode, netd for a bridge. That is what keeps
/// QEMU and netd from both claiming one host port.
pub(crate) fn ingress_nic(mapping: &PortMapping, networks: &[Networking]) -> Option<usize> {
    mapping
        .nic_index
        .or_else(|| default_ingress_nic(networks))
        .filter(|index| *index < networks.len())
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
        clamp_queues_without_netd, default_ingress_nic, effective_vhost, ingress_for, ingress_nic,
        mac_address_for_vm_index, needs_netd_interface, netd_teardown, resolve_networking,
        resolved_networks, settle_vhost, validate_resolved_networks,
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
            assert!(!needs_netd_interface(&resolved[0], &cvm));
        }
    }

    #[test]
    fn turning_vhost_off_also_turns_off_the_multiqueue_default() {
        let mut cvm = node_config(NetworkingMode::Bridge);
        cvm.networking.nic.vhost = Some(false);
        let resolved = resolved_networks(&manifest_with(8, vec![]), &cvm);
        assert!(!resolved[0].vhost_enabled());
        assert_eq!(resolved[0].queue_pairs(), 1);
        assert!(!needs_netd_interface(&resolved[0], &cvm));

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

    #[test]
    fn status_never_claims_a_data_plane_the_nic_did_not_get() {
        let mut cvm = node_config(NetworkingMode::Bridge);
        // No helper on this filesystem and no netd interface needed, so the
        // NIC falls back to QEMU's `bridge` netdev, which has no vhost.
        cvm.qemu_bridge_helper = String::new();
        let mut single = cvm.networking.nic.clone();
        single.queues = Some(1);
        let resolved = resolved_networks(&manifest_with(8, vec![single]), &cvm);
        assert!(resolved[0].vhost_enabled());
        let fell_back = !effective_vhost(&resolved[0], &cvm);
        assert_eq!(fell_back, super::bridge_helper(&cvm).is_none());

        // A configured helper is taken at its word, so vhost is real.
        cvm.qemu_bridge_helper = "/opt/qemu-bridge-helper".into();
        let resolved = resolved_networks(&manifest_with(8, vec![]), &cvm);
        assert!(effective_vhost(&resolved[0], &cvm));

        // Multiqueue goes through netd, which needs no helper at all.
        let mut mq = cvm.networking.nic.clone();
        mq.queues = Some(4);
        cvm.qemu_bridge_helper = String::new();
        let resolved = resolved_networks(&manifest_with(8, vec![mq]), &cvm);
        assert!(needs_netd_interface(&resolved[0], &cvm));
        assert!(effective_vhost(&resolved[0], &cvm));
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
    fn without_netd_a_defaulted_bridge_drops_to_one_queue_but_a_request_does_not() {
        let cvm = node_config(NetworkingMode::Bridge);

        // The default is ours to lower: a node that never deployed netd must
        // keep launching bridge VMs.
        let requested = vec![cvm.networking.nic.clone()];
        let mut resolved = resolved_networks(&manifest_with(8, vec![]), &cvm);
        assert_eq!(resolved[0].queue_pairs(), 8);
        clamp_queues_without_netd(&requested, &mut resolved, &cvm, false);
        assert_eq!(resolved[0].queue_pairs(), 1);
        assert!(!needs_netd_interface(&resolved[0], &cvm));

        // An explicit request is left alone, so prepare fails where the caller
        // can see why instead of silently halving their throughput.
        let mut asked = cvm.networking.nic.clone();
        asked.queues = Some(4);
        let requested = vec![asked.clone()];
        let mut resolved = resolved_networks(&manifest_with(8, vec![asked]), &cvm);
        clamp_queues_without_netd(&requested, &mut resolved, &cvm, false);
        assert_eq!(resolved[0].queue_pairs(), 4);

        // With netd present nothing is touched.
        let requested = vec![cvm.networking.nic.clone()];
        let mut resolved = resolved_networks(&manifest_with(8, vec![]), &cvm);
        clamp_queues_without_netd(&requested, &mut resolved, &cvm, true);
        assert_eq!(resolved[0].queue_pairs(), 8);
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
        cvm.qemu_bridge_helper = String::new();
        let mut single = cvm.networking.nic.clone();
        single.queues = Some(1);
        let manifest = manifest_with(8, vec![single]);

        // Whether this host has a helper is not the test's business; that it
        // gets written down, once, is.
        let helper_missing = super::bridge_helper(&cvm).is_none();
        let mut networks = resolved_networks(&manifest, &cvm);
        assert!(networks[0].vhost_enabled(), "the request starts out on");
        assert_eq!(
            settle_vhost(&mut networks, &cvm),
            usize::from(helper_missing)
        );
        assert_eq!(networks[0].nic.vhost, Some(!helper_missing));
        // Settling an already-settled list reports nothing new, so a relaunch
        // does not warn about a fallback that already happened.
        assert_eq!(settle_vhost(&mut networks, &cvm), 0);

        // A configured helper is taken at its word, so the same NIC settles on.
        cvm.qemu_bridge_helper = "/opt/qemu-bridge-helper".into();
        let mut with_helper = resolved_networks(&manifest, &cvm);
        assert_eq!(settle_vhost(&mut with_helper, &cvm), 0);
        assert_eq!(with_helper[0].nic.vhost, Some(true));

        // The entry the first launch settled keeps its answer: nothing about a
        // running VM is recomputed from the configuration as it stands now.
        assert_eq!(networks[0].nic.vhost, Some(!helper_missing));
    }

    /// Dropping to a single queue pair is only worth doing when it makes the
    /// NIC launchable. A filtered bridge needs netd whatever its queue count,
    /// so clamping it would report a shape no launch can produce.
    #[test]
    fn a_filtered_bridge_is_not_clamped_because_it_cannot_help() {
        use crate::config::NetworkFilterMode;

        let mut cvm = node_config(NetworkingMode::Bridge);
        cvm.network_filter.mode = NetworkFilterMode::Libvirt;
        let requested = vec![cvm.networking.nic.clone()];
        let mut resolved = resolved_networks(&manifest_with(8, vec![]), &cvm);
        assert_eq!(resolved[0].queue_pairs(), 8);
        assert_eq!(
            clamp_queues_without_netd(&requested, &mut resolved, &cvm, false),
            0
        );
        assert_eq!(resolved[0].queue_pairs(), 8);

        // Unfiltered, the same NIC does drop, because then it can launch.
        let cvm = node_config(NetworkingMode::Bridge);
        let mut resolved = resolved_networks(&manifest_with(8, vec![]), &cvm);
        assert_eq!(
            clamp_queues_without_netd(&requested, &mut resolved, &cvm, false),
            1
        );
        assert_eq!(resolved[0].queue_pairs(), 1);
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

        // A NIC netd never touched stays untouched, whatever the node now says.
        let mut untouched = unfiltered.networking.clone();
        untouched.nic.queues = Some(1);
        assert_eq!(netd_teardown(&untouched, &unfiltered), None);

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
        // Single queue and no filtering, so nothing but a stale record could
        // make teardown believe netd built something.
        let mut previous = cvm.networking.clone();
        previous.nic.queues = Some(1);
        previous.netd_interface = NetdInterface::Filtered;
        assert_eq!(netd_teardown(&previous, &cvm), Some(true));

        let resolved = resolve_networking(&previous.nic, &cvm, 4);
        assert_eq!(resolved.netd_interface, NetdInterface::None);
        assert_eq!(netd_teardown(&resolved, &cvm), None);
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
