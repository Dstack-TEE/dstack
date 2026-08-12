// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! VM network resolution, validation, and interface identity.

use std::path::Path;

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

use super::Manifest;
use crate::config::{
    validate_open_file, CvmConfig, Networking, NetworkingMode, SD_LISTEN_FDS_START,
};

pub(crate) fn resolve_networking(networking: &Networking, cfg: &CvmConfig) -> Networking {
    let mut resolved = cfg.networking.clone();
    resolved.mode = networking.mode;
    resolved.restrict = cfg.networking.restrict || networking.restrict;
    if !networking.bridge.is_empty() {
        resolved.bridge = networking.bridge.clone();
    }
    if !networking.mac_prefix.is_empty() {
        resolved.mac_prefix = networking.mac_prefix.clone();
    }
    if !networking.net.is_empty() {
        resolved.net = networking.net.clone();
    }
    if !networking.dhcp_start.is_empty() {
        resolved.dhcp_start = networking.dhcp_start.clone();
    }
    // Not merged from the host defaults: a pre-opened chardev names one
    // device and belongs to exactly one NIC. When set, it also owns the
    // netdev string (generated later from the fd number), so even an empty
    // NIC netdev must replace a host-wide custom default.
    resolved.open_file = networking.open_file.clone();
    let replace_netdev = !networking.open_file.is_empty() || !networking.netdev.is_empty();
    if replace_netdev {
        resolved.netdev = networking.netdev.clone();
    }
    resolved
}

pub(crate) fn resolved_networks(manifest: &Manifest, cfg: &CvmConfig) -> Vec<Networking> {
    if manifest.networks.is_empty() {
        vec![cfg.networking.clone()]
    } else {
        manifest
            .networks
            .iter()
            .map(|networking| resolve_networking(networking, cfg))
            .collect()
    }
}

pub(crate) fn validate_resolved_network(networking: &Networking) -> Result<()> {
    if !networking.open_file.is_empty() {
        validate_open_file("networking.open_file", &networking.open_file)?;
        if networking.mode != NetworkingMode::Custom {
            bail!("networking.open_file requires mode = \"custom\"");
        }
        if !networking.netdev.is_empty() {
            // The netdev string is generated from the inherited fd number,
            // which only the process manager knows.
            bail!("networking.open_file and networking.netdev are mutually exclusive");
        }
    }
    if networking.mode != NetworkingMode::Bridge {
        return Ok(());
    }
    if networking.bridge.is_empty() {
        bail!("bridge networking requested but no bridge is configured");
    }
    if !Path::new("/sys/class/net")
        .join(&networking.bridge)
        .exists()
    {
        bail!("bridge interface '{}' does not exist", networking.bridge);
    }
    Ok(())
}

pub(crate) fn validate_resolved_networks(networks: &[Networking]) -> Result<()> {
    for networking in networks {
        validate_resolved_network(networking)?;
    }
    Ok(())
}

/// Chardev paths the process manager must open before exec, in NIC order.
///
/// The order is the contract: systemd hands the files to the service in
/// declaration order, so entry `i` of this list arrives as fd
/// `SD_LISTEN_FDS_START + i`.
pub(crate) fn open_files(networks: &[Networking]) -> Vec<String> {
    networks
        .iter()
        .filter(|networking| !networking.open_file.is_empty())
        .map(|networking| networking.open_file.clone())
        .collect()
}

/// File descriptor the NIC at `index` receives, or `None` if it does not use a
/// pre-opened chardev.
pub(crate) fn open_file_fd(networks: &[Networking], index: usize) -> Option<u32> {
    if networks.get(index)?.open_file.is_empty() {
        return None;
    }
    let preceding = networks[..index]
        .iter()
        .filter(|networking| !networking.open_file.is_empty())
        .count();
    Some(SD_LISTEN_FDS_START + preceding as u32)
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
        mac_address_for_vm_index, open_file_fd, open_files, validate_resolved_network, Networking,
        NetworkingMode,
    };

    fn open_file_network(path: &str) -> Networking {
        Networking {
            mode: NetworkingMode::Custom,
            bridge: String::new(),
            mac_prefix: String::new(),
            net: String::new(),
            dhcp_start: String::new(),
            restrict: false,
            netdev: String::new(),
            open_file: path.into(),
        }
    }

    #[test]
    fn open_file_descriptors_are_numbered_in_nic_order() {
        let mut networks = vec![
            open_file_network(""),
            open_file_network("/dev/tap10"),
            open_file_network(""),
            open_file_network("/dev/tap11"),
        ];
        networks[0].mode = NetworkingMode::User;
        networks[2].mode = NetworkingMode::Bridge;

        assert_eq!(open_files(&networks), ["/dev/tap10", "/dev/tap11"]);
        assert_eq!(open_file_fd(&networks, 0), None);
        assert_eq!(open_file_fd(&networks, 1), Some(3));
        assert_eq!(open_file_fd(&networks, 2), None);
        assert_eq!(open_file_fd(&networks, 3), Some(4));
        assert_eq!(open_file_fd(&networks, 4), None);
    }

    #[test]
    fn open_file_networks_are_validated() {
        validate_resolved_network(&open_file_network("/dev/tap7498")).unwrap();

        for path in [
            "dev/tap7498",
            "/dev/tap 7498",
            "/dev/tap7498:foo",
            "/dev/tap7498,vhost=on",
            "/dev/%i/tap7498",
        ] {
            validate_resolved_network(&open_file_network(path)).unwrap_err();
        }

        let mut wrong_mode = open_file_network("/dev/tap7498");
        wrong_mode.mode = NetworkingMode::Bridge;
        wrong_mode.bridge = "br0".into();
        validate_resolved_network(&wrong_mode).unwrap_err();

        let mut with_netdev = open_file_network("/dev/tap7498");
        with_netdev.netdev = "tap,id=net0,fd=3".into();
        validate_resolved_network(&with_netdev).unwrap_err();
    }

    #[test]
    fn open_file_does_not_inherit_host_custom_netdev() {
        use rocket::figment::{providers::Format, providers::Toml, Figment};

        let mut cfg: crate::config::Config =
            Figment::from(Toml::string(crate::config::DEFAULT_CONFIG))
                .extract()
                .unwrap();
        cfg.cvm.networking.mode = NetworkingMode::Custom;
        cfg.cvm.networking.netdev = "tap,id=net0,ifname=legacy,script=no".into();

        let nic = open_file_network("/dev/tap7498");
        let resolved = super::resolve_networking(&nic, &cfg.cvm);
        assert_eq!(resolved.open_file, "/dev/tap7498");
        assert!(resolved.netdev.is_empty());
        validate_resolved_network(&resolved).unwrap();
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
}
