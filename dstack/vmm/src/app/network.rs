// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! VM network resolution, validation, and interface identity.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

use super::Manifest;
use crate::config::{CvmConfig, Networking, NetworkingMode};

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
    if !networking.netdev.is_empty() {
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

fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("bridge networking requested but no bridge is configured");
    }
    if name.len() > 15 {
        bail!("invalid bridge interface name '{name}': exceeds IFNAMSIZ");
    }
    let mut chars = name.chars();
    let valid_first = chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    let valid_rest = chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'));
    if !valid_first || !valid_rest {
        bail!("invalid bridge interface name '{name}': expected [A-Za-z0-9_][A-Za-z0-9_.-]*");
    }
    Ok(())
}

fn bridge_sysfs_path(name: &str) -> PathBuf {
    Path::new("/sys/class/net").join(name)
}

pub(crate) fn validate_resolved_network(
    networking: &Networking,
    policy: &Networking,
) -> Result<()> {
    if !policy.allowed_modes.is_empty() && !policy.allowed_modes.contains(&networking.mode) {
        bail!("networking mode '{:?}' is not allowed", networking.mode);
    }
    if networking.mode != NetworkingMode::Bridge {
        return Ok(());
    }

    validate_interface_name(&networking.bridge)?;
    let bridge_allowed = networking.bridge == policy.bridge
        || policy
            .allowed_bridges
            .iter()
            .any(|bridge| bridge == &networking.bridge);
    if !bridge_allowed {
        bail!(
            "bridge interface '{}' is not allowed by the VMM configuration",
            networking.bridge
        );
    }

    let sysfs_path = bridge_sysfs_path(&networking.bridge);
    if !sysfs_path.exists() {
        bail!("bridge interface '{}' does not exist", networking.bridge);
    }
    if !sysfs_path.join("bridge").is_dir() {
        bail!(
            "network interface '{}' is not a Linux bridge",
            networking.bridge
        );
    }
    Ok(())
}

pub(crate) fn validate_resolved_networks(
    networks: &[Networking],
    policy: &Networking,
) -> Result<()> {
    for networking in networks {
        validate_resolved_network(networking, policy)?;
    }
    Ok(())
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
    use super::{mac_address_for_vm_index, validate_interface_name};

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

    #[test]
    fn bridge_interface_names_are_strictly_validated() {
        for valid in ["br0", "dstack-br0", "bridge.100", "_bridge"] {
            validate_interface_name(valid).unwrap();
        }
        for invalid in [
            "",
            "/etc/passwd",
            "br0,helper=/bin/sh",
            "br0=bad",
            "br 0",
            "-br0",
            "0123456789abcdef",
        ] {
            assert!(validate_interface_name(invalid).is_err(), "{invalid}");
        }
    }
}
