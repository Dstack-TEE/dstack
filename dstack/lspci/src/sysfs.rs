// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! GPU inventory read straight from sysfs.
//!
//! Distinct from the `lspci` parser in this crate: no subprocess, no text
//! parsing, and it sees devices the NVIDIA driver never bound. That matters in
//! two places with opposite failure policies -- the boot attestation gate must
//! fail closed when the inventory cannot be read, while a telemetry collector
//! wants to shrug and report no GPUs -- so this returns the raw counts and lets
//! each caller decide.

use std::path::Path;

use anyhow::{Context, Result};

/// Where the kernel exposes the PCI bus.
pub const PCI_DEVICES: &str = "/sys/bus/pci/devices";

const NVIDIA_VENDOR_ID: &str = "0x10de";
/// PCI class prefixes for VGA and 3D controllers.
const DISPLAY_CLASS_PREFIXES: [&str; 2] = ["0x0300", "0x0302"];

/// Display-class PCI devices, split by vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GpuInventory {
    /// All display-class devices, whatever the vendor.
    pub total: u32,
    /// The subset made by NVIDIA.
    pub nvidia: u32,
}

impl GpuInventory {
    /// True when at least one NVIDIA display device is attached.
    pub fn has_nvidia(&self) -> bool {
        self.nvidia > 0
    }
}

/// Counts display-class GPUs on the live PCI bus.
pub fn gpu_inventory() -> Result<GpuInventory> {
    gpu_inventory_at(Path::new(PCI_DEVICES))
}

/// Counts display-class GPUs under an arbitrary sysfs root, for tests.
pub fn gpu_inventory_at(devices_path: &Path) -> Result<GpuInventory> {
    let entries = std::fs::read_dir(devices_path)
        .with_context(|| format!("failed to enumerate {}", devices_path.display()))?;
    let mut inventory = GpuInventory::default();
    for entry in entries {
        let device = entry.context("failed to read PCI device entry")?;
        let class_path = device.path().join("class");
        let class = std::fs::read_to_string(&class_path)
            .with_context(|| format!("failed to read {}", class_path.display()))?;
        if !class
            .trim()
            .get(..6)
            .is_some_and(|prefix| DISPLAY_CLASS_PREFIXES.contains(&prefix))
        {
            continue;
        }
        inventory.total += 1;
        let vendor_path = device.path().join("vendor");
        let vendor = std::fs::read_to_string(&vendor_path)
            .with_context(|| format!("failed to read {}", vendor_path.display()))?;
        if vendor.trim() == NVIDIA_VENDOR_ID {
            inventory.nvidia += 1;
        }
    }
    Ok(inventory)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_pci_device(root: &Path, name: &str, vendor: &str, class: &str) {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vendor"), vendor).unwrap();
        std::fs::write(dir.join("class"), class).unwrap();
    }

    #[test]
    fn inventory_counts_nvidia_and_non_nvidia_gpus() {
        let root = tempfile::tempdir().unwrap();
        add_pci_device(root.path(), "0000:01:00.0", "0x10de\n", "0x030200\n");
        add_pci_device(root.path(), "0000:02:00.0", "0x1234\n", "0x030000\n");
        // A virtio NIC is not a display device and must not be counted.
        add_pci_device(root.path(), "0000:03:00.0", "0x1af4\n", "0x020000\n");
        assert_eq!(
            gpu_inventory_at(root.path()).unwrap(),
            GpuInventory {
                total: 2,
                nvidia: 1
            }
        );
    }

    /// The common CVM: virtio devices only. `has_nvidia` is the gate that keeps
    /// GPU telemetry from costing such a guest anything.
    #[test]
    fn a_guest_without_a_display_device_reports_no_gpus() {
        let root = tempfile::tempdir().unwrap();
        add_pci_device(root.path(), "0000:01:00.0", "0x1af4\n", "0x020000\n");
        add_pci_device(root.path(), "0000:02:00.0", "0x1af4\n", "0x010000\n");
        let inventory = gpu_inventory_at(root.path()).unwrap();
        assert_eq!(inventory, GpuInventory::default());
        assert!(!inventory.has_nvidia());
    }

    /// Callers must be able to tell "no GPUs" from "could not look".
    #[test]
    fn an_unreadable_root_is_an_error_not_an_empty_inventory() {
        assert!(gpu_inventory_at(Path::new("/nonexistent/pci/devices")).is_err());
    }
}
