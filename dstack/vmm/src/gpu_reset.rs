// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use tracing::info;

use crate::{app::GpuConfig, config::GpuConfig as HostGpuConfig};

const PCI_SYSFS_DEVICES: &str = "/sys/bus/pci/devices";
const PCI_BRIDGE_CLASS: u32 = 0x0604;
const PCI_BRIDGE_CONTROL: u64 = 0x3e;
const PCI_BRIDGE_CTL_BUS_RESET: u16 = 1 << 6;
const SBR_ASSERT_TIME: Duration = Duration::from_millis(100);
const SBR_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SBR_STABLE_TIME: Duration = Duration::from_millis(500);

/// Clears device-internal state that can survive VFIO's attach-time FLR.
///
/// Each selected GPU must sit alone behind a dedicated PCIe bridge. Resetting
/// a shared bridge could disrupt unrelated devices, so that topology is
/// rejected rather than guessed at.
pub fn sanitize_on_attach(host: &HostGpuConfig, devices: &GpuConfig) -> Result<()> {
    if !host.enabled || !host.sanitize_on_attach || devices.gpus.is_empty() {
        return Ok(());
    }
    sanitize_at(
        Path::new(PCI_SYSFS_DEVICES),
        devices,
        Duration::from_millis(host.sbr_timeout_ms),
    )
}

fn sanitize_at(sysfs_devices: &Path, devices: &GpuConfig, timeout: Duration) -> Result<()> {
    let selected = devices
        .gpus
        .iter()
        .map(|gpu| normalize_slot(&gpu.slot))
        .collect::<BTreeSet<_>>();
    let mut bridges = BTreeSet::new();

    for gpu in &selected {
        let bridge = upstream_bridge(sysfs_devices, gpu)?;
        ensure_dedicated_bridge(&bridge, gpu)?;
        bridges.insert(bridge);
    }

    for bridge in bridges {
        info!(bridge = %bridge.display(), "sanitizing GPU with PCIe Secondary Bus Reset");
        secondary_bus_reset(&bridge)
            .with_context(|| format!("failed to sanitize GPU using bridge {}", bridge.display()))?;
    }
    wait_for_vfio_ready(sysfs_devices, &selected, timeout)?;
    Ok(())
}

fn wait_for_vfio_ready(
    sysfs_devices: &Path,
    devices: &BTreeSet<String>,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut stable_since = None;
    loop {
        let not_ready = devices
            .iter()
            .filter(|slot| !is_vfio_ready(&sysfs_devices.join(slot)))
            .cloned()
            .collect::<Vec<_>>();
        if not_ready.is_empty() {
            let since = *stable_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= SBR_STABLE_TIME {
                info!(count = devices.len(), "all sanitized GPUs are VFIO-ready");
                return Ok(());
            }
        } else {
            stable_since = None;
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out after {} ms waiting for sanitized GPUs to become VFIO-ready: {}",
                timeout.as_millis(),
                not_ready.join(", ")
            );
        }
        thread::sleep(SBR_POLL_INTERVAL);
    }
}

fn is_vfio_ready(device: &Path) -> bool {
    let Ok(device) = device.canonicalize() else {
        return false;
    };
    let Ok(config) = File::open(device.join("config")) else {
        return false;
    };
    let Ok(vendor) = read_u16(&config, 0) else {
        return false;
    };
    if matches!(vendor, 0 | 0xffff) {
        return false;
    }
    let driver_is_vfio = device
        .join("driver")
        .canonicalize()
        .ok()
        .and_then(|path| path.file_name().map(|name| name == "vfio-pci"))
        .unwrap_or(false);
    driver_is_vfio
        && device.join("iommu_group").canonicalize().is_ok()
        && fs_err::read_dir(device.join("vfio-dev"))
            .ok()
            .and_then(|mut entries| entries.next())
            .is_some()
}

fn normalize_slot(slot: &str) -> String {
    if slot.matches(':').count() == 1 {
        format!("0000:{slot}")
    } else {
        slot.to_owned()
    }
}

fn upstream_bridge(sysfs_devices: &Path, slot: &str) -> Result<PathBuf> {
    let device_link = sysfs_devices.join(slot);
    let device = device_link
        .canonicalize()
        .with_context(|| format!("failed to resolve PCI device {slot}"))?;
    let bridge = device
        .parent()
        .context("PCI device has no upstream bridge")?
        .to_path_buf();
    let class = fs_err::read_to_string(bridge.join("class"))
        .with_context(|| format!("failed to read class of bridge {}", bridge.display()))?;
    let class = u32::from_str_radix(class.trim().trim_start_matches("0x"), 16)
        .context("invalid PCI bridge class")?;
    if class >> 8 != PCI_BRIDGE_CLASS {
        bail!("GPU {slot} is not directly behind a PCI bridge (parent class {class:#08x})");
    }
    Ok(bridge)
}

fn ensure_dedicated_bridge(bridge: &Path, gpu: &str) -> Result<()> {
    let mut downstream = Vec::new();
    for entry in fs_err::read_dir(bridge)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name != gpu && is_pci_slot(&name) && entry.file_type()?.is_dir() {
            downstream.push(name.into_owned());
        }
    }
    if !downstream.is_empty() {
        bail!(
            "refusing to reset shared bridge {} for GPU {gpu}; other downstream PCI devices: {}",
            bridge.display(),
            downstream.join(", ")
        );
    }
    Ok(())
}

fn is_pci_slot(name: &str) -> bool {
    name.len() == 12
        && name.as_bytes()[4] == b':'
        && name.as_bytes()[7] == b':'
        && name.as_bytes()[10] == b'.'
        && name
            .chars()
            .enumerate()
            .all(|(i, c)| matches!(i, 4 | 7 | 10) || c.is_ascii_hexdigit())
}

fn secondary_bus_reset(bridge: &Path) -> Result<()> {
    let config_path = bridge.join("config");
    let config = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config_path)
        .with_context(|| format!("failed to open {}", config_path.display()))?;
    let original = read_u16(&config, PCI_BRIDGE_CONTROL)?;
    write_u16(
        &config,
        PCI_BRIDGE_CONTROL,
        original | PCI_BRIDGE_CTL_BUS_RESET,
    )?;
    thread::sleep(SBR_ASSERT_TIME);
    write_u16(
        &config,
        PCI_BRIDGE_CONTROL,
        original & !PCI_BRIDGE_CTL_BUS_RESET,
    )?;
    Ok(())
}

fn read_u16(file: &File, offset: u64) -> Result<u16> {
    let mut value = [0_u8; 2];
    file.read_exact_at(&mut value, offset)?;
    Ok(u16::from_le_bytes(value))
}

fn write_u16(file: &File, offset: u64, value: u16) -> Result<()> {
    file.write_all_at(&value.to_le_bytes(), offset)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    use crate::app::{AttachMode, GpuSpec};

    #[test]
    fn normalizes_short_pci_slots() {
        assert_eq!(normalize_slot("0f:00.0"), "0000:0f:00.0");
        assert_eq!(normalize_slot("0001:0f:00.0"), "0001:0f:00.0");
    }

    #[test]
    fn recognizes_pci_slots() {
        assert!(is_pci_slot("0000:0f:00.0"));
        assert!(!is_pci_slot("class"));
        assert!(!is_pci_slot("0000:0g:00.0"));
    }

    #[test]
    fn skips_sanitization_when_gpu_passthrough_is_disabled() {
        let host = HostGpuConfig {
            enabled: false,
            listing: Vec::new(),
            exclude: Vec::new(),
            include: Vec::new(),
            allow_attach_all: true,
            sanitize_on_attach: true,
            sbr_timeout_ms: 10_000,
        };
        let devices = GpuConfig {
            attach_mode: AttachMode::Listed,
            gpus: vec![GpuSpec {
                slot: "ff:00.0".into(),
            }],
            bridges: Vec::new(),
        };

        sanitize_on_attach(&host, &devices).unwrap();
    }

    #[test]
    fn finds_a_dedicated_upstream_bridge() {
        let root = tempfile::tempdir().unwrap();
        let bridge = root.path().join("tree/0000:00:01.0");
        let gpu = bridge.join("0000:01:00.0");
        fs_err::create_dir_all(&gpu).unwrap();
        fs_err::write(bridge.join("class"), "0x060400\n").unwrap();
        let devices = root.path().join("devices");
        fs_err::create_dir(&devices).unwrap();
        symlink(&gpu, devices.join("0000:01:00.0")).unwrap();

        let found = upstream_bridge(&devices, "0000:01:00.0").unwrap();
        assert_eq!(found, bridge.canonicalize().unwrap());
        ensure_dedicated_bridge(&found, "0000:01:00.0").unwrap();
    }

    #[test]
    fn rejects_a_bridge_shared_with_another_device() {
        let root = tempfile::tempdir().unwrap();
        let bridge = root.path().join("0000:00:01.0");
        fs_err::create_dir_all(bridge.join("0000:01:00.0")).unwrap();
        fs_err::create_dir_all(bridge.join("0000:01:00.1")).unwrap();

        let error = ensure_dedicated_bridge(&bridge, "0000:01:00.0").unwrap_err();
        assert!(error.to_string().contains("shared bridge"));
        assert!(error.to_string().contains("0000:01:00.1"));
    }
}
