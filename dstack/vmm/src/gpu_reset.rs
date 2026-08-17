// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! GPU sanitization before QEMU attach.
//!
//! Terminating QEMU while GSP/SPDM initialization is in progress can leave
//! stale FSP/SPDM session state in a GPU. VFIO's attach-time FLR does not
//! clear that state; a PCIe Secondary Bus Reset does. The next guest
//! otherwise fails with an SPDM timeout followed by GSP/RmInitAdapter errors.
//!
//! The VMM runs as an unprivileged user, so it cannot issue the SBR by
//! writing Bridge Control in the upstream bridge's sysfs config space: that
//! file is writable by root only, as is /sys/bus/pci/drivers_probe. Instead
//! the VFIO_DEVICE_PCI_HOT_RESET ioctl asks the kernel to perform the same
//! bus reset. The ioctl is authorized by device ownership rather than
//! privilege: the caller must present an fd for every VFIO group affected by
//! the reset. The group nodes under /dev/vfio are the same ones QEMU opens
//! to attach the GPU, so the VMM user already has access to them.
//!
//! A single group fd suffices only because every sanitized GPU sits alone
//! behind a dedicated PCIe bridge and alone in its IOMMU group. The bridge
//! topology is validated first, and the kernel-reported set of devices
//! affected by the reset must all belong to the GPU's own group; anything
//! else aborts the launch rather than risking disruption to other devices.
//!
//! A VFIO group can be opened by only one process at a time, so every fd is
//! closed again before QEMU is spawned.

use std::{
    collections::BTreeSet,
    fs::File,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use tracing::info;
use vfio_ioctls::{PciHotResetDevice, VfioContainer, VfioDevice};

use crate::{app::GpuConfig, config::GpuConfig as HostGpuConfig};

const PCI_SYSFS_DEVICES: &str = "/sys/bus/pci/devices";
const PCI_BRIDGE_CLASS: u32 = 0x0604;
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
    let slots = devices
        .gpus
        .iter()
        .map(|gpu| gpu.slot.clone())
        .collect::<Vec<_>>();
    sanitize_slots(&slots, Duration::from_millis(host.sbr_timeout_ms))
}

/// Sanitizes the given GPU slots. Entry point for the `sanitize-gpu`
/// subcommand; `sanitize_on_attach` funnels here as well.
pub fn sanitize_slots(slots: &[String], timeout: Duration) -> Result<()> {
    if slots.is_empty() {
        bail!("no GPU slots specified");
    }
    let selected = slots
        .iter()
        .map(|slot| normalize_slot(slot))
        .collect::<BTreeSet<_>>();
    sanitize_at(Path::new(PCI_SYSFS_DEVICES), &selected, timeout)
}

fn sanitize_at(sysfs_devices: &Path, selected: &BTreeSet<String>, timeout: Duration) -> Result<()> {
    for gpu in selected {
        let bridge = upstream_bridge(sysfs_devices, gpu)?;
        ensure_dedicated_bridge(&bridge, gpu)?;
    }

    for gpu in selected {
        info!(gpu = %gpu, "sanitizing GPU with VFIO PCI hot reset");
        hot_reset(sysfs_devices, gpu)
            .with_context(|| format!("failed to sanitize GPU {gpu} with VFIO hot reset"))?;
    }
    wait_for_vfio_ready(sysfs_devices, selected, timeout)?;
    Ok(())
}

/// Issues a Secondary Bus Reset on the GPU's upstream bridge through VFIO.
///
/// All fds are dropped on return so that QEMU can open the group afterwards.
fn hot_reset(sysfs_devices: &Path, slot: &str) -> Result<()> {
    let group_id = iommu_group_id(sysfs_devices, slot)?;
    let container = Arc::new(VfioContainer::new(None).context("failed to open VFIO container")?);
    let group = container
        .get_group(group_id)
        .with_context(|| format!("failed to open VFIO group {group_id}"))?;
    let device = VfioDevice::new(&sysfs_devices.join(slot), container)
        .with_context(|| format!("failed to open VFIO device {slot}"))?;

    let dependents = device
        .pci_hot_reset_info()
        .context("VFIO_DEVICE_GET_PCI_HOT_RESET_INFO failed")?;
    let foreign = dependents
        .iter()
        .filter(|dep| dep.group_id != group_id)
        .map(format_dependent)
        .collect::<Vec<_>>();
    if !foreign.is_empty() {
        bail!(
            "refusing hot reset of GPU {slot}: it would also reset devices outside \
             IOMMU group {group_id}: {}",
            foreign.join(", ")
        );
    }
    info!(
        gpu = %slot,
        affected = %dependents.iter().map(format_dependent).collect::<Vec<_>>().join(", "),
        "issuing VFIO PCI hot reset"
    );

    device
        .pci_hot_reset(&[&group])
        .context("VFIO_DEVICE_PCI_HOT_RESET failed")?;
    Ok(())
}

fn format_dependent(dep: &PciHotResetDevice) -> String {
    format!(
        "{:04x}:{:02x}:{:02x}.{:x} (group {})",
        dep.segment,
        dep.bus,
        dep.devfn >> 3,
        dep.devfn & 0x7,
        dep.group_id
    )
}

fn iommu_group_id(sysfs_devices: &Path, slot: &str) -> Result<u32> {
    let link = sysfs_devices.join(slot).join("iommu_group");
    let group = link
        .canonicalize()
        .with_context(|| format!("failed to resolve IOMMU group of {slot}"))?;
    group
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.parse().ok())
        .with_context(|| format!("invalid IOMMU group path {}", group.display()))
}

fn wait_for_vfio_ready(
    sysfs_devices: &Path,
    devices: &BTreeSet<String>,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    let deadline = started + timeout;
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
                info!(
                    count = devices.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "all sanitized GPUs are VFIO-ready"
                );
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
    driver_is_vfio(&device)
        && device.join("iommu_group").canonicalize().is_ok()
        && fs_err::read_dir(device.join("vfio-dev"))
            .ok()
            .and_then(|mut entries| entries.next())
            .is_some()
}

fn driver_is_vfio(device: &Path) -> bool {
    device
        .join("driver")
        .canonicalize()
        .ok()
        .and_then(|path| path.file_name().map(|name| name == "vfio-pci"))
        .unwrap_or(false)
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

fn read_u16(file: &File, offset: u64) -> Result<u16> {
    let mut value = [0_u8; 2];
    file.read_exact_at(&mut value, offset)?;
    Ok(u16::from_le_bytes(value))
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
    fn formats_dependent_devices_with_pci_slot_and_function() {
        let dep = PciHotResetDevice {
            group_id: 46,
            segment: 0,
            bus: 0x0f,
            devfn: 0x1,
        };
        assert_eq!(format_dependent(&dep), "0000:0f:00.1 (group 46)");
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
