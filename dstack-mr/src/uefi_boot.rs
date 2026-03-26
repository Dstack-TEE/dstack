// SPDX-FileCopyrightText: © 2025 dstack-k8s contributors
//
// SPDX-License-Identifier: Apache-2.0

//! UEFI disk boot (UKI mode) measurement for TDX.
//!
//! Computes RTMR[1] and RTMR[2] for the boot path:
//!   OVMF → systemd-boot (EFI app) → UKI (EFI app) → vmlinuz (EFI app)
//!
//! Verified against TDX hardware CCEL event log. All events match.

use crate::kernel::authenticode_sha384_hash;
use crate::{measure_sha384, utf16_encode};
use anyhow::{bail, Context, Result};

/// Compute RTMR[1] event log for UEFI disk boot.
///
/// Events in MR[2] (→ RTMR[1]), verified against hardware:
///   [0] EV_EFI_ACTION: "Calling EFI Application from Boot Option"
///   [1] EV_SEPARATOR: SHA384(0x00000000)
///   [2] EV_EFI_GPT_EVENT: SHA384(GPT header + non-empty partition entries)
///   [3] EV_EFI_BOOT_SERVICES_APPLICATION: systemd-boot Authenticode hash
///   [4] EV_EFI_BOOT_SERVICES_APPLICATION: UKI Authenticode hash
///   [5] EV_EFI_BOOT_SERVICES_APPLICATION: vmlinuz Authenticode hash
///       (UKI EFI stub calls LoadImage for embedded vmlinuz)
///   [6] EV_EFI_ACTION: "Exit Boot Services Invocation"
///   [7] EV_EFI_ACTION: "Exit Boot Services Returned with Success"
pub fn rtmr1_log(
    bootloader_data: &[u8],
    uki_data: &[u8],
    vmlinuz_data: &[u8],
    disk_path: Option<&str>,
) -> Result<Vec<Vec<u8>>> {
    let bootloader_hash =
        authenticode_sha384_hash(bootloader_data).context("bootloader authenticode hash")?;
    let uki_hash = authenticode_sha384_hash(uki_data).context("UKI authenticode hash")?;
    let vmlinuz_hash =
        authenticode_sha384_hash(vmlinuz_data).context("vmlinuz authenticode hash")?;

    let mut log = vec![
        measure_sha384(b"Calling EFI Application from Boot Option"),
        measure_sha384(&[0x00, 0x00, 0x00, 0x00]), // separator
    ];

    // GPT event: SHA384 of GPT header + non-empty partition entries
    if let Some(disk) = disk_path {
        let gpt_digest = compute_gpt_event_digest(disk)?;
        log.push(gpt_digest);
    }

    log.push(bootloader_hash);
    log.push(uki_hash);
    log.push(vmlinuz_hash);
    log.push(measure_sha384(b"Exit Boot Services Invocation"));
    log.push(measure_sha384(b"Exit Boot Services Returned with Success"));

    Ok(log)
}

/// Compute RTMR[2] event log for UEFI disk boot.
///
/// Events in MR[3] (→ RTMR[2]), verified against hardware:
///   [0] EV_EVENT_TAG "LOADED_IMAGE::LoadOptions": SHA384(cmdline as UTF-16LE + null terminator)
///   [1] EV_EVENT_TAG "Linux initrd": SHA384(initrd data)
///
/// The Linux EFI stub converts cmdline to UTF-16LE before measuring.
pub fn rtmr2_log(cmdline: &str, initrd_data: &[u8]) -> Vec<Vec<u8>> {
    // Cmdline: convert to UTF-16LE with null terminator (matches Linux EFI stub)
    let mut utf16_cmdline = utf16_encode(cmdline);
    utf16_cmdline.extend([0, 0]); // null terminator
    let cmdline_hash = measure_sha384(&utf16_cmdline);

    let initrd_hash = measure_sha384(initrd_data);

    vec![cmdline_hash, initrd_hash]
}

/// Compute GPT event digest from a raw disk image.
///
/// Format: UEFI_GPT_DATA = { EFI_PARTITION_TABLE_HEADER (92B), NumberOfPartitions (u64), Partitions[] }
///
/// IMPORTANT: OVMF only includes NON-EMPTY partition entries (PartitionTypeGUID != 0).
/// The GPT header's NumberOfPartitionEntries field says 128 (allocated slots),
/// but the event's NumberOfPartitions only counts actual partitions with data.
fn compute_gpt_event_digest(disk_path: &str) -> Result<Vec<u8>> {
    let data = std::fs::read(disk_path).context("failed to read disk image")?;

    let gpt_offset = 512; // GPT header at LBA 1
    if data.len() < gpt_offset + 92 {
        bail!("disk too small for GPT header");
    }
    if &data[gpt_offset..gpt_offset + 8] != b"EFI PART" {
        bail!("no GPT signature at LBA 1");
    }

    let header_size =
        u32::from_le_bytes(data[gpt_offset + 12..gpt_offset + 16].try_into()?) as usize;
    let max_entries =
        u32::from_le_bytes(data[gpt_offset + 80..gpt_offset + 84].try_into()?) as usize;
    let entry_size =
        u32::from_le_bytes(data[gpt_offset + 84..gpt_offset + 88].try_into()?) as usize;
    let entries_lba =
        u64::from_le_bytes(data[gpt_offset + 72..gpt_offset + 80].try_into()?) as usize;
    let entries_offset = entries_lba * 512;

    // Collect non-empty partitions (PartitionTypeGUID != all zeros)
    let mut actual_partitions = Vec::new();
    for i in 0..max_entries {
        let entry_off = entries_offset + i * entry_size;
        if entry_off + entry_size > data.len() {
            break;
        }
        let type_guid = &data[entry_off..entry_off + 16];
        if type_guid != [0u8; 16] {
            actual_partitions.push(&data[entry_off..entry_off + entry_size]);
        }
    }

    // Build UEFI_GPT_DATA: header + actual partition count + non-empty entries
    let mut gpt_data = Vec::new();
    gpt_data.extend_from_slice(&data[gpt_offset..gpt_offset + header_size]);
    gpt_data.extend_from_slice(&(actual_partitions.len() as u64).to_le_bytes());
    for entry in &actual_partitions {
        gpt_data.extend_from_slice(entry);
    }

    Ok(measure_sha384(&gpt_data))
}
