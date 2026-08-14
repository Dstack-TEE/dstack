// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Fixed-layout ACPI tables emitted by QEMU's Q35 machine.
//!
//! Checksums stay zero in these blobs. QEMU's table-loader asks firmware to
//! calculate them after it has relocated the table pointers.

const OEM_ID: &[u8; 6] = b"BOCHS ";
const OEM_TABLE_ID: &[u8; 8] = b"BXPC    ";
const CREATOR_ID: &[u8; 4] = b"BXPC";

const DSDT_OFFSET: u32 = 64;
const PM_IO_BASE: u32 = 0x0600;
const GPE0_IO_BASE: u32 = 0x0620;
const SCI_INTERRUPT: u16 = 9;
const SMI_COMMAND_PORT: u32 = 0x00b2;
const ACPI_ENABLE_COMMAND: u8 = 2;
const ACPI_DISABLE_COMMAND: u8 = 3;
const LOCAL_APIC_ADDRESS: u32 = 0xfee0_0000;
const IO_APIC_ADDRESS: u32 = 0xfec0_0000;
const MCFG_BASE: u64 = 0xe000_0000;

fn put(out: &mut [u8], offset: usize, bytes: &[u8]) {
    out[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// Standard 36-byte ACPI system-description-table header.
fn header(signature: &[u8; 4], length: usize, revision: u8) -> Vec<u8> {
    let mut out = vec![0; length];
    put(&mut out, 0, signature);
    put(&mut out, 4, &(length as u32).to_le_bytes());
    out[8] = revision;
    put(&mut out, 10, OEM_ID);
    put(&mut out, 16, OEM_TABLE_ID);
    put(&mut out, 24, &1u32.to_le_bytes());
    put(&mut out, 28, CREATOR_ID);
    put(&mut out, 32, &1u32.to_le_bytes());
    out
}

/// Firmware ACPI Control Structure. Unlike the other records it has no SDT
/// header and is never checksummed.
pub(crate) fn facs() -> Vec<u8> {
    let mut out = vec![0; 64];
    put(&mut out, 0, b"FACS");
    put(&mut out, 4, &64u32.to_le_bytes());
    out
}

/// Fixed ACPI Description Table for Q35/ICH9.
pub(crate) fn fadt(smm: bool, cpu_count: u32) -> Vec<u8> {
    let mut out = header(b"FACP", 244, 3);
    // Firmware patches FIRMWARE_CTRL; DSDT is blob-relative until relocation.
    put(&mut out, 40, &DSDT_OFFSET.to_le_bytes());
    out[44] = 1; // Multiple APIC interrupt model.
    put(&mut out, 46, &SCI_INTERRUPT.to_le_bytes());
    if smm {
        put(&mut out, 48, &SMI_COMMAND_PORT.to_le_bytes());
        out[52] = ACPI_ENABLE_COMMAND;
        out[53] = ACPI_DISABLE_COMMAND;
    }
    // Legacy fixed-register addresses and lengths.
    put(&mut out, 56, &PM_IO_BASE.to_le_bytes()); // PM1a event block
    put(&mut out, 64, &(PM_IO_BASE + 4).to_le_bytes()); // PM1a control block
    put(&mut out, 76, &(PM_IO_BASE + 8).to_le_bytes()); // PM timer
    put(&mut out, 80, &GPE0_IO_BASE.to_le_bytes());
    out[88] = 4; // PM1 event length
    out[89] = 2; // PM1 control length
    out[91] = 4; // PM timer length
    out[92] = 16; // GPE0 block length
    put(&mut out, 96, &0x0fffu16.to_le_bytes()); // C2 unsupported
    put(&mut out, 98, &0x0fffu16.to_le_bytes()); // C3 unsupported
    out[108] = 0x32; // RTC century register
    put(&mut out, 109, &2u16.to_le_bytes()); // 8042 present
    let mut flags = (1 << 0) | (1 << 2) | (1 << 5) | (1 << 7) | (1 << 10) | (1 << 15);
    if cpu_count > 8 {
        flags |= 1 << 18; // Force APIC clustered logical destination mode.
    }
    put(&mut out, 112, &(flags as u32).to_le_bytes());
    // Reset register: System I/O, byte access, port 0xcf9; reset value 0x0f.
    out[116] = 1;
    out[117] = 8;
    put(&mut out, 120, &0x0cf9u64.to_le_bytes());
    out[128] = 0x0f;
    // X_FIRMWARE_CTRL is zero; X_DSDT repeats the blob-relative DSDT offset.
    put(&mut out, 140, &u64::from(DSDT_OFFSET).to_le_bytes());
    gas(&mut out, 148, 32, PM_IO_BASE);
    gas(&mut out, 172, 16, PM_IO_BASE + 4);
    gas(&mut out, 208, 32, PM_IO_BASE + 8);
    gas(&mut out, 220, 128, GPE0_IO_BASE);
    out
}

fn gas(out: &mut [u8], offset: usize, width: u8, address: u32) {
    out[offset] = 1; // System I/O
    out[offset + 1] = width;
    put(out, offset + 4, &u64::from(address).to_le_bytes());
}

/// Multiple APIC Description Table.
pub(crate) fn madt(cpu_count: u32, pic: bool, legacy_irq_overrides: bool) -> Vec<u8> {
    let legacy_cpus = cpu_count.min(255) as usize;
    let x2apic_cpus = cpu_count.saturating_sub(255) as usize;
    let cpu_bytes = legacy_cpus * 8 + x2apic_cpus * 16;
    let interrupt_tail = if legacy_irq_overrides { 172 } else { 62 };
    let lint_len = if cpu_count <= 255 { 6 } else { 12 };
    let tail_len = interrupt_tail + lint_len;
    let mut out = header(b"APIC", 44 + cpu_bytes + tail_len, 3);
    put(&mut out, 36, &LOCAL_APIC_ADDRESS.to_le_bytes());
    put(&mut out, 40, &(pic as u32).to_le_bytes());
    for index in 0..cpu_count {
        if index < 255 {
            let at = 44 + index as usize * 8;
            put(&mut out, at, &[0, 8, index as u8, index as u8]);
            put(&mut out, at + 4, &1u32.to_le_bytes());
        } else {
            let at = 44 + legacy_cpus * 8 + (index as usize - 255) * 16;
            put(&mut out, at, &[9, 16, 0, 0]);
            put(&mut out, at + 4, &index.to_le_bytes());
            put(&mut out, at + 8, &1u32.to_le_bytes());
            put(&mut out, at + 12, &index.to_le_bytes());
        }
    }
    let at = 44 + cpu_bytes;
    put(&mut out, at, &[1, 12, 0, 0]); // I/O APIC ID 0
    put(&mut out, at + 4, &IO_APIC_ADDRESS.to_le_bytes());
    if legacy_irq_overrides {
        for irq in 0u8..16 {
            let entry = at + 12 + usize::from(irq) * 10;
            put(&mut out, entry, &[2, 10, 0, irq]);
            let gsi = if irq == 0 { 2 } else { u32::from(irq) };
            put(&mut out, entry + 4, &gsi.to_le_bytes());
            put(&mut out, entry + 8, &5u16.to_le_bytes());
        }
    } else {
        // IRQ0 -> GSI2, then overrides for IRQ5/9/10/11 (level, active-low).
        put(&mut out, at + 12, &[2, 10, 0, 0, 2, 0, 0, 0, 0, 0]);
        for (n, irq) in [5u8, 9, 10, 11].into_iter().enumerate() {
            let entry = at + 22 + n * 10;
            put(&mut out, entry, &[2, 10, 0, irq]);
            put(&mut out, entry + 4, &u32::from(irq).to_le_bytes());
            put(&mut out, entry + 8, &13u16.to_le_bytes());
        }
    }
    let lint = at + interrupt_tail;
    if cpu_count <= 255 {
        put(&mut out, lint, &[4, 6, 0xff, 0, 0, 1]);
    } else {
        put(&mut out, lint, &[0x0a, 12, 0, 0]);
        put(&mut out, lint + 4, &u32::MAX.to_le_bytes());
        put(&mut out, lint + 8, &[1, 0, 0, 0]);
    }
    out
}

pub(crate) fn mcfg() -> Vec<u8> {
    let mut out = header(b"MCFG", 60, 1);
    put(&mut out, 44, &MCFG_BASE.to_le_bytes());
    out[55] = 0xff; // buses 0..255, segment group zero
    out
}

pub(crate) fn waet() -> Vec<u8> {
    let mut out = header(b"WAET", 40, 1);
    put(&mut out, 36, &2u32.to_le_bytes()); // ACPI PM timer is reliable
    out
}

pub(crate) fn rsdt(entries: &[u32]) -> Vec<u8> {
    let mut out = header(b"RSDT", 36 + entries.len() * 4, 1);
    for (index, entry) in entries.iter().enumerate() {
        put(&mut out, 36 + index * 4, &entry.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facs_matches_qemu() {
        crate::dsdt::fixture::assert_blob_range(&facs(), 0, 64);
    }
    #[test]
    fn fadt_matches_qemu() {
        crate::dsdt::fixture::assert_blob_range(&fadt(false, 1), 8322, 8566);
    }
    #[test]
    fn madt_matches_qemu() {
        crate::dsdt::fixture::assert_blob_range(&madt(1, false, false), 8566, 8686);
    }
    #[test]
    fn mcfg_matches_qemu() {
        crate::dsdt::fixture::assert_blob_range(&mcfg(), 8686, 8746);
    }
    #[test]
    fn waet_matches_qemu() {
        crate::dsdt::fixture::assert_blob_range(&waet(), 8746, 8786);
    }
    #[test]
    fn rsdt_matches_qemu() {
        crate::dsdt::fixture::assert_blob_range(&rsdt(&[8322, 8566, 8686, 8746]), 8786, 8838);
    }
}
