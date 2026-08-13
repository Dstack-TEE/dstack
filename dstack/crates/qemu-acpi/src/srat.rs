// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

fn header(length: u32) -> Vec<u8> {
    let mut out = b"SRAT".to_vec();
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&[1, 0]);
    out.extend_from_slice(b"BOCHS ");
    out.extend_from_slice(b"BXPC    ");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(b"BXPC");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

fn memory_affinity(base: u64, length: u64, enabled: bool) -> Vec<u8> {
    let mut out = vec![1, 40];
    out.extend_from_slice(&0u32.to_le_bytes()); // proximity domain
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&base.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(enabled as u32).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

pub(crate) fn build(cpu_count: u32, memory_size: u64, pci_hole64_size: Option<u64>) -> Vec<u8> {
    let mut body = Vec::new();
    for index in 0..cpu_count {
        if index < 255 {
            body.extend_from_slice(&[0, 16, 0, index as u8]);
            body.extend_from_slice(&1u32.to_le_bytes());
            body.extend_from_slice(&[0, 0, 0, 0]);
            body.extend_from_slice(&0u32.to_le_bytes());
        } else {
            body.extend_from_slice(&[2, 24]);
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&index.to_le_bytes());
            body.extend_from_slice(&1u32.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
        }
    }
    let low = if memory_size >= 0xb000_0000 {
        0x8000_0000
    } else {
        memory_size
    };
    body.extend_from_slice(&memory_affinity(0, low.min(0xa_0000), true));
    if low > 0x10_0000 {
        body.extend_from_slice(&memory_affinity(0x10_0000, low - 0x10_0000, true));
    } else {
        body.extend_from_slice(&memory_affinity(0, 0, false));
    }
    if memory_size > low {
        let high_length = memory_size - low;
        let high_end = 0x1_0000_0000u64.saturating_add(high_length);
        // qemu64 is an AMD CPU model. QEMU relocates RAM above 1 TiB when the
        // rounded end of RAM plus the Q35 64-bit PCI hole reaches AMD's
        // reserved HyperTransport range (pc_max_used_gpa/pc_memory_init).
        let pci_hole_start = high_end.saturating_add((1 << 30) - 1) & !((1 << 30) - 1);
        let pci_hole_size = pci_hole64_size.unwrap_or(1 << 35);
        let max_used = pci_hole_start
            .saturating_add(pci_hole_size)
            .saturating_sub(1);
        let high_base = if max_used >= 0xfd_0000_0000 {
            0x100_0000_0000
        } else {
            0x1_0000_0000
        };
        body.extend_from_slice(&memory_affinity(high_base, high_length, true));
    } else {
        body.extend_from_slice(&memory_affinity(0, 0, false));
    }
    let mut out = header((48 + body.len()) as u32);
    out.extend_from_slice(&body);
    out
}
