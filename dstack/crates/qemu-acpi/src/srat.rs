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

const HOLE_640K_START: u64 = 0xa_0000;
const HOLE_640K_END: u64 = 0x10_0000;

fn memory_affinity(base: u64, length: u64, node: u32, enabled: bool) -> Vec<u8> {
    let mut out = vec![1, 40];
    out.extend_from_slice(&node.to_le_bytes()); // proximity domain
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&base.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(enabled as u32).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

/// Where RAM above the 32-bit PCI hole starts.
fn above_4g_mem_start(memory_size: u64, below_4g: u64, pci_hole64_size: Option<u64>) -> u64 {
    let high_end = 0x1_0000_0000u64.saturating_add(memory_size - below_4g);
    // qemu64 is an AMD CPU model. QEMU relocates RAM above 1 TiB when the
    // rounded end of RAM plus the Q35 64-bit PCI hole reaches AMD's
    // reserved HyperTransport range (pc_max_used_gpa/pc_memory_init).
    let pci_hole_start = high_end.saturating_add((1 << 30) - 1) & !((1 << 30) - 1);
    let pci_hole_size = pci_hole64_size.unwrap_or(1 << 35);
    let max_used = pci_hole_start
        .saturating_add(pci_hole_size)
        .saturating_sub(1);
    if max_used >= 0xfd_0000_0000 {
        0x100_0000_0000
    } else {
        0x1_0000_0000
    }
}

/// SRAT for `nodes` NUMA nodes sharing vCPUs and RAM evenly, in order.
pub(crate) fn build(
    cpu_count: u32,
    memory_size: u64,
    pci_hole64_size: Option<u64>,
    nodes: u32,
) -> Vec<u8> {
    let mut body = Vec::new();
    let cpus_per_node = cpu_count / nodes;
    for index in 0..cpu_count {
        let node = index / cpus_per_node;
        if index < 255 {
            body.extend_from_slice(&[0, 16, node as u8, index as u8]);
            body.extend_from_slice(&1u32.to_le_bytes());
            body.extend_from_slice(&[0, 0, 0, 0]);
            body.extend_from_slice(&0u32.to_le_bytes());
        } else {
            body.extend_from_slice(&[2, 24]);
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&node.to_le_bytes());
            body.extend_from_slice(&index.to_le_bytes());
            body.extend_from_slice(&1u32.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
        }
    }
    let below_4g = if memory_size >= 0xb000_0000 {
        0x8000_0000
    } else {
        memory_size
    };
    let above_4g = above_4g_mem_start(memory_size, below_4g, pci_hole64_size);
    // QEMU's build_srat(): each node's range, cut around the 640K and the
    // 32-bit PCI holes, then disabled entries up to `nodes + 2`.
    let mut entries = 0;
    let mut push = |base, length, node| {
        body.extend_from_slice(&memory_affinity(base, length, node, true));
        entries += 1;
    };
    let mut next_base = 0;
    for node in 0..nodes {
        let mut mem_base = next_base;
        let mut mem_len = memory_size / u64::from(nodes);
        next_base = mem_base + mem_len;
        if mem_base <= HOLE_640K_START && next_base > HOLE_640K_START {
            mem_len -= next_base - HOLE_640K_START;
            if mem_len > 0 {
                push(mem_base, mem_len, node);
            }
            if next_base <= HOLE_640K_END {
                next_base = HOLE_640K_END;
                continue;
            }
            mem_base = HOLE_640K_END;
            mem_len = next_base - HOLE_640K_END;
        }
        if mem_base <= below_4g && next_base > below_4g {
            mem_len -= next_base - below_4g;
            if mem_len > 0 {
                push(mem_base, mem_len, node);
            }
            mem_base = above_4g;
            mem_len = next_base - below_4g;
            next_base = mem_base + mem_len;
        }
        if mem_len > 0 {
            push(mem_base, mem_len, node);
        }
    }
    for _ in entries..nodes + 2 {
        body.extend_from_slice(&memory_affinity(0, 0, 0, false));
    }
    let mut out = header((48 + body.len()) as u32);
    out.extend_from_slice(&body);
    out
}
