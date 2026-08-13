// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::aml_patch::{adjust_package, grow_package, integer};
use crate::cpu;
use crate::{AcpiBlobs, Error, MachineConfig, TABLE_BLOB_SIZE};

fn read_u32(data: &[u8], offset: usize, context: &str) -> Result<u32, Error> {
    let bytes = data
        .get(offset..offset.saturating_add(4))
        .and_then(|value| <&[u8; 4]>::try_from(value).ok())
        .ok_or_else(|| Error::MalformedTables(format!("truncated {context}")))?;
    Ok(u32::from_le_bytes(*bytes))
}

fn write_bytes(data: &mut [u8], offset: usize, value: &[u8], context: &str) -> Result<(), Error> {
    let end = offset
        .checked_add(value.len())
        .ok_or_else(|| Error::MalformedTables(format!("{context} offset overflow")))?;
    let destination = data
        .get_mut(offset..end)
        .ok_or_else(|| Error::MalformedTables(format!("truncated {context}")))?;
    destination.copy_from_slice(value);
    Ok(())
}

#[derive(Clone, Copy)]
/// Patch points in a QEMU-generated compatibility fixture.
///
/// Every offset is relative to the start of the DSDT table, which starts at
/// byte 64 in `etc/acpi/tables`, immediately after QEMU's 64-byte FACS. The
/// first 36 DSDT bytes are its ACPI header. The `*_pkg` fields identify AML
/// package-length operands that enclose mutable data; `*_insert` fields are
/// insertion points; `max_cpus` is the integer used by CSCN; and
/// `pci_packages` enclose the root-bus slot devices inserted at `pci_insert`.
///
/// Separate fixtures are required for CPU hotplug on/off and PXB/NUMA because
/// QEMU emits structurally different AML, not merely different field values.
/// For a new compatibility profile, generate the four base fixtures with the
/// pinned reference build described in `fixtures/README.md`, disassemble the
/// DSDT with `iasl`, map the relevant ASL object back to its AML byte sequence,
/// and record the package-length or insertion offset relative to the DSDT
/// signature. Verify every offset against the reference binary and its
/// one-device output. Never infer offsets from a Rust-generated blob.
struct Layout {
    /// Trimmed QEMU `etc/acpi/tables` fixture used as the immutable template.
    base: &'static [u8],
    /// Package length of `Scope (\_SB)` containing the CPU hotplug objects.
    cpu_scope_pkg: usize,
    /// Package length of `Device (CPUS)`.
    cpu_device_pkg: usize,
    /// Package length of `Method (CTFY)` (CPU notification dispatch).
    ctfy_pkg: usize,
    /// End of CTFY's existing `Switch`, where CPU notify cases are inserted.
    ctfy_insert: usize,
    /// Inner-to-outer package lengths enclosing CSCN's maximum-CPU integer.
    cscn_packages: [usize; 3],
    /// One-byte integer operand in CSCN that encodes the maximum CPU count.
    max_cpus: usize,
    /// End of the first CPU device, where additional CPU devices are inserted.
    cpu_insert: usize,
    /// Package length of `Device (C000)`, needed when adding `_PXM` for NUMA.
    cpu0_pkg: usize,
    /// Inner and outer PCI root packages enclosing generated slot devices.
    pci_packages: [usize; 2],
    /// End of the PCI root device list, where slots/root ports are inserted.
    pci_insert: usize,
    /// Whether the template already contains CPU `_PXM` objects.
    numa_base: bool,
    /// Whether the template already contains an SRAT table.
    srat_base: bool,
    /// Whether generated GPU ports belong below a PXB rather than the root bus.
    pxb: bool,
}

const V9_PRE92: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-9.1-q35-base.bin"),
    cpu_scope_pkg: 6275,
    cpu_device_pkg: 6453,
    ctfy_pkg: 6491,
    ctfy_insert: 6508,
    cscn_packages: [6768, 6753, 6708],
    max_cpus: 6776,
    cpu_insert: 7282,
    cpu0_pkg: 7226,
    pci_packages: [7763, 7771],
    pci_insert: 7858,
    numa_base: false,
    srat_base: false,
    pxb: false,
};
const V9_2: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-9.2-q35-base.bin"),
    cpu_scope_pkg: 6293,
    cpu_device_pkg: 6471,
    ctfy_pkg: 6509,
    ctfy_insert: 6526,
    cscn_packages: [6786, 6771, 6726],
    max_cpus: 6794,
    cpu_insert: 7300,
    cpu0_pkg: 7244,
    pci_packages: [7781, 7789],
    pci_insert: 7876,
    numa_base: false,
    srat_base: false,
    pxb: false,
};
const V10: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-10.0-q35-base.bin"),
    cpu_scope_pkg: 6293,
    cpu_device_pkg: 6471,
    ctfy_pkg: 6509,
    ctfy_insert: 6526,
    cscn_packages: [6797, 6779, 6726],
    max_cpus: 6805,
    cpu_insert: 7367,
    cpu0_pkg: 7311,
    pci_packages: [7848, 7856],
    pci_insert: 7943,
    numa_base: false,
    srat_base: false,
    pxb: false,
};
const V11_0: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-11.0-q35-base.bin"),
    cpu_scope_pkg: 6293,
    cpu_device_pkg: 6458,
    ctfy_pkg: 6496,
    ctfy_insert: 6513,
    cscn_packages: [6784, 6766, 6713],
    max_cpus: 6792,
    cpu_insert: 7354,
    cpu0_pkg: 7298,
    pci_packages: [7835, 7843],
    pci_insert: 7930,
    numa_base: false,
    srat_base: false,
    pxb: false,
};
const V11_1: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-11.1-q35-base.bin"),
    ..V11_0
};
const V9_PRE92_PXB: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-9.1-q35-numa-pxb-base.bin"),
    cpu_insert: 7288,
    pci_packages: [9838, 9846],
    pci_insert: 9933,
    numa_base: true,
    srat_base: true,
    pxb: true,
    ..V9_PRE92
};
const V9_2_PXB: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-9.2-q35-numa-pxb-base.bin"),
    cpu_insert: 7306,
    pci_packages: [9856, 9864],
    pci_insert: 9951,
    numa_base: true,
    srat_base: true,
    pxb: true,
    ..V9_2
};
const V10_PXB: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-10.0-q35-numa-pxb-base.bin"),
    cpu_insert: 7373,
    pci_packages: [9923, 9931],
    pci_insert: 10018,
    numa_base: true,
    srat_base: true,
    pxb: true,
    ..V10
};
const V11_0_PXB: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-11.0-q35-numa-pxb-base.bin"),
    cpu_insert: 7360,
    pci_packages: [9910, 9918],
    pci_insert: 10005,
    numa_base: true,
    srat_base: true,
    pxb: true,
    ..V11_0
};
const V11_1_PXB: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-11.1-q35-numa-pxb-base.bin"),
    ..V11_0_PXB
};

const V9_PRE92_HP: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-9.1-q35-hotplug-off-base.bin"),
    cpu_scope_pkg: 5942,
    cpu_device_pkg: 6120,
    ctfy_pkg: 6158,
    ctfy_insert: 6175,
    cscn_packages: [6435, 6420, 6375],
    max_cpus: 6443,
    cpu_insert: 6949,
    cpu0_pkg: 6893,
    pci_packages: [7354, 7362],
    pci_insert: 7449,
    numa_base: false,
    srat_base: false,
    pxb: false,
};
const V9_2_HP: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-9.2-q35-hotplug-off-base.bin"),
    ..V9_PRE92_HP
};
const V10_HP: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-10.0-q35-hotplug-off-base.bin"),
    cscn_packages: [6446, 6428, 6375],
    max_cpus: 6454,
    cpu_insert: 7016,
    cpu0_pkg: 6960,
    pci_packages: [7421, 7429],
    pci_insert: 7516,
    ..V9_PRE92_HP
};
const V11_0_HP: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-11.0-q35-hotplug-off-base.bin"),
    cpu_device_pkg: 6107,
    ctfy_pkg: 6145,
    ctfy_insert: 6162,
    cscn_packages: [6433, 6415, 6362],
    max_cpus: 6441,
    cpu_insert: 7003,
    cpu0_pkg: 6947,
    pci_packages: [7408, 7416],
    pci_insert: 7503,
    ..V9_PRE92_HP
};
const V11_1_HP: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-11.1-q35-hotplug-off-base.bin"),
    ..V11_0_HP
};
const V9_PRE92_HP_PXB: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-9.1-q35-hotplug-off-numa-pxb-base.bin"),
    cpu_insert: 6955,
    pci_packages: [9429, 9437],
    pci_insert: 9524,
    numa_base: true,
    srat_base: true,
    pxb: true,
    ..V9_PRE92_HP
};
const V9_2_HP_PXB: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-9.2-q35-hotplug-off-numa-pxb-base.bin"),
    ..V9_PRE92_HP_PXB
};
const V10_HP_PXB: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-10.0-q35-hotplug-off-numa-pxb-base.bin"),
    cpu_insert: 7022,
    pci_packages: [9496, 9504],
    pci_insert: 9591,
    numa_base: true,
    srat_base: true,
    pxb: true,
    ..V10_HP
};
const V11_0_HP_PXB: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-11.0-q35-hotplug-off-numa-pxb-base.bin"),
    cpu_insert: 7009,
    pci_packages: [9483, 9491],
    pci_insert: 9578,
    numa_base: true,
    srat_base: true,
    pxb: true,
    ..V11_0_HP
};
const V11_1_HP_PXB: Layout = Layout {
    base: include_bytes!("../fixtures/qemu-11.1-q35-hotplug-off-numa-pxb-base.bin"),
    ..V11_0_HP_PXB
};

fn pci_slot(slot: u32) -> Vec<u8> {
    let name = format!("S{:02X}_", slot * 8);
    let mut out = vec![0x5b, 0x82, 0x0f];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&[0x08, b'_', b'A', b'D', b'R', 0x0c]);
    out.extend_from_slice(&(slot << 16).to_le_bytes());
    out
}

fn pcie_root_port(slot: u32) -> Result<Vec<u8>, Error> {
    let mut child = Vec::new();
    child.extend_from_slice(b"S00_");
    child.extend_from_slice(&[0x08, b'_', b'A', b'D', b'R', 0x00]);
    let child = crate::aml_patch::package(&[0x5b, 0x82], &child)?;

    let mut body = Vec::new();
    body.extend_from_slice(format!("S{:02X}_", slot * 8).as_bytes());
    body.extend_from_slice(&[0x08, b'_', b'A', b'D', b'R', 0x0c]);
    body.extend_from_slice(&(slot << 16).to_le_bytes());
    body.extend_from_slice(&child);
    crate::aml_patch::package(&[0x5b, 0x82], &body)
}

fn mutate_cpus(used: &mut Vec<u8>, count: u32, layout: Layout, numa: bool) -> Result<(), Error> {
    let base_len = used.len();
    let mut numa_growth = 0;
    if numa && !layout.numa_base {
        let pxm = [0x08, b'_', b'P', b'X', b'M', 0x00];
        used.splice(64 + layout.cpu_insert..64 + layout.cpu_insert, pxm);
        let width = grow_package(used, 64 + layout.cpu0_pkg, pxm.len())?;
        numa_growth = pxm.len() + width.max(0) as usize;
    }
    if count == 1 {
        let growth = used.len() - base_len;
        grow_package(used, 64 + layout.cpu_device_pkg, growth)?;
        let growth = used.len() - base_len;
        grow_package(used, 64 + layout.cpu_scope_pkg, growth)?;
        return Ok(());
    }
    let mut mappings = Vec::new();
    let mut objects = Vec::new();
    for index in 1..count {
        mappings.extend_from_slice(&cpu::notify_case(index)?);
        objects.extend_from_slice(&cpu::object(index, numa)?);
    }
    // Work from high offsets to low offsets so base offsets remain valid.
    used.splice(
        64 + layout.cpu_insert + numa_growth..64 + layout.cpu_insert + numa_growth,
        objects,
    );
    let maximum = integer(count);
    used.splice(
        64 + layout.max_cpus..64 + layout.max_cpus + 1,
        maximum.iter().copied(),
    );
    used.splice(
        64 + layout.ctfy_insert..64 + layout.ctfy_insert,
        mappings.iter().copied(),
    );

    // Grow the packages enclosing the variable maximum-CPU integer.
    let ctfy_width = grow_package(used, 64 + layout.ctfy_pkg, mappings.len())?;
    let shift = mappings.len() as isize + ctfy_width;
    let integer_growth = maximum.len() - 1;
    let mut inner_growth = integer_growth;
    for original in layout.cscn_packages {
        let at = (64isize + original as isize + shift) as usize;
        let width = grow_package(used, at, inner_growth)?;
        inner_growth += width.max(0) as usize;
    }

    // CPUS Device and its containing _SB scope cover both methods and objects.
    let growth = used.len() - base_len;
    grow_package(used, 64 + layout.cpu_device_pkg, growth)?;
    let growth = used.len() - base_len;
    grow_package(used, 64 + layout.cpu_scope_pkg, growth)?;
    Ok(())
}

fn mutate_apic(used: &mut Vec<u8>, count: u32, pic: bool) -> Result<(), Error> {
    let start = used
        .windows(4)
        .position(|w| w == b"APIC")
        .ok_or_else(|| Error::MalformedTables("APIC".into()))?;
    let old_len = read_u32(used, start + 4, "APIC header")? as usize;
    write_bytes(used, start + 40, &(pic as u32).to_le_bytes(), "APIC flags")?;
    let tail_start = start + 44 + 8;
    let mut entries = Vec::new();
    for index in 0..count {
        if index < 255 {
            entries.extend_from_slice(&[0, 8, index as u8, index as u8]);
            entries.extend_from_slice(&1u32.to_le_bytes());
        } else {
            entries.extend_from_slice(&[9, 16, 0, 0]);
            entries.extend_from_slice(&index.to_le_bytes());
            entries.extend_from_slice(&1u32.to_le_bytes());
            entries.extend_from_slice(&index.to_le_bytes());
        }
    }
    let table_end = start
        .checked_add(old_len)
        .ok_or_else(|| Error::MalformedTables("APIC length overflow".into()))?;
    let mut tail = used
        .get(tail_start..table_end)
        .ok_or_else(|| Error::MalformedTables("invalid APIC length".into()))?
        .to_vec();
    if count > 255 {
        let truncated = tail
            .len()
            .checked_sub(6)
            .ok_or_else(|| Error::MalformedTables("truncated APIC tail".into()))?;
        tail.truncate(truncated);
        tail.extend_from_slice(&[0x0a, 12, 0, 0]);
        tail.extend_from_slice(&u32::MAX.to_le_bytes());
        tail.extend_from_slice(&[1, 0, 0, 0]);
    }
    entries.extend_from_slice(&tail);
    used.splice(start + 44..start + old_len, entries.iter().copied());
    let new_len = 44 + entries.len();
    write_bytes(
        used,
        start + 4,
        &(new_len as u32).to_le_bytes(),
        "APIC length",
    )?;
    Ok(())
}

fn update_rsdt(used: &mut [u8], numa: bool) -> Result<(), Error> {
    let rsdt = used
        .windows(4)
        .position(|w| w == b"RSDT")
        .ok_or_else(|| Error::MalformedTables("RSDT".into()))?;
    let normal: &[[u8; 4]] = &[*b"FACP", *b"APIC", *b"MCFG", *b"WAET"];
    let numa_tables: &[[u8; 4]] = &[*b"FACP", *b"APIC", *b"SRAT", *b"MCFG", *b"WAET"];
    for (entry, signature) in (if numa { numa_tables } else { normal }).iter().enumerate() {
        let target = used
            .windows(4)
            .position(|w| w == *signature)
            .ok_or_else(|| Error::MalformedTables(String::from_utf8_lossy(signature).into()))?;
        write_bytes(
            used,
            rsdt + 36 + entry * 4,
            &(target as u32).to_le_bytes(),
            "RSDT entry",
        )?;
    }
    Ok(())
}

pub(crate) fn build(config: &MachineConfig) -> Result<AcpiBlobs, Error> {
    let pxb = config.hugepages && config.num_gpus > 0;
    let hp = config.hotplug_off;
    let layout = match (config.qemu_version.compatibility(), pxb, hp) {
        (Some(crate::Compatibility::V8 | crate::Compatibility::V9Pre92), false, false) => V9_PRE92,
        (Some(crate::Compatibility::V8 | crate::Compatibility::V9Pre92), true, false) => {
            V9_PRE92_PXB
        }
        (Some(crate::Compatibility::V8 | crate::Compatibility::V9Pre92), false, true) => {
            V9_PRE92_HP
        }
        (Some(crate::Compatibility::V8 | crate::Compatibility::V9Pre92), true, true) => {
            V9_PRE92_HP_PXB
        }
        (Some(crate::Compatibility::V9_2), false, false) => V9_2,
        (Some(crate::Compatibility::V9_2), true, false) => V9_2_PXB,
        (Some(crate::Compatibility::V9_2), false, true) => V9_2_HP,
        (Some(crate::Compatibility::V9_2), true, true) => V9_2_HP_PXB,
        (Some(crate::Compatibility::V10), false, false) => V10,
        (Some(crate::Compatibility::V10), true, false) => V10_PXB,
        (Some(crate::Compatibility::V10), false, true) => V10_HP,
        (Some(crate::Compatibility::V10), true, true) => V10_HP_PXB,
        (Some(crate::Compatibility::V11_0), false, false) => V11_0,
        (Some(crate::Compatibility::V11_0), true, false) => V11_0_PXB,
        (Some(crate::Compatibility::V11_0), false, true) => V11_0_HP,
        (Some(crate::Compatibility::V11_0), true, true) => V11_0_HP_PXB,
        (Some(crate::Compatibility::V11_1), false, false) => V11_1,
        (Some(crate::Compatibility::V11_1), true, false) => V11_1_PXB,
        (Some(crate::Compatibility::V11_1), false, true) => V11_1_HP,
        (Some(crate::Compatibility::V11_1), true, true) => V11_1_HP_PXB,
        _ => return Err(Error::UnsupportedVersion(config.qemu_version)),
    };
    let requested = i64::from(config.num_nics) + i64::from(config.num_verity_volumes);
    let extra = requested - i64::from(!config.root_verity);
    let ports = if layout.pxb {
        u64::from(config.num_nvswitches)
    } else {
        u64::from(config.num_gpus) + u64::from(config.num_nvswitches)
    };
    let mut used = layout.base.to_vec();
    mutate_cpus(&mut used, config.cpu_count, layout, config.hugepages)?;
    let cpu_growth = used.len() - layout.base.len();

    let mut insert = 64 + layout.pci_insert + cpu_growth;
    let mut added = Vec::new();
    if extra < 0 {
        used.drain(insert - 17..insert);
        insert -= 17;
    } else {
        for index in 0..extra as u32 {
            added.extend_from_slice(&pci_slot(5 + index));
        }
    }
    let first_port_slot = 5 + requested.max(0) as u32;
    for index in 0..ports as u32 {
        added.extend_from_slice(&pcie_root_port(first_port_slot + index)?);
    }
    used.splice(insert..insert, added.iter().copied());
    let amount = added.len() as isize - if extra < 0 { 17 } else { 0 };
    let delta1 = adjust_package(&mut used, 64 + layout.pci_packages[0] + cpu_growth, amount)?;
    let second = (64 + layout.pci_packages[1] + cpu_growth) as isize + delta1;
    adjust_package(&mut used, second as usize, amount)?;

    let dsdt_len = read_u32(&used, 68, "DSDT header")? as usize;
    let actual_dsdt_len = dsdt_len
        .checked_add(cpu_growth)
        .and_then(|value| value.checked_add_signed(amount))
        .ok_or_else(|| Error::MalformedTables("DSDT length overflow".into()))?;
    write_bytes(
        &mut used,
        68,
        &(actual_dsdt_len as u32).to_le_bytes(),
        "DSDT length",
    )?;
    // Q35 maps at most 2 GiB of RAM below 4 GiB. The first PCI memory
    // window starts immediately after low RAM and ends at 0xdfffffff.
    // QEMU emits this range in the PCI0 _CRS DWordMemory descriptor.
    let low_ram_end = if config.memory_size >= 0xb000_0000 {
        0x8000_0000
    } else {
        config.memory_size as u32
    };
    let pci32_max = 0xdfff_ffffu32;
    let pci32_length = u64::from(pci32_max) + 1 - u64::from(low_ram_end);
    let descriptor = [
        0x87, 0x17, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff,
        0xff, 0xff, 0xdf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60,
    ];
    let at = used
        .windows(descriptor.len())
        .position(|window| window == descriptor)
        .ok_or_else(|| Error::MalformedTables("PCI32 resource".into()))?;
    write_bytes(
        &mut used,
        at + 10,
        &low_ram_end.to_le_bytes(),
        "PCI32 minimum",
    )?;
    write_bytes(
        &mut used,
        at + 22,
        &(pci32_length as u32).to_le_bytes(),
        "PCI32 length",
    )?;

    if let Some(size) = config.pci_hole64_size {
        let minimum = 0x3800_0000_0000u64;
        let marker = minimum.to_le_bytes();
        let at = used
            .windows(8)
            .position(|w| w == marker)
            .ok_or_else(|| Error::MalformedTables("PCI64 resource".into()))?;
        write_bytes(
            &mut used,
            at + 8,
            &minimum.wrapping_add(size).wrapping_sub(1).to_le_bytes(),
            "PCI64 maximum",
        )?;
        write_bytes(&mut used, at + 24, &size.to_le_bytes(), "PCI64 length")?;
    }
    mutate_apic(&mut used, config.cpu_count, config.pic)?;
    if config.hugepages {
        let srat = crate::srat::build(config.cpu_count, config.memory_size);
        if layout.srat_base {
            let start = used
                .windows(4)
                .position(|w| w == b"SRAT")
                .ok_or_else(|| Error::MalformedTables("SRAT".into()))?;
            let old = read_u32(&used, start + 4, "SRAT header")? as usize;
            used.splice(start..start + old, srat);
        } else {
            let mcfg = used
                .windows(4)
                .position(|w| w == b"MCFG")
                .ok_or_else(|| Error::MalformedTables("MCFG".into()))?;
            used.splice(mcfg..mcfg, srat);
            let rsdt = used
                .windows(4)
                .position(|w| w == b"RSDT")
                .ok_or_else(|| Error::MalformedTables("RSDT".into()))?;
            used.splice(rsdt + 44..rsdt + 44, 0u32.to_le_bytes());
            write_bytes(&mut used, rsdt + 4, &56u32.to_le_bytes(), "RSDT length")?;
        }
    }
    if config.smm {
        let facp = used
            .windows(4)
            .position(|w| w == b"FACP")
            .ok_or_else(|| Error::MalformedTables("FACP".into()))?;
        write_bytes(
            &mut used,
            facp + 48,
            &0xb2u32.to_le_bytes(),
            "FADT SMI command",
        )?;
        write_bytes(&mut used, facp + 52, &[2, 3], "FADT ACPI enable values")?;
    }
    if config.cpu_count > 8 {
        let facp = used
            .windows(4)
            .position(|w| w == b"FACP")
            .ok_or_else(|| Error::MalformedTables("FACP".into()))?;
        let at = facp + 112;
        let flags = read_u32(&used, at, "FADT flags")? | (1 << 18);
        write_bytes(&mut used, at, &flags.to_le_bytes(), "FADT flags")?;
    }
    update_rsdt(&mut used, config.hugepages)?;
    let blob_size = used.len().div_ceil(TABLE_BLOB_SIZE) * TABLE_BLOB_SIZE;
    used.resize(blob_size, 0);
    super::fw_cfg::finish(used)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::QemuVersion;

    fn config(nics: u32, volumes: u32) -> MachineConfig {
        MachineConfig {
            qemu_version: QemuVersion::new(11, 1, 0),
            cpu_count: 1,
            memory_size: 2 << 30,
            pic: false,
            smm: false,
            hugepages: false,
            num_gpus: 0,
            num_nvswitches: 0,
            num_nics: nics,
            num_verity_volumes: volumes,
            hotplug_off: false,
            root_verity: true,
            pci_hole64_size: None,
        }
    }

    #[test]
    fn one_nic_matches_qemu_byte_for_byte() -> Result<(), Error> {
        let actual = build(&config(1, 0))?;
        assert_eq!(
            actual.tables,
            include_bytes!("../fixtures/qemu-11.1-q35-one-nic.bin")
        );
        assert_eq!(
            actual.loader,
            include_bytes!("../fixtures/qemu-11.1-q35-one-nic-loader.bin")
        );
        assert_eq!(
            actual.rsdp,
            include_bytes!("../fixtures/qemu-11.1-q35-one-nic-rsdp.bin")
        );
        Ok(())
    }

    #[test]
    fn numa_loader_and_rsdp_match_qemu_byte_for_byte() -> Result<(), Error> {
        let mut numa = config(1, 0);
        numa.hugepages = true;
        let actual = build(&numa)?;
        assert_eq!(
            actual.loader,
            include_bytes!("../fixtures/qemu-11.1-q35-numa-one-nic-loader.bin")
        );
        assert_eq!(
            actual.rsdp,
            include_bytes!("../fixtures/qemu-11.1-q35-numa-one-nic-rsdp.bin")
        );
        Ok(())
    }

    fn qemu_hash(config: MachineConfig) -> Result<String, Error> {
        use sha2::{Digest, Sha256};

        // Keep ownership local so callers can conveniently mutate a base config.
        config.validate()?;
        Ok(hex::encode(Sha256::digest(build(&config)?.tables)))
    }

    #[test]
    fn qemu_version_and_cpu_goldens() -> Result<(), Error> {
        let versions = [
            (
                (8, 2, 0),
                "ff0c03c7f4026a95b0b2f2e08cef7d501a3a44b4df036c9f26de91828f0215f6",
            ),
            (
                (9, 1, 0),
                "ff0c03c7f4026a95b0b2f2e08cef7d501a3a44b4df036c9f26de91828f0215f6",
            ),
            (
                (9, 2, 1),
                "b183eba66c6e96556f28cefe60ca92620b82488fcefaf66167aad61e2b2e73d1",
            ),
            (
                (10, 0, 0),
                "d0410a8abdbba6d86a19a2eefd491376727e4e2d80c54349d7f30deca14ca6e1",
            ),
            (
                (11, 0, 0),
                "e211dd453e651ef320d28c65d23f578e96468614614e7b1172f18df5052d0f1f",
            ),
            (
                (11, 1, 0),
                "09f99e5dcf36b80a9258e849b3a9a70e7914244008e6a92a689eb22e4cc17a8f",
            ),
        ];
        for ((major, minor, micro), expected) in versions {
            let mut c = config(1, 0);
            c.qemu_version = QemuVersion::new(major, minor, micro);
            assert_eq!(qemu_hash(c)?, expected);
        }

        let cpus = [
            (
                1,
                "09f99e5dcf36b80a9258e849b3a9a70e7914244008e6a92a689eb22e4cc17a8f",
            ),
            (
                2,
                "1362c6f473801b34f93df4e2966b2d3350f7f9113750da78a2cb799177157da8",
            ),
            (
                8,
                "0f9fc08c5efd03f1cb3cfaa1a0a09c45dcfbc18183dbc5aa1367ad10eb65135a",
            ),
            (
                64,
                "089fda95fb5d45ba9a5f46ebc99d85e1331daa4dd38f60597eec9a3d95c94bb5",
            ),
            (
                256,
                "d1c3291dbdf0ccc4acdecce5f78fbe80e0ca7d6d803a62c9f5b59ee8c7e0a1b5",
            ),
            (
                4096,
                "6a4bbd704addd10996632d6535432598c742789e60b29d055a7784be927588a5",
            ),
        ];
        for (count, expected) in cpus {
            let mut c = config(1, 0);
            c.cpu_count = count;
            assert_eq!(qemu_hash(c)?, expected);
        }
        Ok(())
    }

    #[test]
    fn qemu_device_count_goldens() -> Result<(), Error> {
        let cases = [
            (
                0,
                0,
                0,
                0,
                "93a140bbc031dc313ed4011b838c8b22ffdecb474435d9fcb294be97194c953c",
            ),
            (
                1,
                0,
                0,
                0,
                "09f99e5dcf36b80a9258e849b3a9a70e7914244008e6a92a689eb22e4cc17a8f",
            ),
            (
                2,
                0,
                0,
                0,
                "fbf083121cc3b46b3b7913e45e635e6bb31e11f0cb6e029aa504bc4de68e2d64",
            ),
            (
                1,
                1,
                0,
                0,
                "fbf083121cc3b46b3b7913e45e635e6bb31e11f0cb6e029aa504bc4de68e2d64",
            ),
            (
                1,
                4,
                0,
                0,
                "7d722d7e3d811aa7978030af1d2a6c6aa68a5ab9267d7dff4e57babdf1476870",
            ),
            (
                1,
                0,
                1,
                0,
                "f47ab428541cb334c6de6e59e7fcf44a5db7b314e9dd4c643978968917eb25b2",
            ),
            (
                1,
                0,
                8,
                0,
                "ae3fefc72eb747cbff363e4f5ac7f3366f257849dc5f2719a9368303abaef4cc",
            ),
            (
                1,
                0,
                1,
                1,
                "8a48a13bc6041d73f7decce488054a8d25800cc82e11fa9bd1687e010ac9c9b0",
            ),
            (
                1,
                0,
                1,
                4,
                "2052ea73c74e1462947e600c95742e48cae0f7a84bc0ec79ab12f7a7818aec7a",
            ),
        ];
        for (nics, volumes, gpus, switches, expected) in cases {
            let mut c = config(nics, volumes);
            c.num_gpus = gpus;
            c.num_nvswitches = switches;
            assert_eq!(qemu_hash(c)?, expected);
        }
        Ok(())
    }

    #[test]
    fn qemu_memory_layout_boundaries() -> Result<(), Error> {
        let cases = [
            (
                1,
                "8d7620126cfd2a2edabbc8c9f289ca2993f547d595eed61fd508d24f2b52e3ac",
            ),
            (
                2049,
                "646e5cc620fd7819f8f4756c712619d2a72c29a175fc04b79867cee80e67cf82",
            ),
            (
                2815,
                "ee35c5e548a3f527dd12b1dd6ee14e093fd6063056470b3ef6cb6c844e4186a4",
            ),
            (
                2816,
                "3bf181108245994ceb7e983b1fa62009dcd56f7b49fd1e96ef15eb07d04aefc9",
            ),
            (
                1_048_576,
                "f22a114b0975b18200553442d6c9fab172fb930252c1a95926c594b2c25bca57",
            ),
        ];
        for (mib, expected) in cases {
            let mut c = config(1, 0);
            c.cpu_count = 2;
            c.memory_size = mib * 1024 * 1024;
            c.hugepages = true;
            c.num_gpus = 1;
            assert_eq!(qemu_hash(c)?, expected);
        }
        Ok(())
    }

    #[test]
    fn pxb_supports_qemus_full_gpu_range() -> Result<(), Error> {
        for gpus in [1, 8, 32] {
            let mut c = config(1, 0);
            c.hugepages = true;
            c.num_gpus = gpus;
            assert_eq!(
                qemu_hash(c)?,
                "a8449287b161102ca136f892d13d6bc853d1abdc9ba7804e886f0a42784878c3"
            );
        }
        Ok(())
    }

    #[test]
    fn device_kinds_share_qemus_slot_allocation() -> Result<(), Error> {
        assert_eq!(build(&config(5, 0))?.tables, build(&config(1, 4))?.tables);
        Ok(())
    }

    #[test]
    fn hostile_counts_are_rejected_without_generation() {
        let mut c = config(u32::MAX, u32::MAX);
        c.cpu_count = u32::MAX;
        c.num_gpus = u32::MAX;
        c.num_nvswitches = u32::MAX;
        assert!(crate::build(&c).is_err());

        let mut c = config(1, 0);
        c.cpu_count = 0;
        assert!(crate::build(&c).is_err());

        let mut c = config(1, 0);
        c.memory_size = 0;
        assert!(crate::build(&c).is_err());
    }

    #[test]
    fn validated_boundary_inputs_generate_safely() -> Result<(), Error> {
        for version in [
            QemuVersion::new(8, 0, 0),
            QemuVersion::new(9, 1, 0),
            QemuVersion::new(9, 2, 0),
            QemuVersion::new(10, 0, 0),
            QemuVersion::new(11, 0, 0),
            QemuVersion::new(11, 1, 0),
        ] {
            for cpus in [1, 255, 256, 4096] {
                for memory_size in [1, 0xafff_ffff, 0xb000_0000, u64::MAX] {
                    let mut c = config(0, 0);
                    c.qemu_version = version;
                    c.cpu_count = cpus;
                    c.memory_size = memory_size;
                    c.pci_hole64_size = Some(u64::MAX);
                    crate::build(&c)?;
                }
            }
        }
        Ok(())
    }
}
