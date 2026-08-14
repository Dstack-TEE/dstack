// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! From-scratch generation of QEMU's Q35 DSDT.
//!
//! The DSDT is the only ACPI table QEMU builds out of AML rather than fixed
//! records, and it is 93% of `etc/acpi/tables`. Every term here is emitted in
//! the same order QEMU's `build_dsdt()` emits it, because the byte stream is
//! the measured artifact: an equivalent-but-differently-ordered DSDT would be
//! a different RTMR0.
//!
//! Each submodule owns one contiguous byte range of the table and is verified
//! against the captured QEMU fixture on its own, so a mismatch points at a
//! region instead of at the whole blob.

use crate::{Compatibility, Error, MachineConfig};
use acpi_tables::aml::{Path, Scope};

mod cpus;
mod crs;
mod dbg;
mod fwcf;
mod gpe;
mod links;
mod notify;
mod ops;
mod pci0;
mod pcihp;
mod pic;
mod prt;
mod pxb;
mod sstate;

/// DSDT body: everything after the 36-byte ACPI table header.
pub(crate) fn body(config: &MachineConfig) -> Result<Vec<u8>, Error> {
    let pci_hotplug = !config.hotplug_off;
    let has_pxb = config.hugepages && config.num_gpus > 0;
    let low_ram_end = if config.memory_size >= 0xb000_0000 {
        0x8000_0000
    } else {
        config.memory_size as u32
    };
    let fixed_slots = 4 + u32::from(config.root_verity);
    let regular_slots = fixed_slots + config.num_nics + config.num_verity_volumes;
    let root_ports = if config.hugepages && config.num_gpus > 0 {
        config.num_nvswitches
    } else {
        config.num_gpus + config.num_nvswitches
    };
    let modern_serial_irq = matches!(
        config.qemu_version.compatibility(),
        Some(Compatibility::V11_1)
    );
    let initialize_cpu_selector = matches!(
        config.qemu_version.compatibility(),
        Some(Compatibility::V8 | Compatibility::V9Pre92 | Compatibility::V9_2 | Compatibility::V10)
    );
    let queued_cpu_eject = matches!(
        config.qemu_version.compatibility(),
        Some(Compatibility::V10 | Compatibility::V11_0 | Compatibility::V11_1)
    );
    let modern_device_label = !matches!(
        config.qemu_version.compatibility(),
        Some(Compatibility::V8 | Compatibility::V9Pre92)
    );
    let edge_triggered_links = !modern_device_label;
    let mut out = Vec::new();
    out.extend(dbg::build()); //           36..110   Scope(\) debug port
    out.extend(pci0::build(pci_hotplug)); // 110..426 Scope(_SB) PCI0 + DRAC
    if pci_hotplug {
        out.extend(pcihp::build(modern_device_label));
    }
    out.extend(pic::build()); //          777..796   PICF + _PIC
    out.extend(Scope::raw(
        Path::new("_SB_"),
        [prt::build(), links::build(edge_triggered_links)].concat(),
    )); //                                796..6271  Scope(_SB) routing + links
    out.extend(gpe::hid()); //           6271..6292  Scope(_GPE) _HID
    out.extend(Scope::raw(
        Path::new("_SB_"),
        cpus::build(
            config.cpu_count,
            config.hugepages,
            initialize_cpu_selector,
            queued_cpu_eject,
        )?,
    ));
    out.extend(gpe::e02()); //           7354..7382  \_GPE._E02
    if has_pxb {
        out.extend(pxb::build());
    }
    out.extend(Scope::raw(
        Path::new("\\_SB_.PCI0"),
        crs::build(
            low_ram_end,
            config.pci_hole64_size,
            pci_hotplug,
            if has_pxb { 4 } else { crs::BUS_MAX },
        ),
    ));
    out.extend(sstate::build()); //      7732..7774  Scope(\) _S3/_S4/_S5
    out.extend(fwcf::build()); //        7774..7834  Scope(\_SB.PCI0) FWCF
    out.extend(notify::build(
        regular_slots,
        root_ports,
        modern_serial_irq,
        has_pxb.then_some(0x80),
    ));
    if pci_hotplug {
        out.extend(gpe::e01());
    }
    Ok(out)
}

/// Complete DSDT, including its standard ACPI header.
pub(crate) fn table(config: &MachineConfig) -> Result<Vec<u8>, Error> {
    let body = body(config)?;
    let length = 36 + body.len();
    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(b"DSDT");
    out.extend_from_slice(&(length as u32).to_le_bytes());
    out.extend_from_slice(&[1, 0]); // revision, checksum (fixed by firmware)
    out.extend_from_slice(b"BOCHS ");
    out.extend_from_slice(b"BXPC    ");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(b"BXPC");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend(body);
    Ok(out)
}

#[cfg(test)]
pub(crate) mod fixture {
    /// Captured QEMU output for the baseline machine: 1 vCPU, no extra PCI
    /// devices, CPU hotplug on, no NUMA/PXB. It is a test oracle only and is
    /// never part of generation.
    const BASE: &[u8] = include_bytes!("../../fixtures/qemu-11.1-q35-base.bin");
    const DSDT_OFFSET: usize = 64;
    const DSDT_LEN: usize = 8258;
    /// Length of the ACPI table header preceding the AML body.
    pub(crate) const HEADER_LEN: usize = 36;

    pub(crate) fn dsdt() -> &'static [u8] {
        &BASE[DSDT_OFFSET..DSDT_OFFSET + DSDT_LEN]
    }

    /// The whole captured `etc/acpi/tables` blob, trimmed of its trailing
    /// zero padding. Offsets are the ones the loader relocates against.
    pub(crate) fn base() -> &'static [u8] {
        BASE
    }

    /// Compare generated bytes against a byte range of the whole blob.
    pub(crate) fn assert_blob_range(actual: &[u8], start: usize, end: usize) {
        assert_slice(actual, &base()[start..end], start);
    }

    /// Compare generated bytes against a DSDT byte range, reporting the first
    /// divergence with enough context to find it in an `iasl -d` listing.
    pub(crate) fn assert_region(actual: &[u8], start: usize, end: usize) {
        assert_slice(actual, &dsdt()[start..end], start);
    }

    fn assert_slice(actual: &[u8], expected: &[u8], start: usize) {
        if actual == expected {
            return;
        }
        let common = actual
            .iter()
            .zip(expected)
            .take_while(|(a, b)| a == b)
            .count();
        let window = |bytes: &[u8], from: usize| {
            bytes
                .iter()
                .skip(from)
                .take(16)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        panic!(
            "region at offset {start} does not match QEMU\n\
             matched {common} of {} bytes (generated {} bytes)\n\
             first difference at offset {}\n\
               expected: {}\n\
               actual:   {}",
            expected.len(),
            actual.len(),
            start + common,
            window(expected, common),
            window(actual, common),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::fixture;
    use crate::{MachineConfig, QemuVersion};

    fn config() -> MachineConfig {
        MachineConfig {
            qemu_version: QemuVersion::new(11, 1, 0),
            cpu_count: 1,
            memory_size: 2 << 30,
            pic: false,
            smm: false,
            hugepages: false,
            num_gpus: 0,
            num_nvswitches: 0,
            num_nics: 0,
            num_verity_volumes: 0,
            hotplug_off: false,
            root_verity: true,
            pci_hole64_size: None,
        }
    }

    /// The whole body, once every region lands. Until then the per-region
    /// tests are the ones that matter; this is the integration check that no
    /// term is missing, duplicated, or emitted out of order.
    #[test]
    fn body_matches_qemu() {
        let generated = super::body(&config()).unwrap_or_else(|error| panic!("{error}"));
        fixture::assert_region(&generated, fixture::HEADER_LEN, fixture::dsdt().len());
    }

    #[test]
    fn table_matches_qemu() {
        let generated = super::table(&config()).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(generated, fixture::dsdt());
    }
}
