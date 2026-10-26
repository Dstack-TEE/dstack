// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! The PCI0 root bus resources: the windows the root bridge decodes, plus the
//! two container devices that reserve the ACPI IO ports out of them.
//!
//! The caller wraps this term sequence in `Scope (\_SB.PCI0)`.
//!
//! ```asl
//! Name (_CRS, ResourceTemplate () {
//!     WordBusNumber (ResourceProducer, MinFixed, MaxFixed, PosDecode,
//!         0x0000, 0x0000, 0x00FF, 0x0000, 0x0100, ,, )
//!     IO (Decode16, 0x0CF8, 0x0CF8, 0x01, 0x08, )
//!     WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
//!         0x0000, 0x0000, 0x0CF7, 0x0000, 0x0CF8, ,, , TypeStatic, DenseTranslation)
//!     WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
//!         0x0000, 0x0D00, 0xFFFF, 0x0000, 0xF300, ,, , TypeStatic, DenseTranslation)
//!     DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
//!         0x00000000, 0x000A0000, 0x000BFFFF, 0x00000000, 0x00020000,
//!         ,, , AddressRangeMemory, TypeStatic)
//!     DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite,
//!         0x00000000, 0x80000000, 0xDFFFFFFF, 0x00000000, 0x60000000,
//!         ,, , AddressRangeMemory, TypeStatic)
//!     DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite,
//!         0x00000000, 0xF0000000, 0xFEBFFFFF, 0x00000000, 0x0EC00000,
//!         ,, , AddressRangeMemory, TypeStatic)
//!     QWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
//!         0x0000000000000000, 0x0000380000000000, 0x00003807FFFFFFFF,
//!         0x0000000000000000, 0x0000000800000000, ,, , AddressRangeMemory, TypeStatic)
//! })
//! Device (GPE0) {
//!     Name (_HID, "PNP0A06")
//!     Name (_UID, "GPE0 resources")
//!     Name (_STA, 0x0B)
//!     Name (_CRS, ResourceTemplate () { IO (Decode16, 0x0620, 0x0620, 0x01, 0x10, ) })
//! }
//! Device (PHPR) {
//!     Name (_HID, "PNP0A06")
//!     Name (_UID, "PCI Hotplug resources")
//!     Name (_STA, 0x0B)
//!     Name (_CRS, ResourceTemplate () { IO (Decode16, 0x0CC0, 0x0CC0, 0x01, 0x18, ) })
//! }
//! ```

use acpi_tables::aml::{
    AddressSpace, AddressSpaceCacheable, Device, Name, Path, ResourceTemplate, IO,
};
use acpi_tables::{Aml, AmlSink};

use super::ops::emit_all;

/// Bus numbers the root bridge claims. Q35 exposes one segment of 256.
const BUS_MIN: u16 = 0x0000;
pub(crate) const BUS_MAX: u16 = 0x00ff;

/// The PCI configuration mechanism 1 ports (`CF8`/`CFC`), consumed by the
/// bridge itself rather than forwarded onto the bus.
const PCI_CONFIG_IO_BASE: u16 = 0x0cf8;
const PCI_CONFIG_IO_LEN: u8 = 0x08;

/// Every fixed IO descriptor below is byte aligned.
const IO_ALIGN: u8 = 0x01;

/// Port IO forwarded to the bus, split around the configuration ports above.
const IO_LOW_MIN: u16 = 0x0000;
const IO_LOW_MAX: u16 = 0x0cf7;
const IO_HIGH_MIN: u16 = 0x0d00;
const IO_HIGH_MAX: u16 = 0xffff;

/// The legacy VGA framebuffer aperture.
const VGA_MEM_MIN: u32 = 0x000a_0000;
const VGA_MEM_MAX: u32 = 0x000b_ffff;

/// The 32-bit PCI hole: RAM below 4G ends where this window starts, so a
/// larger guest moves `PCI32_MIN` down.
#[cfg(test)]
const PCI32_MIN: u32 = 0x8000_0000;
const PCI32_MAX: u32 = 0xdfff_ffff;

/// The window above PCIe ECAM and below the local APIC page.
const MMIO32_MIN: u32 = 0xf000_0000;
const MMIO32_MAX: u32 = 0xfebf_ffff;

/// The 64-bit PCI hole, placed just above the guest's addressable RAM.
const PCI64_MIN: u64 = 0x0000_3800_0000_0000;
const PCI64_MAX: u64 = 0x0000_3807_ffff_ffff;

struct Pci64Window {
    max: u64,
    length: u64,
}

impl Aml for Pci64Window {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.byte(0x8a);
        sink.word(43);
        sink.byte(0); // memory range
        sink.byte(0x0c); // MinFixed | MaxFixed
        sink.byte(0x03); // cacheable, read/write
        sink.qword(0); // granularity
        sink.qword(PCI64_MIN);
        sink.qword(self.max);
        sink.qword(0); // translation
        sink.qword(self.length);
    }
}

/// GPE0 block ports, reserved so no PCI device is assigned over them.
const GPE0_IO_BASE: u16 = 0x0620;
const GPE0_IO_LEN: u8 = 0x10;

/// PCI hotplug register block ports, reserved for the same reason.
const PHPR_IO_BASE: u16 = 0x0cc0;
const PHPR_IO_LEN: u8 = 0x18;

/// `Name (_HID, "PNP0A06")`: both reservations are generic containers.
const CONTAINER_HID: &str = "PNP0A06";
/// `Name (_STA, 0x0B)`: present, enabled and functioning, but not shown in UI.
const STA_HIDDEN: u8 = 0x0b;

/// One IO port reservation device: a container that exists only to take a
/// fixed port range out of the root bus window.
fn reservation(name: &str, description: &'static str, base: u16, length: u8) -> Vec<u8> {
    let hid = Name::new(Path::new("_HID"), &CONTAINER_HID);
    let uid = Name::new(Path::new("_UID"), &description);
    let sta = Name::new(Path::new("_STA"), &STA_HIDDEN);

    let port = IO::new(base, base, IO_ALIGN, length);
    let template = ResourceTemplate::new(vec![&port]);
    let crs = Name::new(Path::new("_CRS"), &template);

    emit_all(&[&Device::new(Path::new(name), vec![&hid, &uid, &sta, &crs])])
}

pub(crate) fn build(
    low_ram_end: u32,
    pci_hole64_size: Option<u64>,
    pci_hotplug: bool,
    bus_max: u16,
) -> Vec<u8> {
    let buses = AddressSpace::new_bus_number(BUS_MIN, bus_max);
    let config = IO::new(
        PCI_CONFIG_IO_BASE,
        PCI_CONFIG_IO_BASE,
        IO_ALIGN,
        PCI_CONFIG_IO_LEN,
    );
    let io_low = AddressSpace::new_io(IO_LOW_MIN, IO_LOW_MAX, None);
    let io_high = AddressSpace::new_io(IO_HIGH_MIN, IO_HIGH_MAX, None);
    let vga = AddressSpace::new_memory(
        AddressSpaceCacheable::Cacheable,
        true,
        VGA_MEM_MIN,
        VGA_MEM_MAX,
        None,
    );
    let pci32 = AddressSpace::new_memory(
        AddressSpaceCacheable::NotCacheable,
        true,
        low_ram_end,
        PCI32_MAX,
        None,
    );
    let mmio32 = AddressSpace::new_memory(
        AddressSpaceCacheable::NotCacheable,
        true,
        MMIO32_MIN,
        MMIO32_MAX,
        None,
    );
    let pci64_length = pci_hole64_size.unwrap_or(PCI64_MAX - PCI64_MIN + 1);
    let pci64 = Pci64Window {
        max: PCI64_MIN.wrapping_add(pci64_length).wrapping_sub(1),
        length: pci64_length,
    };

    let template = ResourceTemplate::new(vec![
        &buses, &config, &io_low, &io_high, &vga, &pci32, &mmio32, &pci64,
    ]);
    let crs = Name::new(Path::new("_CRS"), &template);

    let mut out = emit_all(&[&crs]);
    out.extend(reservation(
        "GPE0",
        "GPE0 resources",
        GPE0_IO_BASE,
        GPE0_IO_LEN,
    ));
    if pci_hotplug {
        out.extend(reservation(
            "PHPR",
            "PCI Hotplug resources",
            PHPR_IO_BASE,
            PHPR_IO_LEN,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        super::super::fixture::assert_region(
            &super::build(super::PCI32_MIN, None, true, super::BUS_MAX),
            7395,
            7732,
        );
    }
}
