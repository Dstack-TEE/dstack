// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `Scope (\_SB) { Scope (PCI0) { .. } }`: one descriptor per populated slot on
//! the root bus, and the ISA scaffolding hanging off the ICH9 LPC bridge.
//!
//! QEMU walks every devfn of the bus (`build_append_pci_bus_devices`,
//! `hw/acpi/pcihp.c`) and emits `Device (S<devfn>) { Name (_ADR, ..) }` for the
//! populated ones, then lets each device append its own AML. Only the LPC
//! bridge does (`build_ich9_isa_aml`, `hw/isa/lpc_ich9.c`).
//!
//! ```asl
//! Scope (\_SB) {
//!     Scope (PCI0) {
//!         Device (S00) { Name (_ADR, Zero) }
//!         Device (S08) { Name (_ADR, 0x00010000) }
//!         Device (S10) { Name (_ADR, 0x00020000) }
//!         Device (S18) { Name (_ADR, 0x00030000) }
//!         Device (S20) { Name (_ADR, 0x00040000) }
//!         Device (SF8) {
//!             Name (_ADR, 0x001F0000)
//!             OperationRegion (PIRQ, PCI_Config, 0x60, 0x0C)
//!             Scope (\_SB) {
//!                 Field (PCI0.SF8.PIRQ, ByteAcc, NoLock, Preserve) {
//!                     PRQA, 8, PRQB, 8, PRQC, 8, PRQD, 8,
//!                     Offset (0x08),
//!                     PRQE, 8, PRQF, 8, PRQG, 8, PRQH, 8
//!                 }
//!             }
//!             Device (KBD) {
//!                 Name (_HID, EisaId ("PNP0303"))
//!                 Name (_STA, 0x0F)
//!                 Name (_CRS, ResourceTemplate () {
//!                     IO (Decode16, 0x0060, 0x0060, 0x01, 0x01)
//!                     IO (Decode16, 0x0064, 0x0064, 0x01, 0x01)
//!                     IRQNoFlags () {1}
//!                 })
//!             }
//!             Device (MOU) {
//!                 Name (_HID, EisaId ("PNP0F13"))
//!                 Name (_STA, 0x0F)
//!                 Name (_CRS, ResourceTemplate () { IRQNoFlags () {12} })
//!             }
//!             Device (COM1) {
//!                 Name (_HID, EisaId ("PNP0501"))
//!                 Name (_UID, One)
//!                 Name (_STA, 0x0F)
//!                 Name (_CRS, ResourceTemplate () {
//!                     IO (Decode16, 0x03F8, 0x03F8, 0x00, 0x08)
//!                     IRQ (Level, ActiveLow, Shared, ) {4}
//!                 })
//!             }
//!             Device (RTC) {
//!                 Name (_HID, EisaId ("PNP0B00"))
//!                 Name (_CRS, ResourceTemplate () {
//!                     IO (Decode16, 0x0070, 0x0070, 0x01, 0x08)
//!                     IRQNoFlags () {8}
//!                 })
//!             }
//!         }
//!         Device (SFA) { Name (_ADR, 0x001F0002) }
//!         Device (SFB) { Name (_ADR, 0x001F0003) }
//!     }
//! }
//! ```

use acpi_tables::aml::{
    Device, EISAName, Field, FieldAccessType, FieldEntry, FieldLockRule, FieldUpdateRule, Name,
    OpRegion, OpRegionSpace, Path, ResourceTemplate, Scope, IO,
};
use acpi_tables::{Aml, AmlSink};

use super::ops::{emit, Raw};

/// Devfns populated on the root bus of the fixture machine: the MCH host
/// bridge, four PCI slots, and the three ICH9 functions (LPC, SATA, SMBus).
const CHIPSET_DEVFNS: &[u8] = &[0xf8, 0xfa, 0xfb];

/// The ICH9 LPC bridge, the only function that contributes its own AML.
const LPC_DEVFN: u8 = 0xf8;

pub(crate) fn build(
    slot_count: u32,
    root_port_count: u32,
    modern_serial_irq: bool,
    pxb_devfn: Option<u8>,
) -> Vec<u8> {
    let lpc = lpc_children(modern_serial_irq);

    let mut bus = Vec::new();
    for slot in 0..slot_count {
        bus.extend(pci_device((slot * 8) as u8, false, &lpc));
    }
    for slot in slot_count..slot_count + root_port_count {
        bus.extend(pci_device((slot * 8) as u8, true, &lpc));
    }
    if let Some(devfn) = pxb_devfn {
        bus.extend(pci_device(devfn, false, &lpc));
    }
    for &devfn in CHIPSET_DEVFNS {
        bus.extend(pci_device(devfn, false, &lpc));
    }

    Scope::raw(Path::new("\\_SB_"), Scope::raw(Path::new("PCI0"), bus))
}

fn pci_device(devfn: u8, root_port: bool, lpc: &[u8]) -> Vec<u8> {
    // QEMU names the device after the devfn but addresses it by the
    // ACPI 1.0b Table 6-2 PCI form: (device << 16) | function.
    let name = format!("S{devfn:02X}_");
    let address = (u32::from(devfn >> 3) << 16) | u32::from(devfn & 0x07);
    let adr = Name::new(Path::new("_ADR"), &address);

    let child_address = Name::new(Path::new("_ADR"), &0u8);
    let child = root_port.then(|| emit(&Device::new(Path::new("S00_"), vec![&child_address])));
    let extra = Raw(if devfn == LPC_DEVFN { lpc } else { &[] });
    let child = Raw(match child.as_deref() {
        Some(bytes) => bytes,
        None => &[],
    });
    emit(&Device::new(Path::new(&name), vec![&adr, &extra, &child]))
}

/// The children the ICH9 LPC bridge appends to its own device descriptor.
fn lpc_children(modern_serial_irq: bool) -> Vec<u8> {
    // PCI-to-ISA interrupt routing registers in the bridge's config space.
    let pirq = OpRegion::new(
        Path::new("PIRQ"),
        OpRegionSpace::PCIConfig,
        &0x60u8,
        &0x0cu8,
    );

    // The field lands in \_SB rather than in the device, because the link
    // devices that read PRQA..PRQH live there. It has to follow the operation
    // region it names.
    let routing = Field::new(
        Path::new("PCI0.SF8_.PIRQ"),
        FieldAccessType::Byte,
        FieldLockRule::NoLock,
        FieldUpdateRule::Preserve,
        vec![
            FieldEntry::Named(*b"PRQA", 8),
            FieldEntry::Named(*b"PRQB", 8),
            FieldEntry::Named(*b"PRQC", 8),
            FieldEntry::Named(*b"PRQD", 8),
            // Offset (0x08): PIRQE..PIRQH sit at 0x68, four bytes on.
            FieldEntry::Reserved(0x20),
            FieldEntry::Named(*b"PRQE", 8),
            FieldEntry::Named(*b"PRQF", 8),
            FieldEntry::Named(*b"PRQG", 8),
            FieldEntry::Named(*b"PRQH", 8),
        ],
    );

    let mut out = emit(&pirq);
    out.extend(Scope::raw(Path::new("\\_SB_"), emit(&routing)));
    out.extend(isa_devices(modern_serial_irq));
    out
}

/// The devices on the bridge's ISA bus, in qbus order.
fn isa_devices(modern_serial_irq: bool) -> Vec<u8> {
    let mut out = Vec::new();

    // i8042: data port, command port, keyboard IRQ (hw/input/pckbd.c).
    let kbd_data = IO::new(0x60, 0x60, 0x01, 0x01);
    let kbd_command = IO::new(0x64, 0x64, 0x01, 0x01);
    let kbd_irq = Irq::no_flags(1);
    out.extend(isa_device(
        "KBD_",
        "PNP0303",
        None,
        Some(0x0f),
        vec![&kbd_data, &kbd_command, &kbd_irq],
    ));

    // The i8042's mouse half is a separate ACPI device sharing the ports.
    let mouse_irq = Irq::no_flags(12);
    out.extend(isa_device(
        "MOU_",
        "PNP0F13",
        None,
        Some(0x0f),
        vec![&mouse_irq],
    ));

    // 16550A serial port (hw/char/serial-isa.c).
    let com_ports = IO::new(0x3f8, 0x3f8, 0x00, 0x08);
    let com_irq = if modern_serial_irq {
        Irq::level_active_low_shared(4)
    } else {
        Irq::no_flags(4)
    };
    out.extend(isa_device(
        "COM1",
        "PNP0501",
        Some(1),
        Some(0x0f),
        vec![&com_ports, &com_irq],
    ));

    // MC146818 RTC. QEMU only answers on the first two ports but reserves
    // eight, following physical hardware (hw/rtc/mc146818rtc.c).
    let rtc_ports = IO::new(0x70, 0x70, 0x01, 0x08);
    let rtc_irq = Irq::no_flags(8);
    out.extend(isa_device(
        "RTC_",
        "PNP0B00",
        None,
        None,
        vec![&rtc_ports, &rtc_irq],
    ));

    out
}

/// `Device (name) { _HID, [_UID], [_STA], _CRS }`, the shape every ISA device
/// here shares.
fn isa_device(
    name: &str,
    hid: &str,
    uid: Option<u8>,
    sta: Option<u8>,
    resources: Vec<&dyn Aml>,
) -> Vec<u8> {
    let hid = Name::new(Path::new("_HID"), &EISAName::new(hid));
    let uid = uid.map(|uid| Name::new(Path::new("_UID"), &uid));
    let sta = sta.map(|sta| Name::new(Path::new("_STA"), &sta));
    let template = ResourceTemplate::new(resources);
    let crs = Name::new(Path::new("_CRS"), &template);

    let mut children: Vec<&dyn Aml> = vec![&hid];
    children.extend(uid.iter().map(|name| name as &dyn Aml));
    children.extend(sta.iter().map(|name| name as &dyn Aml));
    children.push(&crs);

    emit(&Device::new(Path::new(name), children))
}

/// The short IRQ resource descriptor, ACPI 6.5 §6.4.2.1. `acpi_tables` only
/// models the extended form (`Interrupt`), which is not what QEMU emits for
/// these legacy devices.
struct Irq {
    mask: u16,
    /// `None` selects the two-byte `IRQNoFlags ()` form.
    flags: Option<u8>,
}

impl Irq {
    /// `IRQNoFlags () {irq}`: edge triggered, active high, exclusive.
    fn no_flags(irq: u8) -> Self {
        Self {
            mask: 1u16 << irq,
            flags: None,
        }
    }

    /// `IRQ (Level, ActiveLow, Shared, ) {irq}`.
    fn level_active_low_shared(irq: u8) -> Self {
        // Bit 0 clear is level triggered, bit 3 is active low, bit 4 is shared.
        Self {
            mask: 1u16 << irq,
            flags: Some((1 << 3) | (1 << 4)),
        }
    }
}

impl Aml for Irq {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        match self.flags {
            None => {
                sink.byte(0x22);
                sink.word(self.mask);
            }
            Some(flags) => {
                sink.byte(0x23);
                sink.word(self.mask);
                sink.byte(flags);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        super::super::fixture::assert_region(&super::build(5, 0, true, None), 7834, 8245);
    }
}
