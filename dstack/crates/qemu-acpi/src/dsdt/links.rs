// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! PCI interrupt link devices: the two shared helpers plus sixteen devices.
//!
//! `IQST`/`IQCR` decode a PCI interrupt route register (the `PRQx` bytes the
//! LPC device exposes as a field): bit 7 means "disabled", the low nibble is
//! the routed ISA IRQ.
//!
//! ```asl
//! Method (IQST, 1, NotSerialized) {
//!     If ((0x80 & Arg0)) { Return (0x09) }   // present, not enabled
//!     Return (0x0B)                           // present and enabled
//! }
//! Method (IQCR, 1, Serialized) {
//!     Name (PRR0, ResourceTemplate () {
//!         Interrupt (ResourceConsumer, Level, ActiveHigh, Shared, ,, _Y00) { 0 }
//!     })
//!     CreateDWordField (PRR0, \_SB.IQCR._Y00._INT, PRRI)
//!     PRRI = (Arg0 & 0x0F)
//!     Return (PRR0)
//! }
//! ```
//!
//! `LNKA`..`LNKH` are the eight routable links, one per PIRQ. They differ only
//! in device name, `_UID` (0..7) and the route register they read and write
//! (`PRQA`..`PRQH`); the ASL below is `LNKA` with those three holes.
//!
//! ```asl
//! Device (LNKA) {
//!     Name (_HID, EisaId ("PNP0C0F"))
//!     Name (_UID, Zero)
//!     Name (_PRS, ResourceTemplate () {
//!         Interrupt (ResourceConsumer, Level, ActiveHigh, Shared, ,, ) { 5, 10, 11 }
//!     })
//!     Method (_STA, 0, NotSerialized) { Return (IQST (PRQA)) }
//!     Method (_DIS, 0, NotSerialized) { PRQA |= 0x80 }
//!     Method (_CRS, 0, NotSerialized) { Return (IQCR (PRQA)) }
//!     Method (_SRS, 1, NotSerialized) {
//!         CreateDWordField (Arg0, 0x05, PRRI)
//!         PRQA = PRRI
//!     }
//! }
//! ```
//!
//! `GSIA`..`GSIH` are the fixed IOAPIC GSIs 16..23 that the same PIRQs land on
//! when the chipset is not in PIC mode. They are not routable, so `_CRS` is a
//! constant and `_DIS`/`_SRS` are empty. They differ only in device name and in
//! the single number that is both `_UID` and the interrupt: `0x10 + index`.
//!
//! ```asl
//! Device (GSIA) {
//!     Name (_HID, EisaId ("PNP0C0F"))
//!     Name (_UID, 0x10)
//!     Name (_PRS, ResourceTemplate () {
//!         Interrupt (ResourceConsumer, Level, ActiveHigh, Shared, ,, ) { 0x10 }
//!     })
//!     Name (_CRS, ResourceTemplate () {
//!         Interrupt (ResourceConsumer, Level, ActiveHigh, Shared, ,, ) { 0x10 }
//!     })
//!     Method (_DIS, 0, NotSerialized) { }
//!     Method (_SRS, 1, NotSerialized) { }
//! }
//! ```

use acpi_tables::aml::{
    And, Arg, CreateDWordField, Device, EISAName, If, Interrupt, Method, MethodCall, Name, Or,
    Path, ResourceTemplate, Return, Store, Zero,
};
use acpi_tables::{Aml, AmlSink};

use super::ops::emit;

/// PNP ID shared by every link device, routable or not.
const LINK_HID: &str = "PNP0C0F";
/// The suffix letters, in the order QEMU emits the devices.
const LETTERS: [char; 8] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
/// ISA IRQs a PIRQ may be routed to. QEMU offers the same three for every link.
const LINK_IRQS: [u32; 3] = [5, 10, 11];
/// GSI of the first non-routable link; the rest follow consecutively.
const GSI_BASE: u8 = 0x10;
/// `_STA` bit set when a device is present but not enabled.
const STA_PRESENT: u8 = 0x09;
/// `_STA` bits set when a device is present and enabled.
const STA_ENABLED: u8 = 0x0b;
/// Route register bit meaning "this PIRQ is masked".
const ROUTE_DISABLE: u8 = 0x80;
/// Route register mask selecting the routed ISA IRQ.
const ROUTE_IRQ: u8 = 0x0f;
/// Byte offset of the interrupt number inside an extended IRQ descriptor, as
/// seen from the start of a single-descriptor resource template buffer.
const DESCRIPTOR_INT_OFFSET: u8 = 0x05;

/// Extended interrupt descriptor listing several interrupt numbers.
/// `acpi_tables::aml::Interrupt` only models the single-number form, which is
/// all a `_CRS` ever needs, but a `_PRS` enumerates every possible routing.
struct InterruptList<'a> {
    consumer: bool,
    edge_triggered: bool,
    active_low: bool,
    shared: bool,
    numbers: &'a [u32],
}

impl<'a> InterruptList<'a> {
    fn new(
        consumer: bool,
        edge_triggered: bool,
        active_low: bool,
        shared: bool,
        numbers: &'a [u32],
    ) -> Self {
        Self {
            consumer,
            edge_triggered,
            active_low,
            shared,
            numbers,
        }
    }
}

impl Aml for InterruptList<'_> {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.byte(0x89); /* Extended IRQ Descriptor */
        sink.word(2 + 4 * self.numbers.len() as u16);
        let flags = ((self.shared as u8) << 3)
            | ((self.active_low as u8) << 2)
            | ((self.edge_triggered as u8) << 1)
            | self.consumer as u8;
        sink.byte(flags);
        sink.byte(self.numbers.len() as u8);
        for number in self.numbers {
            sink.dword(*number);
        }
    }
}

pub(crate) fn build(edge_triggered: bool) -> Vec<u8> {
    let mut out = interrupt_status();
    out.extend(interrupt_resource(edge_triggered));
    for (index, letter) in LETTERS.iter().enumerate() {
        out.extend(link_device(*letter, index as u8, edge_triggered));
    }
    for (index, letter) in LETTERS.iter().enumerate() {
        out.extend(gsi_device(*letter, GSI_BASE + index as u8, edge_triggered));
    }
    out
}

/// `Method (IQST, 1)`: turn a route register value into a `_STA` result.
fn interrupt_status() -> Vec<u8> {
    let masked = And::new(&Zero {}, &ROUTE_DISABLE, &Arg(0));
    let present = Return::new(&STA_PRESENT);
    let disabled = If::new(&masked, vec![&present]);
    let enabled = Return::new(&STA_ENABLED);
    emit(&Method::new(
        Path::new("IQST"),
        1,
        false,
        vec![&disabled, &enabled],
    ))
}

/// `Method (IQCR, 1)`: turn a route register value into a `_CRS` buffer.
/// Serialized because it patches the interrupt number into a named buffer.
fn interrupt_resource(edge_triggered: bool) -> Vec<u8> {
    let template = Interrupt::new(true, edge_triggered, false, true, 0);
    let buffer = ResourceTemplate::new(vec![&template]);
    let named = Name::new(Path::new("PRR0"), &buffer);

    let source = Path::new("PRR0");
    let field = Path::new("PRRI");
    let overlay = CreateDWordField::new(&field, &source, &DESCRIPTOR_INT_OFFSET);

    let routed = And::new(&Zero {}, &Arg(0), &ROUTE_IRQ);
    let target = Path::new("PRRI");
    let patch = Store::new(&target, &routed);

    let result = Path::new("PRR0");
    let ret = Return::new(&result);

    emit(&Method::new(
        Path::new("IQCR"),
        1,
        true,
        vec![&named, &overlay, &patch, &ret],
    ))
}

/// One routable link: `Device (LNK<letter>)` over route register `PRQ<letter>`.
fn link_device(letter: char, uid: u8, edge_triggered: bool) -> Vec<u8> {
    let hid = Name::new(Path::new("_HID"), &EISAName::new(LINK_HID));
    let unique = Name::new(Path::new("_UID"), &uid);

    let possible = InterruptList::new(true, edge_triggered, false, true, &LINK_IRQS);
    let buffer = ResourceTemplate::new(vec![&possible]);
    let prs = Name::new(Path::new("_PRS"), &buffer);

    let register = format!("PRQ{letter}");

    // _STA: Return (IQST (PRQx))
    let status_arg = Path::new(&register);
    let status_call = MethodCall::new(Path::new("IQST"), vec![&status_arg]);
    let status_ret = Return::new(&status_call);
    let sta = Method::new(Path::new("_STA"), 0, false, vec![&status_ret]);

    // _DIS: PRQx |= 0x80
    let disable_target = Path::new(&register);
    let disable_source = Path::new(&register);
    let mask = Or::new(&disable_target, &disable_source, &ROUTE_DISABLE);
    let dis = Method::new(Path::new("_DIS"), 0, false, vec![&mask]);

    // _CRS: Return (IQCR (PRQx))
    let current_arg = Path::new(&register);
    let current_call = MethodCall::new(Path::new("IQCR"), vec![&current_arg]);
    let current_ret = Return::new(&current_call);
    let crs = Method::new(Path::new("_CRS"), 0, false, vec![&current_ret]);

    // _SRS: CreateDWordField (Arg0, 0x05, PRRI); PRQx = PRRI
    let field = Path::new("PRRI");
    let overlay = CreateDWordField::new(&field, &Arg(0), &DESCRIPTOR_INT_OFFSET);
    let store_target = Path::new(&register);
    let store_source = Path::new("PRRI");
    let apply = Store::new(&store_target, &store_source);
    let srs = Method::new(Path::new("_SRS"), 1, false, vec![&overlay, &apply]);

    let name = format!("LNK{letter}");
    emit(&Device::new(
        Path::new(&name),
        vec![&hid, &unique, &prs, &sta, &dis, &crs, &srs],
    ))
}

/// One fixed link: `Device (GSI<letter>)` pinned to interrupt `gsi`.
fn gsi_device(letter: char, gsi: u8, edge_triggered: bool) -> Vec<u8> {
    let hid = Name::new(Path::new("_HID"), &EISAName::new(LINK_HID));
    let unique = Name::new(Path::new("_UID"), &gsi);

    let interrupt = Interrupt::new(true, edge_triggered, false, true, u32::from(gsi));
    let possible = ResourceTemplate::new(vec![&interrupt]);
    let prs = Name::new(Path::new("_PRS"), &possible);
    let current = ResourceTemplate::new(vec![&interrupt]);
    let crs = Name::new(Path::new("_CRS"), &current);

    let empty: Vec<&dyn Aml> = Vec::new();
    let dis = Method::new(Path::new("_DIS"), 0, false, empty.clone());
    let srs = Method::new(Path::new("_SRS"), 1, false, empty);

    let name = format!("GSI{letter}");
    emit(&Device::new(
        Path::new(&name),
        vec![&hid, &unique, &prs, &crs, &dis, &srs],
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        super::super::fixture::assert_region(&super::build(false), 4552, 6271);
    }
}
