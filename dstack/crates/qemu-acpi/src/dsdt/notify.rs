// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `Scope (\_SB) { Scope (PCI0) { .. } }`: one descriptor per populated slot on
//! the root bus, and the ISA scaffolding hanging off the ICH9 LPC bridge.
//!
//! QEMU walks every devfn of the bus (`build_append_pci_bus_devices`,
//! `hw/acpi/pcihp.c`) and emits `Device (S<devfn>) { Name (_ADR, ..) }` for the
//! populated ones, then lets each device append its own AML. The LPC bridge
//! appends its ISA children; PCIe root ports append their secondary-bus PCI
//! hotplug slots and recursive notification methods.
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
    And, Arg, Device, EISAName, Field, FieldAccessType, FieldEntry, FieldLockRule, FieldUpdateRule,
    If, Index, Local, Method, MethodCall, Name, Notify, One, OpRegion, OpRegionSpace, Package,
    Path, ResourceTemplate, Return, Scope, Store, Zero, IO,
};
use acpi_tables::{Aml, AmlSink};

use super::ops::{emit, Raw};

/// Devfns populated on the root bus of the baseline machine by the ICH9 chipset:
/// LPC (which emits extra AML), SATA, and SMBus.
const CHIPSET_DEVFNS: &[u8] = &[0xf8, 0xfa, 0xfb];

/// The ICH9 LPC bridge, the only function that contributes its own AML.
const LPC_DEVFN: u8 = 0xf8;

pub(crate) fn build(
    slot_count: u32,
    root_port_count: u32,
    modern_serial_irq: bool,
    pxb_devfn: Option<u8>,
    pci_hotplug: bool,
) -> Vec<u8> {
    let lpc = lpc_children(modern_serial_irq);
    let root_ports = root_ports(slot_count, root_port_count, pxb_devfn);

    let mut devices = Vec::new();
    for slot in 0..slot_count {
        devices.push(((slot * 8) as u8, false, None));
    }
    if let Some(devfn) = pxb_devfn {
        devices.push((devfn, false, None));
    }
    for &(devfn, bsel) in &root_ports {
        devices.push((devfn, true, pci_hotplug.then_some(bsel)));
    }
    for &devfn in CHIPSET_DEVFNS {
        devices.push((devfn, false, None));
    }
    devices.sort_unstable_by_key(|(devfn, _, _)| *devfn);

    let mut bus = Vec::new();
    for (devfn, root_port, bsel) in devices {
        bus.extend(pci_device(devfn, root_port, bsel, &lpc));
    }

    Scope::raw(Path::new("\\_SB_"), Scope::raw(Path::new("PCI0"), bus))
}

/// Build the recursive notification methods QEMU appends after the root-bus
/// device descriptions. The host bridge has no BSEL; each hotplug-capable
/// root-port secondary bus has one, assigned in bus traversal order.
pub(crate) fn pcnt(
    slot_count: u32,
    root_port_count: u32,
    pxb_devfn: Option<u8>,
) -> Option<Vec<u8>> {
    let root_ports = root_ports(slot_count, root_port_count, pxb_devfn);
    if root_ports.is_empty() {
        return None;
    }

    let mut children = Vec::new();
    for &(devfn, bsel) in root_ports.iter().rev() {
        children.extend(child_pcnt(devfn, bsel));
    }

    let mut calls = Vec::new();
    for &(devfn, _) in root_ports.iter().rev() {
        // `Path` cannot encode AML ParentPrefixChar. A zero-argument method
        // invocation is just its NameString, which QEMU emits as
        // `^S<devfn>.PCNT` from the root PCNT method.
        calls.push(parent_pcnt_call(devfn));
    }
    let raw_calls: Vec<_> = calls.iter().map(|call| Raw(call)).collect();
    let call_refs = raw_calls.iter().map(|call| call as &dyn Aml).collect();
    children.extend(emit(&Method::new(Path::new("PCNT"), 0, false, call_refs)));

    Some(Scope::raw(Path::new("\\_SB_.PCI0"), children))
}

fn root_ports(slot_count: u32, count: u32, pxb_devfn: Option<u8>) -> Vec<(u8, u32)> {
    let mut ports = Vec::with_capacity(count as usize);
    let mut slot = slot_count;
    for index in 0..count {
        if pxb_devfn == Some((slot * 8) as u8) {
            slot += 1;
        }
        // QEMU inserts each secondary bus at the head of the root child list,
        // then allocates BSEL values by walking that list. Root ports are
        // created in ascending slot order, so their BSEL values run backward.
        let bsel = count - index - 1;
        ports.push(((slot * 8) as u8, bsel));
        slot += 1;
    }
    ports
}

fn pci_device(devfn: u8, root_port: bool, bsel: Option<u32>, lpc: &[u8]) -> Vec<u8> {
    // QEMU names the device after the devfn but addresses it by the
    // ACPI 1.0b Table 6-2 PCI form: (device << 16) | function.
    let name = format!("S{devfn:02X}_");
    let address = (u32::from(devfn >> 3) << 16) | u32::from(devfn & 0x07);
    let adr = Name::new(Path::new("_ADR"), &address);

    let child = root_port.then(|| root_port_child(bsel));
    let extra = Raw(if devfn == LPC_DEVFN { lpc } else { &[] });
    let child = Raw(match child.as_deref() {
        Some(bytes) => bytes,
        None => &[],
    });
    emit(&Device::new(Path::new(&name), vec![&adr, &extra, &child]))
}

fn root_port_child(bsel: Option<u32>) -> Vec<u8> {
    let child_address = Name::new(Path::new("_ADR"), &Zero {});
    let mut out = emit(&Device::new(Path::new("S00_"), vec![&child_address]));
    let Some(bsel) = bsel else {
        return out;
    };

    out.extend(emit(&Name::new(Path::new("BSEL"), &bsel)));
    out.extend(hotplug_slot());
    out.extend(dvnt());
    out
}

fn hotplug_slot() -> Vec<u8> {
    let zero = Zero {};
    let one = One {};
    let asun = Name::new(Path::new("ASUN"), &zero);

    let local0 = Local(0);
    let params = Package::new(vec![&zero, &zero]);
    let init_params = Store::new(&local0, &params);
    let bus_slot = Index::new(&zero, &local0, &zero);
    let bsel_name = Path::new("BSEL");
    let store_bus = Store::new(&bus_slot, &bsel_name);
    let sun_slot = Index::new(&zero, &local0, &one);
    let asun_name = Path::new("ASUN");
    let store_sun = Store::new(&sun_slot, &asun_name);
    let (arg0, arg1, arg2, arg3) = (Arg(0), Arg(1), Arg(2), Arg(3));
    let pdsm = MethodCall::new(Path::new("PDSM"), vec![&arg0, &arg1, &arg2, &arg3, &local0]);
    let ret = Return::new(&pdsm);
    let dsm = Method::new(
        Path::new("_DSM"),
        4,
        true,
        vec![&init_params, &store_bus, &store_sun, &ret],
    );

    let sun = Name::new(Path::new("_SUN"), &zero);
    let bsel_name = Path::new("BSEL");
    let sun_name = Path::new("_SUN");
    let eject = MethodCall::new(Path::new("PCEJ"), vec![&bsel_name, &sun_name]);
    let ej0 = Method::new(Path::new("_EJ0"), 1, false, vec![&eject]);

    emit(&Scope::new(
        Path::new("S00_"),
        vec![&asun, &dsm, &sun, &ej0],
    ))
}

fn dvnt() -> Vec<u8> {
    let arg0 = Arg(0);
    let arg1 = Arg(1);
    let one = One {};
    let selected = And::new(&Zero {}, &arg0, &one);
    let slot = Path::new("S00_");
    let notify = Notify::new(&slot, &arg1);
    let branch = If::new(&selected, vec![&notify]);
    emit(&Method::new(Path::new("DVNT"), 2, false, vec![&branch]))
}

fn child_pcnt(devfn: u8, bsel: u32) -> Vec<u8> {
    let bnum = Path::new("BNUM");
    let pciu = Path::new("PCIU");
    let pcid = Path::new("PCID");
    let one = One {};
    let eject_request = 3u8;
    let select_bus = Store::new(&bnum, &bsel);
    let inserted = MethodCall::new(Path::new("DVNT"), vec![&pciu, &one]);
    let removed = MethodCall::new(Path::new("DVNT"), vec![&pcid, &eject_request]);
    let method = Method::new(
        Path::new("PCNT"),
        0,
        false,
        vec![&select_bus, &inserted, &removed],
    );
    Scope::raw(Path::new(&format!("S{devfn:02X}_")), emit(&method))
}

fn parent_pcnt_call(devfn: u8) -> Vec<u8> {
    let mut call = vec![0x5e, 0x2e]; // ParentPrefixChar, DualNamePrefix
    call.extend_from_slice(format!("S{devfn:02X}_PCNT").as_bytes());
    call
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
        super::super::fixture::assert_region(&super::build(5, 0, true, None, true), 7834, 8245);
    }

    #[test]
    fn eight_root_ports_include_qemus_hotplug_aml() {
        use sha2::{Digest, Sha256};

        let hotplug_on = super::build(6, 8, true, None, true);
        let hotplug_off = super::build(6, 8, true, None, false);
        assert_eq!(hotplug_on.len() - hotplug_off.len(), 854);

        let pcnt = super::pcnt(6, 8, None).unwrap();
        assert_eq!(pcnt.len(), 411);
        assert_eq!(
            hex::encode(Sha256::digest(pcnt)),
            "29f0fc0087802ef8886aa8eff10bbd78b471e50f8ce2d543861cd437a2806851"
        );
    }

    #[test]
    fn root_port_bsel_mapping_follows_qemus_reverse_child_walk() {
        assert_eq!(
            super::root_ports(6, 8, None),
            vec![
                (0x30, 7),
                (0x38, 6),
                (0x40, 5),
                (0x48, 4),
                (0x50, 3),
                (0x58, 2),
                (0x60, 1),
                (0x68, 0),
            ]
        );
    }

    #[test]
    fn eight_root_port_devices_match_independent_qemu_encoding() {
        use sha2::{Digest, Sha256};

        let ports = super::root_ports(6, 8, None);
        let mut hotplug_off = Vec::new();
        let mut hotplug_on = Vec::new();
        for (devfn, bsel) in ports {
            hotplug_off.extend(super::pci_device(devfn, true, None, &[]));
            hotplug_on.extend(super::pci_device(devfn, true, Some(bsel), &[]));
        }
        assert_eq!(hotplug_off.len(), 240);
        assert_eq!(hotplug_on.len(), 1094);
        assert_eq!(
            hex::encode(Sha256::digest(hotplug_off)),
            "7a107a6f0cf575cff4f70489c1b61a8c1ef1ae86a89de182ab0f412cea7bf80d"
        );
        assert_eq!(
            hex::encode(Sha256::digest(hotplug_on)),
            "caec37e9162f026c9e36fe4952fb55f6aa7db09fc92e4e785914f84b05a705b3"
        );
    }

    #[test]
    fn root_port_hotplug_terms_match_independent_qemu_encoding() {
        use sha2::{Digest, Sha256};

        let base = super::root_port_child(None);
        for (bsel, expected) in [
            (
                0,
                "2ab2603633fbf9eee2f7b9104d9f2510a55884520f1f02ddc41276fc9dfee90f",
            ),
            (
                2,
                "4b39e662fdf5334c777209850bb8984abb1dbda74f2f20bd807198e7683662ee",
            ),
        ] {
            let port = super::root_port_child(Some(bsel));
            assert_eq!(hex::encode(Sha256::digest(&port[base.len()..])), expected);
        }
    }

    #[test]
    fn root_port_hotplug_aml_is_conditional() {
        let hotplug_off = super::build(6, 8, true, None, false);
        let no_ports = super::build(6, 0, true, None, false);
        assert_eq!(hotplug_off.len() - no_ports.len(), 8 * 30);
        assert!(super::pcnt(6, 0, None).is_none());
    }
}
