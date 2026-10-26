// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `Scope (_SB)`: the PCI Express host bridge and the DRAM controller stub.
//!
//! ```asl
//! Scope (_SB) {
//!     Device (PCI0) {
//!         Name (_HID, EisaId ("PNP0A08"))
//!         Name (_CID, EisaId ("PNP0A03"))
//!         Name (_UID, Zero)
//!         Method (_OSC, 4, NotSerialized) {
//!             CreateDWordField (Arg3, Zero, CDW1)
//!             If ((Arg0 == ToUUID ("33db4d5b-1ff7-401c-9657-7441c03dd766"))) {
//!                 CreateDWordField (Arg3, 0x04, CDW2)
//!                 CreateDWordField (Arg3, 0x08, CDW3)
//!                 Local0 = CDW3
//!                 Local0 &= 0x1E
//!                 If ((Arg1 != One)) {
//!                     CDW1 |= 0x08
//!                 }
//!                 If ((CDW3 != Local0)) {
//!                     CDW1 |= 0x10
//!                 }
//!                 CDW3 = Local0
//!             } Else {
//!                 CDW1 |= 0x04
//!             }
//!             Return (Arg3)
//!         }
//!         Method (EDSM, 5, Serialized) {
//!             If ((Arg2 == Zero)) {
//!                 Local0 = Buffer (One) { 0x00 }
//!                 If ((Arg0 != ToUUID ("e5c937d0-3553-4d7a-9117-ea4d19c3434d"))) {
//!                     Return (Local0)
//!                 }
//!                 If ((Arg1 < 0x02)) {
//!                     Return (Local0)
//!                 }
//!                 Local0 [Zero] = 0x81
//!                 Return (Local0)
//!             }
//!             If ((Arg2 == 0x07)) {
//!                 Local0 = Package (0x02) { Zero, "" }
//!                 Local1 = DerefOf (Arg4 [Zero])
//!                 Local0 [Zero] = Local1
//!                 Return (Local0)
//!             }
//!         }
//!     }
//!     Device (DRAC) {
//!         Name (_HID, "PNP0C01")
//!         Name (_CRS, ResourceTemplate () {
//!             DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
//!                 NonCacheable, ReadWrite,
//!                 0x00000000,         // Granularity
//!                 0xE0000000,         // Range Minimum
//!                 0xEFFFFFFF,         // Range Maximum
//!                 0x00000000,         // Translation Offset
//!                 0x10000000,         // Length
//!                 ,, , AddressRangeMemory, TypeStatic)
//!         })
//!     }
//! }
//! ```

use acpi_tables::aml::{
    AddressSpace, AddressSpaceCacheable, AmlStr, And, Arg, BufferData, CreateDWordField, DeRefOf,
    Device, EISAName, Else, Equal, If, Index, LessThan, Local, Method, Name, NotEqual, One, Or,
    Package, Path, ResourceTemplate, Return, Scope, Store, Uuid, Zero,
};

use super::ops::{emit, Raw};

/// PCI Firmware Specification host bridge `_OSC` UUID.
const OSC_UUID: &str = "33db4d5b-1ff7-401c-9657-7441c03dd766";
/// PCI Firmware Specification device labeling `_DSM` UUID, the only function
/// set `EDSM` implements.
const DSM_LABEL_UUID: &str = "e5c937d0-3553-4d7a-9117-ea4d19c3434d";

/// The MMCONFIG window `DRAC` reserves: 256 MiB at 0xE0000000.
const MCFG_BASE: u32 = 0xE000_0000;
const MCFG_LAST: u32 = 0xEFFF_FFFF;

pub(crate) fn build(pci_hotplug: bool) -> Vec<u8> {
    let pci0 = pci0(pci_hotplug);
    let drac = drac();
    emit(&Scope::new(
        Path::new("_SB_"),
        vec![&Raw(&pci0), &Raw(&drac)],
    ))
}

/// `Device (PCI0)`: the PCIe host bridge, its `_OSC` capability negotiation
/// and the `EDSM` helper every per-slot `_DSM` forwards to.
fn pci0(pci_hotplug: bool) -> Vec<u8> {
    let hid = Name::new(Path::new("_HID"), &EISAName::new("PNP0A08"));
    let cid = Name::new(Path::new("_CID"), &EISAName::new("PNP0A03"));
    let uid = Name::new(Path::new("_UID"), &Zero {});
    let osc = osc(pci_hotplug);
    let edsm = edsm();

    emit(&Device::new(
        Path::new("PCI0"),
        vec![&hid, &cid, &uid, &Raw(&osc), &Raw(&edsm)],
    ))
}

/// `Method (_OSC, 4, NotSerialized)`. Arg3 is the capability buffer the OS
/// passes in; the method masks it down to what QEMU actually supports and
/// records the outcome in the status dword.
pub(crate) fn osc(pci_hotplug: bool) -> Vec<u8> {
    let (arg0, arg1, arg3) = (Arg(0), Arg(1), Arg(3));
    let local0 = Local(0);
    let zero = Zero {};
    let one = One {};
    let (cdw1, cdw2, cdw3) = (Path::new("CDW1"), Path::new("CDW2"), Path::new("CDW3"));

    let create_cdw1 = CreateDWordField::new(&cdw1, &arg3, &zero);

    let uuid = Uuid::new(OSC_UUID);
    let recognized = Equal::new(&arg0, &uuid);

    let create_cdw2 = CreateDWordField::new(&cdw2, &arg3, &0x04u8);
    let create_cdw3 = CreateDWordField::new(&cdw3, &arg3, &0x08u8);
    let load = Store::new(&local0, &cdw3);
    // keep only the control bits QEMU grants: SHPC, PME, AER, PCIe capability
    let supported: u8 = if pci_hotplug { 0x1e } else { 0x1f };
    let mask = And::new(&local0, &local0, &supported);

    let wrong_revision = NotEqual::new(&arg1, &one);
    let set_revision_error = Or::new(&cdw1, &cdw1, &0x08u8);
    let revision_check = If::new(&wrong_revision, vec![&set_revision_error]);

    let masked_off = NotEqual::new(&cdw3, &local0);
    let set_capability_error = Or::new(&cdw1, &cdw1, &0x10u8);
    let capability_check = If::new(&masked_off, vec![&set_capability_error]);

    let store_back = Store::new(&cdw3, &local0);
    let granted = If::new(
        &recognized,
        vec![
            &create_cdw2,
            &create_cdw3,
            &load,
            &mask,
            &revision_check,
            &capability_check,
            &store_back,
        ],
    );

    // unrecognized UUID: set the "unrecognized" bit and grant nothing
    let set_uuid_error = Or::new(&cdw1, &cdw1, &0x04u8);
    let rejected = Else::new(vec![&set_uuid_error]);

    let ret = Return::new(&arg3);

    emit(&Method::new(
        Path::new("_OSC"),
        4,
        false,
        vec![&create_cdw1, &granted, &rejected, &ret],
    ))
}

/// `Method (EDSM, 5, Serialized)`: the shared body of every PCI slot `_DSM`.
/// Arg0..Arg3 are the `_DSM` arguments; Arg4 is the slot's label package,
/// supplied by the caller so this body can be emitted once.
fn edsm() -> Vec<u8> {
    let (arg0, arg1, arg2, arg4) = (Arg(0), Arg(1), Arg(2), Arg(4));
    let (local0, local1) = (Local(0), Local(1));
    let zero = Zero {};

    let ret_local0 = Return::new(&local0);

    // function 0: report the supported function bitmap
    let query = Equal::new(&arg2, &zero);
    let empty = BufferData::new(vec![0x00]);
    let init = Store::new(&local0, &empty);

    let label_uuid = Uuid::new(DSM_LABEL_UUID);
    let other_uuid = NotEqual::new(&arg0, &label_uuid);
    let uuid_check = If::new(&other_uuid, vec![&ret_local0]);

    let old_revision = LessThan::new(&arg1, &0x02u8);
    let revision_check = If::new(&old_revision, vec![&ret_local0]);

    // functions 0 and 7 are supported, so bits 0 and 7 of the first byte
    let slot0 = Index::new(&zero, &local0, &zero);
    let set_bitmap = Store::new(&slot0, &0x81u8);

    let query_branch = If::new(
        &query,
        vec![
            &init,
            &uuid_check,
            &revision_check,
            &set_bitmap,
            &ret_local0,
        ],
    );

    // function 7: return {slot number, label}, with the slot number lifted
    // out of the caller-supplied package
    let label = Equal::new(&arg2, &0x07u8);
    let blank: AmlStr = "";
    let template = Package::new(vec![&zero, &blank]);
    let alloc = Store::new(&local0, &template);

    let caller_slot0 = Index::new(&zero, &arg4, &zero);
    let deref = DeRefOf::new(&caller_slot0);
    let take_slot = Store::new(&local1, &deref);
    let put_slot = Store::new(&slot0, &local1);

    let label_branch = If::new(&label, vec![&alloc, &take_slot, &put_slot, &ret_local0]);

    emit(&Method::new(
        Path::new("EDSM"),
        5,
        true,
        vec![&query_branch, &label_branch],
    ))
}

/// `Device (DRAC)`: the DRAM controller. It exists only to claim the MMCONFIG
/// window as a producer, so the OS keeps it out of the PCI resource pool.
fn drac() -> Vec<u8> {
    let hid_value: AmlStr = "PNP0C01";
    let hid = Name::new(Path::new("_HID"), &hid_value);

    let window = AddressSpace::new_memory(
        AddressSpaceCacheable::NotCacheable,
        true,
        MCFG_BASE,
        MCFG_LAST,
        None,
    );
    let crs = Name::new(Path::new("_CRS"), &ResourceTemplate::new(vec![&window]));

    emit(&Device::new(Path::new("DRAC"), vec![&hid, &crs]))
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        super::super::fixture::assert_region(&super::build(true), 110, 426);
    }
}
