// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

//! ACPI host bridges emitted for dstack's per-NUMA-node PXBs.

use acpi_tables::aml::{
    AddressSpace, Device, EISAName, Method, Name, PackageBuilder, Path, ResourceTemplate, Return,
    Scope, Zero,
};

use crate::NumaNode;

use super::ops::{emit, Raw};

fn routing_table() -> PackageBuilder {
    let mut table = PackageBuilder::new();
    for slot in 0u32..32 {
        let address = (slot << 16) | 0xffff;
        for pin in 0u8..4 {
            let letter = (b'A' + ((slot as u8 + pin + 3) & 3)) as char;
            let link = Path::new(&format!("LNK{letter}"));
            let mut entry = PackageBuilder::new();
            entry.add_element(&address);
            entry.add_element(&pin);
            entry.add_element(&link);
            entry.add_element(&Zero {});
            table.add_element(&entry);
        }
    }
    table
}

/// One `\\_SB.PCxx` host bridge per expander. QEMU walks the root bus's
/// children, which it keeps newest first, so the last node's comes first.
pub(crate) fn build(nodes: &[NumaNode]) -> Vec<u8> {
    let bridges = nodes
        .iter()
        .enumerate()
        .rev()
        .filter_map(|(pxm, node)| node.pxb_bus.map(|bus| bridge(bus, pxm as u8)));
    bridges
        .map(|bridge| Scope::raw(Path::new("\\_SB_"), bridge))
        .collect::<Vec<_>>()
        .concat()
}

fn bridge(bus: u8, pxm: u8) -> Vec<u8> {
    let uid = Name::new(Path::new("_UID"), &bus);
    let bbn = Name::new(Path::new("_BBN"), &bus);
    let hid = Name::new(Path::new("_HID"), &EISAName::new("PNP0A08"));
    let cid = Name::new(Path::new("_CID"), &EISAName::new("PNP0A03"));
    let osc = super::pci0::osc(false);
    let pxm = Name::new(Path::new("_PXM"), &pxm);

    let routes = routing_table();
    let return_routes = Return::new(&routes);
    let prt = Method::new(Path::new("_PRT"), 0, false, vec![&return_routes]);

    let buses = AddressSpace::new_bus_number(u16::from(bus), u16::from(bus));
    let resources = ResourceTemplate::new(vec![&buses]);
    let crs = Name::new(Path::new("_CRS"), &resources);

    let osc = Raw(&osc);
    let name = format!("PC{bus:02X}");
    emit(&Device::new(
        Path::new(&name),
        vec![&uid, &bbn, &hid, &cid, &osc, &pxm, &prt, &crs],
    ))
}
