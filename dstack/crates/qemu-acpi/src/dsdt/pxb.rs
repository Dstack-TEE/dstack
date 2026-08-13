// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

//! ACPI host bridge emitted for dstack's GPU PXB.

use acpi_tables::aml::{
    AddressSpace, Device, EISAName, Method, Name, PackageBuilder, Path, ResourceTemplate, Return,
    Scope, Zero,
};

use super::ops::{emit, Raw};

const BUS: u8 = 5;

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

pub(crate) fn build() -> Vec<u8> {
    let uid = Name::new(Path::new("_UID"), &BUS);
    let bbn = Name::new(Path::new("_BBN"), &BUS);
    let hid = Name::new(Path::new("_HID"), &EISAName::new("PNP0A08"));
    let cid = Name::new(Path::new("_CID"), &EISAName::new("PNP0A03"));
    let osc = super::pci0::osc(false);
    let pxm = Name::new(Path::new("_PXM"), &Zero {});

    let routes = routing_table();
    let return_routes = Return::new(&routes);
    let prt = Method::new(Path::new("_PRT"), 0, false, vec![&return_routes]);

    let buses = AddressSpace::new_bus_number(u16::from(BUS), u16::from(BUS));
    let resources = ResourceTemplate::new(vec![&buses]);
    let crs = Name::new(Path::new("_CRS"), &resources);

    let osc = Raw(&osc);
    let bridge = Device::new(
        Path::new("PC05"),
        vec![&uid, &bbn, &hid, &cid, &osc, &pxm, &prt, &crs],
    );
    Scope::raw(Path::new("\\_SB_"), emit(&bridge))
}
