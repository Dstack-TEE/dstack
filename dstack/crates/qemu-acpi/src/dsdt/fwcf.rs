// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `Scope (\_SB.PCI0)`: the fw_cfg device, so the guest can find the fw_cfg
//! I/O ports without probing them.
//!
//! ```asl
//! Scope (\_SB.PCI0) {
//!     Device (FWCF) {
//!         Name (_HID, "QEMU0002")
//!         Name (_STA, 0x0B)
//!         Name (_CRS, ResourceTemplate () {
//!             IO (Decode16, 0x0510, 0x0510, 0x01, 0x0C)
//!         })
//!     }
//! }
//! ```

use acpi_tables::aml::{AmlStr, Device, Name, Path, ResourceTemplate, Scope, IO};

use super::ops::emit;

pub(crate) fn build() -> Vec<u8> {
    let id: AmlStr = "QEMU0002";
    let hid = Name::new(Path::new("_HID"), &id);
    // Present and functioning, but hidden from the user interface.
    let sta = Name::new(Path::new("_STA"), &0x0bu8);

    // The fw_cfg selector, data and DMA registers at 0x510..0x51c.
    let ports = IO::new(0x510, 0x510, 0x01, 0x0c);
    let template = ResourceTemplate::new(vec![&ports]);
    let crs = Name::new(Path::new("_CRS"), &template);

    let device = Device::new(Path::new("FWCF"), vec![&hid, &sta, &crs]);
    Scope::raw(Path::new("\\_SB_.PCI0"), emit(&device))
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        super::super::fixture::assert_region(&super::build(), 7774, 7834);
    }
}
