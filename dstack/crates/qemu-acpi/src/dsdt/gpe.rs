// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! The general purpose event block: its device ID, and the two edge-triggered
//! handlers QEMU wires up. These three fragments are far apart in the table,
//! so each is built and verified separately.
//!
//! ```asl
//! Scope (_GPE) {
//!     Name (_HID, "ACPI0006")
//! }
//!
//! Method (\_GPE._E02, 0, NotSerialized) {
//!     \_SB.CPUS.CSCN ()
//! }
//!
//! Scope (_GPE) {
//!     Method (_E01, 0, NotSerialized) {
//!     }
//! }
//! ```
//!
//! `_E01` is deliberately empty here: it is the PCI hotplug event, and the
//! baseline machine has no hotplug-capable bridge for it to scan.

use acpi_tables::aml::{Acquire, Method, MethodCall, Name, Path, Release, Scope};

use super::ops::emit_all;

/// `Name (_HID, "ACPI0006")`: the GPE block device ID.
const GPE_BLOCK_HID: &str = "ACPI0006";

/// `Scope (_GPE) { Name (_HID, "ACPI0006") }`
pub(crate) fn hid() -> Vec<u8> {
    let id = Name::new(Path::new("_HID"), &GPE_BLOCK_HID);
    emit_all(&[&Scope::new(Path::new("_GPE"), vec![&id])])
}

/// `Method (\_GPE._E02, 0, NotSerialized) { \_SB.CPUS.CSCN () }`, the CPU
/// hotplug event: rescan the CPU devices.
pub(crate) fn e02() -> Vec<u8> {
    let scan = MethodCall::new(Path::new("\\_SB_.CPUS.CSCN"), vec![]);
    emit_all(&[&Method::new(
        Path::new("\\_GPE._E02"),
        0,
        false,
        vec![&scan],
    )])
}

/// `Scope (_GPE) { Method (_E01, 0, NotSerialized) { ... } }`, the PCI
/// hotplug event. QEMU leaves the method empty when no bus supplies PCNT.
pub(crate) fn e01(has_pcnt: bool) -> Vec<u8> {
    let acquire = Acquire::new(Path::new("\\_SB_.PCI0.BLCK"), 0xffff);
    let scan = MethodCall::new(Path::new("\\_SB_.PCI0.PCNT"), vec![]);
    let release = Release::new(Path::new("\\_SB_.PCI0.BLCK"));
    let children: Vec<&dyn acpi_tables::Aml> = if has_pcnt {
        vec![&acquire, &scan, &release]
    } else {
        vec![]
    };
    let handler = Method::new(Path::new("_E01"), 0, false, children);
    emit_all(&[&Scope::new(Path::new("_GPE"), vec![&handler])])
}

#[cfg(test)]
mod tests {
    #[test]
    fn hid_matches_qemu() {
        super::super::fixture::assert_region(&super::hid(), 6271, 6292);
    }

    #[test]
    fn e02_matches_qemu() {
        super::super::fixture::assert_region(&super::e02(), 7354, 7382);
    }

    #[test]
    fn e01_matches_qemu() {
        super::super::fixture::assert_region(&super::e01(false), 8245, 8258);
    }

    #[test]
    fn e01_scans_root_port_buses_when_pcnt_exists() {
        use sha2::{Digest, Sha256};

        let e01 = super::e01(true);
        assert_eq!(e01.len() - super::e01(false).len(), 51);
        assert_eq!(
            hex::encode(Sha256::digest(e01)),
            "6e22ff760f3c9e6263713cd7590518d1fd5ca2cd2344e8856bb618d2bef6d470"
        );
    }
}
