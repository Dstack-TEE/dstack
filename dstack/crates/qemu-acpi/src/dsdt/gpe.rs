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

use acpi_tables::aml::{Method, MethodCall, Name, Path, Scope};

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

/// `Scope (_GPE) { Method (_E01, 0, NotSerialized) {} }`, the PCI hotplug
/// event.
pub(crate) fn e01() -> Vec<u8> {
    let handler = Method::new(Path::new("_E01"), 0, false, vec![]);
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
        super::super::fixture::assert_region(&super::e01(), 8245, 8258);
    }
}
