// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `Scope (\)`: the sleep state packages QEMU advertises for S3/S4/S5.
//!
//! ```asl
//! Scope (\) {
//!     Name (_S3, Package (0x04) { One, One, Zero, Zero })
//!     Name (_S4, Package (0x04) { 0x02, 0x02, Zero, Zero })
//!     Name (_S5, Package (0x04) { Zero, Zero, Zero, Zero })
//! }
//! ```

use acpi_tables::aml::{Name, One, Package, Path, Zero};

use super::ops::{emit_all, root_scope};

pub(crate) fn build() -> Vec<u8> {
    let one = One {};
    let zero = Zero {};
    let two = 2u8;

    // Each package is { PM1a SLP_TYP, PM1b SLP_TYP, reserved, reserved }.
    let s3 = Package::new(vec![&one, &one, &zero, &zero]);
    let s4 = Package::new(vec![&two, &two, &zero, &zero]);
    let s5 = Package::new(vec![&zero, &zero, &zero, &zero]);

    let s3 = Name::new(Path::new("_S3_"), &s3);
    let s4 = Name::new(Path::new("_S4_"), &s4);
    let s5 = Name::new(Path::new("_S5_"), &s5);

    root_scope(&emit_all(&[&s3, &s4, &s5]))
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        super::super::fixture::assert_region(&super::build(), 7732, 7774);
    }
}
