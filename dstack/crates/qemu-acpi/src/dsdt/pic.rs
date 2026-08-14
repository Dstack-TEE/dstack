// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! The interrupt model the OS selected. `_PIC` only records the choice; the
//! `_PRT` methods later in the table read `PICF` back to decide which routing
//! package to return.
//!
//! ```asl
//! Name (PICF, Zero)
//! Method (_PIC, 1, NotSerialized) {
//!     PICF = Arg0
//! }
//! ```

use acpi_tables::aml::{Arg, Method, Name, Path, Store, Zero};

use super::ops::emit_all;

pub(crate) fn build() -> Vec<u8> {
    let picf = Path::new("PICF");
    let flag = Name::new(Path::new("PICF"), &Zero {});
    let record = Store::new(&picf, &Arg(0));
    let method = Method::new(Path::new("_PIC"), 1, false, vec![&record]);

    emit_all(&[&flag, &method])
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        super::super::fixture::assert_region(&super::build(), 777, 796);
    }
}
