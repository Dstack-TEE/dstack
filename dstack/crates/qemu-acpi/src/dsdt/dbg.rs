// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `Scope (\)`: the QEMU debug port and the `DBUG` string writer.
//!
//! ```asl
//! Scope (\) {
//!     OperationRegion (DBG, SystemIO, 0x0402, One)
//!     Field (DBG, ByteAcc, NoLock, Preserve) { DBGB, 8 }
//!     Method (DBUG, 1, NotSerialized) {
//!         ToHexString (Arg0, Local0)
//!         ToBuffer (Local0, Local0)
//!         Local1 = (SizeOf (Local0) - One)
//!         Local2 = Zero
//!         While ((Local2 < Local1)) {
//!             DBGB = DerefOf (Local0 [Local2])
//!             Local2++
//!         }
//!         DBGB = 0x0A
//!     }
//! }
//! ```

use acpi_tables::aml::{
    Arg, DeRefOf, FieldAccessType, FieldEntry, FieldLockRule, FieldUpdateRule, Index, LessThan,
    Local, One, OpRegion, OpRegionSpace, Path, SizeOf, Store, Subtract, ToBuffer, While, Zero,
};

use super::ops::{emit_all, root_scope, Increment, ToHexString};

pub(crate) fn build() -> Vec<u8> {
    let region = OpRegion::new(
        Path::new("DBG_"),
        OpRegionSpace::SystemIO,
        &0x402u16,
        &One {},
    );
    let field = acpi_tables::aml::Field::new(
        Path::new("DBG_"),
        FieldAccessType::Byte,
        FieldLockRule::NoLock,
        FieldUpdateRule::Preserve,
        vec![FieldEntry::Named(*b"DBGB", 8)],
    );

    let (local0, local1, local2) = (Local(0), Local(1), Local(2));
    let to_hex = ToHexString::new(&local0, &Arg(0));
    let to_buffer = ToBuffer::new(&local0, &local0);
    let size = SizeOf::new(&local0);
    let length = Subtract::new(&local1, &size, &One {});
    let init = Store::new(&local2, &Zero {});

    let dbgb = Path::new("DBGB");
    let index = Index::new(&Zero {}, &local0, &local2);
    let deref = DeRefOf::new(&index);
    let write = Store::new(&dbgb, &deref);
    let advance = Increment::new(&local2);
    let condition = LessThan::new(&local2, &local1);
    let loop_ = While::new(&condition, vec![&write, &advance]);

    let newline = Store::new(&dbgb, &0x0au8);
    let method = acpi_tables::aml::Method::new(
        Path::new("DBUG"),
        1,
        false,
        vec![&to_hex, &to_buffer, &length, &init, &loop_, &newline],
    );

    root_scope(&emit_all(&[&region, &field, &method]))
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        super::super::fixture::assert_region(&super::build(), 36, 110);
    }
}
