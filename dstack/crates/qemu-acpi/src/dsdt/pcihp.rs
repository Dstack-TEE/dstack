// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `Scope (_SB.PCI0)`: the ACPI PCI hotplug registers and the methods that
//! drive them.
//!
//! ```asl
//! Scope (_SB.PCI0) {
//!     OperationRegion (PCST, SystemIO, 0x0CC0, 0x08)
//!     Field (PCST, DWordAcc, NoLock, WriteAsZeros) { PCIU, 32, PCID, 32 }
//!     OperationRegion (SEJ, SystemIO, 0x0CC8, 0x04)
//!     Field (SEJ, DWordAcc, NoLock, WriteAsZeros) { B0EJ, 32 }
//!     OperationRegion (BNMR, SystemIO, 0x0CD0, 0x08)
//!     Field (BNMR, DWordAcc, NoLock, WriteAsZeros) { BNUM, 32, PIDX, 32 }
//!     Mutex (BLCK, 0x00)
//!     Method (PCEJ, 2, NotSerialized) {
//!         Acquire (BLCK, 0xFFFF)
//!         BNUM = Arg0
//!         B0EJ = (One << Arg1)
//!         Release (BLCK)
//!         Return (Zero)
//!     }
//!     Method (AIDX, 2, NotSerialized) {
//!         Acquire (BLCK, 0xFFFF)
//!         BNUM = Arg0
//!         PIDX = (One << Arg1)
//!         Local0 = PIDX
//!         Release (BLCK)
//!         Return (Local0)
//!     }
//!     Method (PDSM, 5, Serialized) {
//!         If ((Arg2 == Zero)) {
//!             Local0 = Buffer (One) { 0x00 }
//!             If ((Arg0 != ToUUID ("e5c937d0-3553-4d7a-9117-ea4d19c3434d"))) {
//!                 Return (Local0)
//!             }
//!             If ((Arg1 < 0x02)) {
//!                 Return (Local0)
//!             }
//!             Local1 = Zero
//!             Local2 = AIDX (DerefOf (Arg4 [Zero]), DerefOf (Arg4 [One]))
//!             If (!((Local2 == Zero) | (Local2 == 0xFFFFFFFF))) {
//!                 Local1 |= One
//!                 Local1 |= (One << 0x07)
//!             }
//!             Local0 [Zero] = Local1
//!             Return (Local0)
//!         }
//!         If ((Arg2 == 0x07)) {
//!             Local2 = AIDX (DerefOf (Arg4 [Zero]), DerefOf (Arg4 [One]))
//!             Local0 = Package (0x02) {}
//!             If (!((Local2 == Zero) || (Local2 == 0xFFFFFFFF))) {
//!                 Local0 [Zero] = Local2
//!                 Local0 [One] = ""
//!             }
//!             Return (Local0)
//!         }
//!     }
//! }
//! ```

use acpi_tables::aml::{
    Acquire, AmlStr, Arg, BufferData, DeRefOf, Equal, Field, FieldAccessType, FieldEntry,
    FieldLockRule, FieldUpdateRule, If, Index, LessThan, Local, Method, MethodCall, Mutex,
    NotEqual, One, OpRegion, OpRegionSpace, Or, Path, Release, Return, Scope, ShiftLeft, Store,
    Uuid, Zero,
};
use acpi_tables::{Aml, AmlSink};

use super::ops::{emit, emit_all, pkg_length, LNot};

/// `LOr (a, b)`. `acpi_tables` models the comparison operators and the bitwise
/// ones, but not the logical connectives, and QEMU uses both `Or` and `LOr` in
/// `PDSM` on otherwise identical operands.
struct LOr<'a> {
    a: &'a dyn Aml,
    b: &'a dyn Aml,
}

impl<'a> LOr<'a> {
    fn new(a: &'a dyn Aml, b: &'a dyn Aml) -> Self {
        Self { a, b }
    }
}

impl Aml for LOr<'_> {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.byte(0x91);
        self.a.to_aml_bytes(sink);
        self.b.to_aml_bytes(sink);
    }
}

/// `Package (count) {}`: a package that reserves element slots but initializes
/// none of them. `Package` and `PackageBuilder` both derive the count from the
/// elements they are given, so neither can express the empty form.
struct EmptyPackage(u8);

impl Aml for EmptyPackage {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.byte(0x12);
        sink.vec(&pkg_length(1));
        sink.byte(self.0);
    }
}

struct LegacyPair;

impl Aml for LegacyPair {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.byte(0x12);
        sink.vec(&pkg_length(4));
        sink.byte(2);
        sink.byte(0); // Zero
        sink.byte(0x0d); // empty string
        sink.byte(0);
    }
}

pub(crate) fn build(modern_device_label: bool) -> Vec<u8> {
    let mut children = registers();
    children.extend(pcej());
    children.extend(aidx());
    children.extend(pdsm(modern_device_label));
    Scope::raw(Path::new("_SB_.PCI0"), children)
}

/// The three hotplug I/O windows, their fields, and the mutex that serializes
/// the two-step "select a bus, then act on it" register protocol.
fn registers() -> Vec<u8> {
    let dword_field = |region: &str, entries: Vec<FieldEntry>| {
        Field::new(
            Path::new(region),
            FieldAccessType::DWord,
            FieldLockRule::NoLock,
            FieldUpdateRule::WriteAsZeroes,
            entries,
        )
    };

    let pcst = OpRegion::new(
        Path::new("PCST"),
        OpRegionSpace::SystemIO,
        &0x0cc0u16,
        &0x08u8,
    );
    let pcst_field = dword_field(
        "PCST",
        vec![
            FieldEntry::Named(*b"PCIU", 32),
            FieldEntry::Named(*b"PCID", 32),
        ],
    );

    let sej = OpRegion::new(
        Path::new("SEJ_"),
        OpRegionSpace::SystemIO,
        &0x0cc8u16,
        &0x04u8,
    );
    let sej_field = dword_field("SEJ_", vec![FieldEntry::Named(*b"B0EJ", 32)]);

    let bnmr = OpRegion::new(
        Path::new("BNMR"),
        OpRegionSpace::SystemIO,
        &0x0cd0u16,
        &0x08u8,
    );
    let bnmr_field = dword_field(
        "BNMR",
        vec![
            FieldEntry::Named(*b"BNUM", 32),
            FieldEntry::Named(*b"PIDX", 32),
        ],
    );

    let lock = Mutex::new(Path::new("BLCK"), 0x00);

    emit_all(&[
        &pcst,
        &pcst_field,
        &sej,
        &sej_field,
        &bnmr,
        &bnmr_field,
        &lock,
    ])
}

/// `PCEJ (bus, slot)`: eject the slot by writing its bit to `B0EJ`.
fn pcej() -> Vec<u8> {
    let (bnum, b0ej) = (Path::new("BNUM"), Path::new("B0EJ"));
    let (arg0, arg1) = (Arg(0), Arg(1));

    let acquire = Acquire::new(Path::new("BLCK"), 0xffff);
    let select = Store::new(&bnum, &arg0);
    let slot_bit = ShiftLeft::new(&Zero {}, &One {}, &arg1);
    let eject = Store::new(&b0ej, &slot_bit);
    let release = Release::new(Path::new("BLCK"));
    let ret = Return::new(&Zero {});

    emit(&Method::new(
        Path::new("PCEJ"),
        2,
        false,
        vec![&acquire, &select, &eject, &release, &ret],
    ))
}

/// `AIDX (bus, slot)`: read back the ACPI index the firmware assigned to the
/// slot, or 0/0xFFFFFFFF when the host does not report one.
fn aidx() -> Vec<u8> {
    let local0 = Local(0);
    let (bnum, pidx) = (Path::new("BNUM"), Path::new("PIDX"));
    let (arg0, arg1) = (Arg(0), Arg(1));

    let acquire = Acquire::new(Path::new("BLCK"), 0xffff);
    let select = Store::new(&bnum, &arg0);
    let slot_bit = ShiftLeft::new(&Zero {}, &One {}, &arg1);
    let request = Store::new(&pidx, &slot_bit);
    let read = Store::new(&local0, &pidx);
    let release = Release::new(Path::new("BLCK"));
    let ret = Return::new(&local0);

    emit(&Method::new(
        Path::new("AIDX"),
        2,
        false,
        vec![&acquire, &select, &request, &read, &release, &ret],
    ))
}

/// `PDSM (uuid, revision, function, args, slot)`: the `_DSM` body shared by
/// every hotplug-capable slot. Function 0 reports which functions exist,
/// function 7 returns the slot's ACPI index and (empty) label.
fn pdsm(modern_device_label: bool) -> Vec<u8> {
    let (local0, local1, local2) = (Local(0), Local(1), Local(2));
    let (arg0, arg1, arg2, arg4) = (Arg(0), Arg(1), Arg(2), Arg(4));

    // shared by both branches: AIDX (DerefOf (Arg4 [Zero]), DerefOf (Arg4 [One]))
    let bus_index = Index::new(&Zero {}, &arg4, &Zero {});
    let bus = DeRefOf::new(&bus_index);
    let slot_index = Index::new(&Zero {}, &arg4, &One {});
    let slot = DeRefOf::new(&slot_index);
    let aidx_call = MethodCall::new(Path::new("AIDX"), vec![&bus, &slot]);
    let read_index = Store::new(&local2, &aidx_call);

    // shared by both branches: the "no index reported" test, once as a bitwise
    // Or and once as a logical LOr, matching QEMU term for term.
    let unassigned = Equal::new(&local2, &Zero {});
    let invalid = Equal::new(&local2, &0xffff_ffffu32);
    let no_index_bitwise = Or::new(&Zero {}, &unassigned, &invalid);
    let has_index_bitwise = LNot::new(&no_index_bitwise);
    let no_index_logical = LOr::new(&unassigned, &invalid);
    let has_index_logical = LNot::new(&no_index_logical);

    let ret0 = Return::new(&local0);

    // If ((Arg2 == Zero)): the supported-function bitmap.
    let empty_bitmap = BufferData::new(vec![0x00]);
    let init_bitmap = Store::new(&local0, &empty_bitmap);

    let uuid = Uuid::new("e5c937d0-3553-4d7a-9117-ea4d19c3434d");
    let wrong_uuid = NotEqual::new(&arg0, &uuid);
    let bail_uuid = If::new(&wrong_uuid, vec![&ret0]);
    let old_revision = LessThan::new(&arg1, &0x02u8);
    let bail_revision = If::new(&old_revision, vec![&ret0]);

    let init_bits = Store::new(&local1, &Zero {});
    let function_zero = Or::new(&local1, &local1, &One {});
    let function_seven_bit = ShiftLeft::new(&Zero {}, &One {}, &0x07u8);
    let function_seven = Or::new(&local1, &local1, &function_seven_bit);
    let set_bits = If::new(&has_index_bitwise, vec![&function_zero, &function_seven]);

    let bitmap_slot = Index::new(&Zero {}, &local0, &Zero {});
    let store_bits = Store::new(&bitmap_slot, &local1);
    let is_query = Equal::new(&arg2, &Zero {});
    let query = If::new(
        &is_query,
        vec![
            &init_bitmap,
            &bail_uuid,
            &bail_revision,
            &init_bits,
            &read_index,
            &set_bits,
            &store_bits,
            &ret0,
        ],
    );

    // If ((Arg2 == 0x07)): the device name, as (ACPI index, label) pair.
    let empty_pair = EmptyPackage(0x02);
    let legacy_pair = LegacyPair;
    let init_empty_pair = Store::new(&local0, &empty_pair);
    let init_legacy_pair = Store::new(&local0, &legacy_pair);
    let init_pair_bytes = if modern_device_label {
        emit(&init_empty_pair)
    } else {
        emit(&init_legacy_pair)
    };
    let init_pair = super::ops::Raw(&init_pair_bytes);
    let index_slot = Index::new(&Zero {}, &local0, &Zero {});
    let store_index = Store::new(&index_slot, &local2);
    let label: AmlStr = "";
    let label_slot = Index::new(&Zero {}, &local0, &One {});
    let store_label = Store::new(&label_slot, &label);
    let modern_fill = If::new(&has_index_logical, vec![&store_index, &store_label]);
    let fill_pair_bytes = if modern_device_label {
        emit(&modern_fill)
    } else {
        emit(&store_index)
    };
    let fill_pair = super::ops::Raw(&fill_pair_bytes);
    let is_name = Equal::new(&arg2, &0x07u8);
    let modern_name = If::new(&is_name, vec![&read_index, &init_pair, &fill_pair, &ret0]);
    let legacy_name = If::new(&is_name, vec![&init_pair, &read_index, &fill_pair, &ret0]);
    let name_bytes = if modern_device_label {
        emit(&modern_name)
    } else {
        emit(&legacy_name)
    };
    let name = super::ops::Raw(&name_bytes);

    emit(&Method::new(
        Path::new("PDSM"),
        5,
        true,
        vec![&query, &name],
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        super::super::fixture::assert_region(&super::build(true), 426, 777);
    }
}
