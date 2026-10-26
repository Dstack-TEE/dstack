// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `Scope (PCI0)`: the two PCI interrupt routing tables and `_PRT`.
//!
//! `PRTP` (PIC mode) routes every slot/pin pair to a `LNKx` link device,
//! `PRTA` (APIC mode) routes it to the matching `GSIx` device. Both are a
//! `Package` of 128 entries — 32 slots by 4 pins — with identical shape:
//!
//! ```asl
//! Scope (PCI0) {
//!     Name (PRTP, Package (0x80) {
//!         Package (0x04) { 0xFFFF, Zero, LNKE, Zero },  // slot 0, INTA
//!         ...                                           // 127 more
//!     })
//!     Name (PRTA, Package (0x80) { ... })               // same, GSIx
//!     Method (_PRT, 0, NotSerialized) {
//!         If ((PICF == Zero)) { Return (PRTP) }
//!         Else               { Return (PRTA) }
//!     }
//! }
//! ```
//!
//! Construction rule (QEMU `build_q35_routing_table()` /
//! `append_q35_prt_entry()` in `hw/i386/acpi-build.c`): entry `(slot, pin)`
//! holds the address `(slot << 16) | 0xffff`, the pin index, the link name,
//! and `Zero` for the (unused) source index. The link letter is
//! `base + (head + pin) % 4`, where the per-slot `base`/`head` follow the
//! chipset's default `D<N>IR` values:
//!
//! * slots `0x00..=0x17` — base `E`, head `slot & 3` (PIRQ\[E-H\], rotating)
//! * slot `0x18` — base `E`, head 0
//! * slots `0x19..=0x1d` — base `A`, head 0 (INTA -> PIRQA)
//! * slot `0x1e` — base `E`, head 0 (PCIe->PCI bridge, PIRQ\[E-H\])
//! * slot `0x1f` — base `A`, head 0

use acpi_tables::aml::{Else, Equal, If, Method, Name, PackageBuilder, Path, Return, Scope, Zero};

use super::ops::emit_all;

/// One 128-entry routing table. `prefix` is the three-character device family
/// (`LNK` for PIC mode, `GSI` for APIC mode).
fn routing_table(prefix: &str) -> PackageBuilder {
    let mut table = PackageBuilder::new();
    for slot in 0u32..32 {
        let base = if matches!(slot, 0x19..=0x1d | 0x1f) {
            b'A'
        } else {
            b'E'
        };
        let head = if slot < 0x18 { slot as u8 & 3 } else { 0 };
        // Slot 0's address is 0xffff, which QEMU emits as a word rather than a
        // dword; the `u32` encoder narrows to the same shortest form.
        let address = (slot << 16) | 0xffff;
        for pin in 0u8..4 {
            let name = format!("{prefix}{}", (base + (head + pin) % 4) as char);
            let mut entry = PackageBuilder::new();
            entry.add_element(&address);
            entry.add_element(&pin);
            entry.add_element(&Path::new(&name));
            entry.add_element(&Zero {});
            table.add_element(&entry);
        }
    }
    table
}

pub(crate) fn build() -> Vec<u8> {
    let prtp = Name::new(Path::new("PRTP"), &routing_table("LNK"));
    let prta = Name::new(Path::new("PRTA"), &routing_table("GSI"));

    let picf = Path::new("PICF");
    let zero = Zero {};
    let pic_mode = Equal::new(&picf, &zero);
    let pic_table = Path::new("PRTP");
    let apic_table = Path::new("PRTA");
    let return_pic = Return::new(&pic_table);
    let return_apic = Return::new(&apic_table);
    let if_pic = If::new(&pic_mode, vec![&return_pic]);
    let else_apic = Else::new(vec![&return_apic]);
    let prt = Method::new(Path::new("_PRT"), 0, false, vec![&if_pic, &else_apic]);

    Scope::raw(Path::new("PCI0"), emit_all(&[&prtp, &prta, &prt]))
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_qemu() {
        super::super::fixture::assert_region(&super::build(), 804, 4552);
    }
}
