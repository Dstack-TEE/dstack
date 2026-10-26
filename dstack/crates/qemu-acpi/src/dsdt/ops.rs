// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! AML terms QEMU emits that `acpi_tables` does not model, plus the helper
//! that turns any term into bytes.
//!
//! Keep this module small: anything that exists upstream should be used from
//! upstream, so this stays a list of genuine gaps rather than a second builder.

use acpi_tables::{Aml, AmlSink};

/// Serialize one AML term.
pub(crate) fn emit(term: &dyn Aml) -> Vec<u8> {
    let mut bytes = Vec::new();
    term.to_aml_bytes(&mut bytes);
    bytes
}

/// Serialize a list of AML terms in order.
pub(crate) fn emit_all(terms: &[&dyn Aml]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for term in terms {
        term.to_aml_bytes(&mut bytes);
    }
    bytes
}

macro_rules! object_op {
    ($(#[$doc:meta])* $name:ident, $opcode:expr) => {
        $(#[$doc])*
        pub(crate) struct $name<'a> {
            operand: &'a dyn Aml,
        }

        impl<'a> $name<'a> {
            pub(crate) fn new(operand: &'a dyn Aml) -> Self {
                Self { operand }
            }
        }

        impl Aml for $name<'_> {
            fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
                sink.byte($opcode);
                self.operand.to_aml_bytes(sink);
            }
        }
    };
}

object_op!(
    /// `Increment (operand)`
    Increment,
    0x75
);
object_op!(
    /// `LNot (operand)`
    LNot,
    0x92
);

/// `ToHexString (operand, target)`
pub(crate) struct ToHexString<'a> {
    operand: &'a dyn Aml,
    target: &'a dyn Aml,
}

impl<'a> ToHexString<'a> {
    pub(crate) fn new(target: &'a dyn Aml, operand: &'a dyn Aml) -> Self {
        Self { operand, target }
    }
}

impl Aml for ToHexString<'_> {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.byte(0x98);
        self.operand.to_aml_bytes(sink);
        self.target.to_aml_bytes(sink);
    }
}

/// AML `PkgLength` for a term body of `content` bytes, using the same width
/// rule as QEMU: the smallest encoding that still fits once the length bytes
/// are counted in.
pub(crate) fn pkg_length(content: usize) -> Vec<u8> {
    let width = if content < (1 << 6) - 1 {
        1
    } else if content < (1 << 12) - 2 {
        2
    } else if content < (1 << 20) - 3 {
        3
    } else {
        4
    };
    let length = content + width;
    let mut out = Vec::with_capacity(width);
    if width == 1 {
        out.push(length as u8);
        return out;
    }
    out.push((((width - 1) as u8) << 6) | (length & 0x0f) as u8);
    for index in 0..width - 1 {
        out.push((length >> (4 + index * 8)) as u8);
    }
    out
}

/// `Scope (\) { .. }`. `acpi_tables::aml::Path` requires four-character name
/// segments, so it cannot express the root scope's null name.
pub(crate) fn root_scope(children: &[u8]) -> Vec<u8> {
    let mut body = vec![b'\\', 0x00];
    body.extend_from_slice(children);
    let mut out = vec![0x10];
    out.extend(pkg_length(body.len()));
    out.extend(body);
    out
}

/// Raw pre-encoded AML, for terms that are more readable as bytes than as a
/// tree. Used sparingly and always next to the ASL it encodes.
pub(crate) struct Raw<'a>(pub(crate) &'a [u8]);

impl Aml for Raw<'_> {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.vec(self.0);
    }
}
