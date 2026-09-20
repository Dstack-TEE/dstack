// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the OVMF footer and SEV metadata parsers.
//!
//! `ovmf_footer_table_bytes`, `ovmf_footer_entries`, `parse_ovmf_footer` and
//! `parse_ovmf_metadata_sections` all walk a binary backwards from its last
//! byte using lengths the binary supplies. The OVMF image is an artifact named
//! by the image metadata, so the property is that any byte string returns `Ok`
//! or `Err` -- and that the backwards walk terminates, since a zero or
//! non-advancing entry size is what would stop it from doing so.

use prop_harness::{case, check, corpus_files};
use proptest::prelude::*;

use super::*;

/// Fixed so a failure reproduces exactly.
const SEED: [u8; 32] = *b"dstack-mr ovmf footer seed00001!";

/// One footer entry, laid out `data || size || guid`. `size` is separate from
/// `data.len()` because the walk trusts the field.
#[derive(Debug, Clone)]
struct FooterEntry {
    data: Vec<u8>,
    size: u16,
    guid: [u8; 16],
}

impl FooterEntry {
    fn encode(&self) -> Vec<u8> {
        let mut out = self.data.clone();
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.guid);
        out
    }
}

/// An OVMF binary with a real footer GUID, so the walk is reached, and every
/// length it reads drawn from the strategy.
fn ovmf_image() -> impl Strategy<Value = Vec<u8>> {
    let guid = prop_oneof![
        2 => Just(GUID_SEV_HASH_TABLE_RV),
        2 => Just(GUID_SEV_ES_RESET_BLK),
        2 => Just(GUID_SEV_META_DATA),
        1 => Just(GUID_FOOTER_TABLE),
        2 => any::<[u8; 16]>(),
    ];
    let entry = (
        prop::collection::vec(any::<u8>(), 0..32),
        prop_oneof![4 => 18u16..64, 2 => 0u16..18, 2 => any::<u16>()],
        guid,
    )
        .prop_map(|(data, size, guid)| FooterEntry { data, size, guid });
    (
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(entry, 0..6),
        // The footer's own `total_size`: correct, or anything.
        prop_oneof![4 => Just(None), 3 => any::<u16>().prop_map(Some)],
    )
        .prop_map(|(prefix, entries, total_size)| {
            let mut table = vec![];
            for entry in &entries {
                table.extend_from_slice(&entry.encode());
            }
            let mut image = prefix;
            image.extend_from_slice(&table);
            let total = total_size.unwrap_or((table.len() + OVMF_FOOTER_ENTRY_SIZE) as u16);
            image.extend_from_slice(&total.to_le_bytes());
            image.extend_from_slice(&GUID_FOOTER_TABLE);
            image.extend_from_slice(&[0u8; OVMF_RESET_VECTOR_TAIL_SIZE]);
            image
        })
}

/// A SEV metadata blob with the `ASEV` magic, so the section decode is reached.
fn sev_metadata_image() -> impl Strategy<Value = (Vec<u8>, usize)> {
    (
        prop::collection::vec(any::<u8>(), 0..32),
        any::<u32>(),
        prop_oneof![4 => Just(1u32), 1 => any::<u32>()],
        prop_oneof![5 => 0u32..8, 2 => 0u32..200, 1 => Just(u32::MAX)],
        prop::collection::vec(
            (
                any::<u32>(),
                any::<u32>(),
                prop_oneof![5 => 0u32..6, 1 => any::<u32>()],
            ),
            0..8,
        ),
        prop_oneof![4 => Just(None), 3 => any::<u32>().prop_map(Some)],
    )
        .prop_map(
            |(prefix, size, version, declared, sections, offset_override)| {
                let mut image = prefix;
                let meta_start = image.len();
                image.extend_from_slice(b"ASEV");
                image.extend_from_slice(&size.to_le_bytes());
                image.extend_from_slice(&version.to_le_bytes());
                image.extend_from_slice(&declared.to_le_bytes());
                for (gpa, size, section_type) in sections {
                    image.extend_from_slice(&gpa.to_le_bytes());
                    image.extend_from_slice(&size.to_le_bytes());
                    image.extend_from_slice(&section_type.to_le_bytes());
                }
                let offset = offset_override.unwrap_or((image.len() - meta_start) as u32) as usize;
                (image, offset)
            },
        )
}

fn exercise_footer(data: &[u8]) {
    if let Ok(table) = ovmf_footer_table_bytes(data) {
        let _ = ovmf_footer_entries(table);
    }
    if let Ok(footer) = parse_ovmf_footer(data) {
        let _ = parse_ovmf_metadata_sections(data, footer.metadata_offset_from_end);
    }
    let _ = OvmfInfo::parse(data.to_vec());
}

#[test]
fn the_footer_walk_never_panics_on_arbitrary_bytes() {
    check(
        "ovmf footer parsers over arbitrary bytes",
        SEED,
        prop::collection::vec(any::<u8>(), 0..512),
        |bytes| {
            exercise_footer(&bytes);
            Ok(())
        },
    );
}

#[test]
fn the_footer_walk_always_terminates() {
    check(
        "ovmf footer parsers over arbitrary footer tables",
        SEED,
        ovmf_image(),
        |image| {
            exercise_footer(&image);
            Ok(())
        },
    );
}

#[test]
fn the_metadata_section_decode_never_panics() {
    check(
        "parse_ovmf_metadata_sections over arbitrary metadata",
        SEED,
        sev_metadata_image(),
        |(image, offset_from_end)| {
            let _ = parse_ovmf_metadata_sections(&image, offset_from_end);
            Ok(())
        },
    );
}

#[test]
fn the_ovmf_corpus_never_panics() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/ovmf");
    for (name, bytes) in corpus_files(dir) {
        case(&format!("ovmf corpus {name}"), move || {
            exercise_footer(&bytes);
            // The metadata offset is a field of the footer, so drive the
            // section decode directly too: a blob whose footer is malformed
            // still reaches this parser through a different image.
            for offset in [0usize, 1, 16, bytes.len(), bytes.len().saturating_add(1)] {
                let _ = parse_ovmf_metadata_sections(&bytes, offset);
            }
        });
    }
}
