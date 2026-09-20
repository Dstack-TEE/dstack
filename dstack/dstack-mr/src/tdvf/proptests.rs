// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the TDVF metadata parser and MRTD computation.
//!
//! `Tdvf::parse` is handed a whole firmware image: on the TDX-lite path the
//! blob and its metadata come from `vm_config`, which the requester authors.
//! The property is the weakest useful one -- for arbitrary bytes the call
//! returns `Ok` or `Err` within a bounded time and never panics -- because
//! release binaries are `panic = "abort"`, so a panic here aborts
//! `dstack-verifier` or `dstack-kms` instead of failing one measurement.
//!
//! Uniformly random bytes never reach the section walk: they die at the footer
//! GUID. So the strategies below build images that are *structurally* valid --
//! real footer GUID, real metadata GUID, a "TDVF" descriptor -- and draw every
//! number the parser reads from the strategy. That is the shape an attacker
//! sends.

use prop_harness::{case, check, corpus_files};
use proptest::prelude::*;

use super::*;

/// Fixed so a failure reproduces: the same seed, `prop_harness::CASES` and
/// strategy replay the same images in the same order on any machine.
const SEED: [u8; 32] = *b"dstack-mr tdvf parse prop seed01";

const METADATA_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";
const FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const BYTES_AFTER_TABLE_FOOTER: usize = 32;
const GUID_TABLE_HEADER_SIZE: usize = 18;

/// One entry of an OVMF-style GUIDed table, laid out `data || len || guid`.
///
/// `len` is separate from `data.len()` on purpose: the backwards walk trusts
/// the field, not the payload, and that is where a zero or wrapping length
/// gets it.
#[derive(Debug, Clone)]
struct TableEntry {
    data: Vec<u8>,
    len: u16,
    guid: Vec<u8>,
}

impl TableEntry {
    fn encode(&self) -> Vec<u8> {
        let mut out = self.data.clone();
        out.extend_from_slice(&self.len.to_le_bytes());
        out.extend_from_slice(&self.guid);
        out
    }
}

/// Close a table the way a real image does: the table bytes, a length covering
/// the table plus the footer entry, the footer GUID, and the reset vector.
fn close_table(prefix: &[u8], table: &[u8], tables_len: Option<u16>) -> Vec<u8> {
    let mut fw = prefix.to_vec();
    fw.extend_from_slice(table);
    let len = tables_len.unwrap_or((table.len() + GUID_TABLE_HEADER_SIZE) as u16);
    fw.extend_from_slice(&len.to_le_bytes());
    fw.extend_from_slice(&encode_guid(FOOTER_GUID).expect("footer guid"));
    fw.extend_from_slice(&[0u8; BYTES_AFTER_TABLE_FOOTER]);
    fw
}

/// The six little-endian fields of a `TdvfSection` record.
#[derive(Debug, Clone)]
struct SectionFields {
    data_offset: u32,
    raw_data_size: u32,
    memory_address: u64,
    memory_data_size: u64,
    sec_type: u32,
    attributes: u32,
}

impl SectionFields {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TDVF_SECTION_SIZE);
        out.extend_from_slice(&self.data_offset.to_le_bytes());
        out.extend_from_slice(&self.raw_data_size.to_le_bytes());
        out.extend_from_slice(&self.memory_address.to_le_bytes());
        out.extend_from_slice(&self.memory_data_size.to_le_bytes());
        out.extend_from_slice(&self.sec_type.to_le_bytes());
        out.extend_from_slice(&self.attributes.to_le_bytes());
        out
    }
}

/// A whole firmware image, with the descriptor reachable through a real
/// GUIDed table.
#[derive(Debug, Clone)]
struct TdvfImage {
    payload_len: usize,
    version: u32,
    sections: Vec<SectionFields>,
    /// All-zero section records appended after `sections`.
    zero_fillers: usize,
    /// `None` declares exactly the records the image holds; `Some` makes the
    /// count a free field, as it is on the wire.
    declared_sections: Option<u32>,
    /// `None` points the metadata entry at the descriptor this image actually
    /// contains; `Some` makes the offset a free field, as it is on the wire.
    meta_offset_from_end: Option<u32>,
}

impl TdvfImage {
    fn encode(&self) -> Vec<u8> {
        let mut records = vec![];
        for section in &self.sections {
            records.extend_from_slice(&section.encode());
        }
        records.extend(std::iter::repeat_n(
            0u8,
            self.zero_fillers * TDVF_SECTION_SIZE,
        ));
        let record_count = (self.sections.len() + self.zero_fillers) as u32;

        let mut payload = vec![0u8; self.payload_len];
        let descriptor_at = payload.len();
        payload.extend_from_slice(b"TDVF");
        payload.extend_from_slice(&(16 + records.len() as u32).to_le_bytes());
        payload.extend_from_slice(&self.version.to_le_bytes());
        payload.extend_from_slice(&self.declared_sections.unwrap_or(record_count).to_le_bytes());
        payload.extend_from_slice(&records);

        // The metadata entry's payload is the descriptor's offset from the end
        // of the image, which is only known once the table is closed.
        let offset_field = payload.len();
        let entry = TableEntry {
            data: vec![0u8; 4],
            len: (4 + GUID_TABLE_HEADER_SIZE) as u16,
            guid: encode_guid(METADATA_GUID).expect("metadata guid"),
        };

        let mut fw = close_table(&payload, &entry.encode(), None);
        let offset = self
            .meta_offset_from_end
            .unwrap_or((fw.len() - descriptor_at) as u32);
        fw[offset_field..offset_field + 4].copy_from_slice(&offset.to_le_bytes());
        fw
    }
}

/// Values that matter to a length or offset field: zero, small, the wrapping
/// end of the range, and uniformly random.
fn interesting_u32() -> impl Strategy<Value = u32> {
    prop_oneof![
        3 => Just(0u32),
        3 => 0u32..0x4000,
        1 => Just(u32::MAX),
        1 => Just(0xffff_fff0u32),
        4 => any::<u32>(),
    ]
}

/// Guest addresses and sizes. Page-aligned values get extra weight because the
/// parser rejects everything else before it can do any work with them.
fn interesting_u64() -> impl Strategy<Value = u64> {
    prop_oneof![
        3 => Just(0u64),
        4 => (0u64..0x2000).prop_map(|page| page * PAGE_SIZE),
        2 => Just(0x1000_0000_0000u64),
        2 => Just(0xffff_ffff_ffff_f000u64),
        3 => any::<u64>().prop_map(|value| value & !(PAGE_SIZE - 1)),
        2 => any::<u64>(),
    ]
}

/// Replacing exactly one field of an otherwise valid section.
///
/// Drawing all six fields independently does not work: the alignment, ordering
/// and in-range checks are conjunctive, so a uniformly drawn section passes
/// roughly one time in twelve and a three-section image roughly one time in
/// two thousand. Measured over 256 images of that shape, *no* section ever
/// reached the hashing loop -- the search was only ever testing the rejection
/// paths. Starting from a section the parser accepts and perturbing one field
/// puts the interesting values on the other side of the checks.
#[derive(Debug, Clone)]
enum Mutation {
    Keep,
    DataOffset(u32),
    RawDataSize(u32),
    MemoryAddress(u64),
    MemoryDataSize(u64),
    SecType(u32),
    Attributes(u32),
}

impl Mutation {
    fn apply(self, mut section: SectionFields) -> SectionFields {
        match self {
            Self::Keep => {}
            Self::DataOffset(value) => section.data_offset = value,
            Self::RawDataSize(value) => section.raw_data_size = value,
            Self::MemoryAddress(value) => section.memory_address = value,
            Self::MemoryDataSize(value) => section.memory_data_size = value,
            Self::SecType(value) => section.sec_type = value,
            Self::Attributes(value) => section.attributes = value,
        }
        section
    }
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        8 => Just(Mutation::Keep),
        1 => interesting_u32().prop_map(Mutation::DataOffset),
        1 => interesting_u32().prop_map(Mutation::RawDataSize),
        1 => interesting_u64().prop_map(Mutation::MemoryAddress),
        1 => interesting_u64().prop_map(Mutation::MemoryDataSize),
        1 => any::<u32>().prop_map(Mutation::SecType),
        1 => any::<u32>().prop_map(Mutation::Attributes),
    ]
}

/// A section whose data lies inside [`PAYLOAD_LEN`], then one field perturbed.
fn section_fields() -> impl Strategy<Value = SectionFields> {
    let valid = (0u64..4, 0u64..4, 0u64..0x100, 0u32..6, 0u32..4).prop_map(
        |(data_page, size_pages, address_page, sec_type, attributes)| SectionFields {
            data_offset: (data_page * PAGE_SIZE) as u32,
            raw_data_size: (size_pages * PAGE_SIZE) as u32,
            memory_address: address_page * PAGE_SIZE,
            memory_data_size: size_pages * PAGE_SIZE,
            sec_type,
            attributes,
        },
    );
    (valid, mutation()).prop_map(|(section, mutation)| mutation.apply(section))
}

/// Big enough that a valid section's `data_offset + memory_data_size` is
/// always inside the image, small enough that 256 of them stay fast.
const PAYLOAD_LEN: usize = 0x8000;

fn tdvf_image() -> impl Strategy<Value = TdvfImage> {
    (
        prop_oneof![6 => Just(PAYLOAD_LEN), 1 => 0usize..PAYLOAD_LEN],
        prop_oneof![6 => Just(1u32), 1 => any::<u32>()],
        prop::collection::vec(section_fields(), 0..6),
        // All-zero records pass every per-section check, so padding with them
        // is how the section-count limit gets reached at all.
        prop_oneof![7 => Just(0usize), 2 => 1usize..100, 1 => Just(200usize)],
        prop_oneof![7 => Just(None), 1 => Just(Some(u32::MAX)), 2 => interesting_u32().prop_map(Some)],
        prop_oneof![9 => Just(None), 1 => interesting_u32().prop_map(Some)],
    )
        .prop_map(
            |(payload_len, version, sections, zero_fillers, declared_sections, meta_offset_from_end)| {
                TdvfImage {
                    payload_len,
                    version,
                    sections,
                    zero_fillers,
                    declared_sections,
                    meta_offset_from_end,
                }
            },
        )
}

/// A GUIDed table of arbitrary entries, to drive the backwards walk itself.
fn guid_table_image() -> impl Strategy<Value = Vec<u8>> {
    let guid = prop_oneof![
        3 => Just(encode_guid(METADATA_GUID).expect("metadata guid")),
        1 => Just(encode_guid(FOOTER_GUID).expect("footer guid")),
        2 => prop::collection::vec(any::<u8>(), 16),
    ];
    let entry = (
        prop::collection::vec(any::<u8>(), 0..64),
        prop_oneof![4 => 0u16..128, 1 => Just(0u16), 2 => any::<u16>()],
        guid,
    )
        .prop_map(|(data, len, guid)| TableEntry { data, len, guid });
    (
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(entry, 0..6),
        prop_oneof![4 => Just(None), 3 => any::<u16>().prop_map(Some)],
    )
        .prop_map(|(prefix, entries, tables_len)| {
            let mut table = vec![];
            for entry in &entries {
                table.extend_from_slice(&entry.encode());
            }
            close_table(&prefix, &table, tables_len)
        })
}

/// Everything a caller does with a parsed image, so a bound that only holds in
/// `parse` but not in the hashing loop still shows up.
fn exercise(fw: &[u8]) {
    let Ok(tdvf) = Tdvf::parse(fw) else {
        return;
    };
    let _ = tdvf.mrtd_two_pass();
    let _ = tdvf.mrtd_single_pass();
    let _ = tdvf.td_hob_witness_v1();
    for memory_size in [0, 0x1000, 0x8000_0000, 0xB000_0000, u64::MAX] {
        let _ = tdvf.measure_td_hob(memory_size);
    }
}

#[test]
fn tdvf_parse_never_panics_on_arbitrary_bytes() {
    check(
        "Tdvf::parse over arbitrary bytes",
        SEED,
        prop::collection::vec(any::<u8>(), 0..0x1000),
        |bytes| {
            exercise(&bytes);
            Ok(())
        },
    );
}

#[test]
fn the_guid_table_walk_always_terminates() {
    check(
        "Tdvf::parse over arbitrary GUIDed tables",
        SEED,
        guid_table_image(),
        |fw| {
            exercise(&fw);
            Ok(())
        },
    );
}

#[test]
fn the_section_table_walk_never_panics() {
    check(
        "Tdvf::parse over arbitrary section tables",
        SEED,
        tdvf_image(),
        |image| {
            exercise(&image.encode());
            Ok(())
        },
    );
}

/// An image the parser accepts must produce a digest, not an error: the bounds
/// added for malformed input must not have excluded a real firmware shape.
#[test]
fn a_well_formed_image_still_measures() {
    let image = TdvfImage {
        payload_len: 0x1000,
        version: 1,
        zero_fillers: 0,
        declared_sections: None,
        sections: vec![
            SectionFields {
                data_offset: 0,
                raw_data_size: 0x1000,
                memory_address: 0x100000,
                memory_data_size: 0x1000,
                sec_type: 0,
                attributes: ATTRIBUTE_MR_EXTEND,
            },
            SectionFields {
                data_offset: 0,
                raw_data_size: 0,
                memory_address: 0x810000,
                memory_data_size: 0x10000,
                sec_type: TDVF_SECTION_TD_HOB,
                attributes: 0,
            },
        ],
        meta_offset_from_end: None,
    };
    let fw = image.encode();
    let tdvf = Tdvf::parse(&fw).expect("a well formed image must parse");
    assert_eq!(tdvf.sections.len(), 2);
    assert_eq!(tdvf.mrtd_two_pass().expect("mrtd").len(), 48);
    tdvf.td_hob_witness_v1().expect("witness");
}

/// Table-driven regression over the checked-in byte patterns. Each file is a
/// shape that once panicked or ran unbounded; the random search may or may not
/// rediscover it, so it stays here whether or not it does.
#[test]
fn the_tdvf_corpus_never_panics() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/tdvf");
    for (name, bytes) in corpus_files(dir) {
        case(&format!("tdvf corpus {name}"), move || exercise(&bytes));
    }
}
