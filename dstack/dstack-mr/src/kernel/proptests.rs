// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the PE/COFF Authenticode hash.
//!
//! `authenticode_sha384_hash` walks a kernel image using offsets the image
//! itself supplies -- `lfanew`, `SizeOfOptionalHeader`, `SizeOfHeaders`, the
//! section table -- and every one of them is a slice bound. The image is an
//! artifact the requester names, so the property is that any byte string
//! returns `Ok` or `Err` rather than aborting the process.
//!
//! Random bytes stop at the `PE\0\0` signature, so the strategy builds an
//! image that reaches the header walk and draws the header fields from the
//! strategy.

use prop_harness::{case, check, corpus_files};
use proptest::prelude::*;

use super::*;

/// Fixed so a failure reproduces exactly.
const SEED: [u8; 32] = *b"dstack-mr pe authenticode seed01";

/// Where `PeImage` puts the PE signature. A real bzImage uses the same value.
const LFANEW: usize = 0x40;
const COFF_HEADER_OFFSET: usize = LFANEW + 4;
const OPTIONAL_HEADER_OFFSET: usize = COFF_HEADER_OFFSET + 20;

/// A PE/COFF image with a valid DOS stub and signature, and every header field
/// the Authenticode walk reads drawn from the strategy.
#[derive(Debug, Clone)]
struct PeImage {
    len: usize,
    magic: u16,
    optional_header_size: u16,
    size_of_headers: u32,
    num_sections: u16,
    cert_table_addr: u32,
    cert_table_size: u32,
    sections: Vec<(u32, u32)>,
}

impl PeImage {
    fn encode(&self) -> Vec<u8> {
        let mut image = vec![0u8; self.len];
        let put32 = |image: &mut Vec<u8>, at: usize, value: u32| {
            if let Some(slot) = image.get_mut(at..at + 4) {
                slot.copy_from_slice(&value.to_le_bytes());
            }
        };
        let put16 = |image: &mut Vec<u8>, at: usize, value: u16| {
            if let Some(slot) = image.get_mut(at..at + 2) {
                slot.copy_from_slice(&value.to_le_bytes());
            }
        };

        put32(&mut image, 0x3c, LFANEW as u32);
        put32(&mut image, LFANEW, pe::IMAGE_NT_SIGNATURE);
        put16(&mut image, COFF_HEADER_OFFSET + 2, self.num_sections);
        put16(
            &mut image,
            COFF_HEADER_OFFSET + 16,
            self.optional_header_size,
        );
        put16(&mut image, OPTIONAL_HEADER_OFFSET, self.magic);
        put32(
            &mut image,
            OPTIONAL_HEADER_OFFSET + 60,
            self.size_of_headers,
        );

        let data_dir = OPTIONAL_HEADER_OFFSET + if self.magic == 0x20b { 112 } else { 96 };
        let cert_dir = data_dir + pe::IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
        put32(&mut image, cert_dir, self.cert_table_addr);
        put32(&mut image, cert_dir + 4, self.cert_table_size);

        let section_table = OPTIONAL_HEADER_OFFSET + self.optional_header_size as usize;
        for (i, (ptr_raw_data, size_raw_data)) in self.sections.iter().enumerate() {
            let section = section_table + i * 40;
            put32(&mut image, section + 16, *size_raw_data);
            put32(&mut image, section + 20, *ptr_raw_data);
        }
        image
    }
}

fn interesting_u32() -> impl Strategy<Value = u32> {
    prop_oneof![
        3 => Just(0u32),
        3 => 0u32..0x2000,
        1 => Just(u32::MAX),
        1 => Just(0xffff_fff0u32),
        3 => any::<u32>(),
    ]
}

fn pe_image() -> impl Strategy<Value = PeImage> {
    (
        // Long enough to hold the header a valid image needs, and short enough
        // that the whole search stays fast. `lfanew + 88` is the length at
        // which the certificate directory falls off the end of a PE32 image.
        prop_oneof![
            4 => 0x200usize..0x2000,
            2 => Just(LFANEW + 88),
            2 => Just(LFANEW + 24),
            1 => 0usize..0x100,
        ],
        prop_oneof![4 => Just(0x20bu16), 3 => Just(0x10bu16), 1 => any::<u16>()],
        prop_oneof![4 => Just(0xf0u16), 2 => 0u16..0x200, 2 => any::<u16>()],
        interesting_u32(),
        prop_oneof![5 => 0u16..4, 2 => 0u16..64, 1 => any::<u16>()],
        interesting_u32(),
        interesting_u32(),
        prop::collection::vec((interesting_u32(), interesting_u32()), 0..4),
    )
        .prop_map(
            |(
                len,
                magic,
                optional_header_size,
                size_of_headers,
                num_sections,
                cert_table_addr,
                cert_table_size,
                sections,
            )| PeImage {
                len,
                magic,
                optional_header_size,
                size_of_headers,
                num_sections,
                cert_table_addr,
                cert_table_size,
                sections,
            },
        )
}

/// Both entry points: the file digest and QEMU's patched-copy digest, which
/// rewrites the setup header before hashing.
fn exercise(image: &[u8]) {
    let _ = kernel_authenticode_sha384(image);
    for (initrd_size, mem_size, acpi_data_size) in [
        (0u32, 0u64, 0u32),
        (0x1000, 0x8000_0000, 0x1000),
        (u32::MAX, u64::MAX, u32::MAX),
        (0x1000, TDX_KERNEL_HASH_COMPAT_2G_MEMORY, 0),
    ] {
        let _ = patched_kernel_authenticode_sha384(image, initrd_size, mem_size, acpi_data_size);
    }
}

#[test]
fn authenticode_never_panics_on_arbitrary_bytes() {
    check(
        "kernel_authenticode_sha384 over arbitrary bytes",
        SEED,
        prop::collection::vec(any::<u8>(), 0..0x1000),
        |bytes| {
            exercise(&bytes);
            Ok(())
        },
    );
}

#[test]
fn authenticode_never_panics_on_arbitrary_pe_headers() {
    check(
        "kernel_authenticode_sha384 over arbitrary PE headers",
        SEED,
        pe_image(),
        |image| {
            exercise(&image.encode());
            Ok(())
        },
    );
}

/// The bounds added for malformed headers must not have excluded a real image:
/// a well-formed one still hashes.
#[test]
fn a_well_formed_pe_image_still_hashes() {
    let image = PeImage {
        len: 0x2000,
        magic: 0x20b,
        optional_header_size: 0xf0,
        size_of_headers: 0x400,
        num_sections: 1,
        cert_table_addr: 0,
        cert_table_size: 0,
        sections: vec![(0x400, 0x400)],
    };
    let digest = kernel_authenticode_sha384(&image.encode()).expect("a valid PE must hash");
    assert_eq!(digest.len(), 48);
}

#[test]
fn the_pe_corpus_never_panics() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/pe");
    for (name, bytes) in corpus_files(dir) {
        case(&format!("pe corpus {name}"), move || exercise(&bytes));
    }
}
