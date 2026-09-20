// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the SEV-SNP report and certificate-table parsers.
//!
//! Both run on an *unverified* attestation: `QuoteVerifier::verify` calls
//! `normalize_ask_vcek_certs` -- and so `parse_kernel_cert_table` -- before it
//! checks a single signature, and `parse_amd_snp_report` decodes the report
//! body before the report is authenticated. Release binaries are
//! `panic = "abort"`, so the bar is that arbitrary bytes return `Ok` or `Err`
//! and never panic, and that the work and memory they cost is bounded by the
//! bytes they came from.

use prop_harness::{case, check};
use proptest::prelude::*;

use super::*;

/// Fixed so a failure reproduces exactly.
const SEED: [u8; 32] = *b"sev-snp-qvl parser prop seed0001";

/// `parse_amd_snp_report` rejects anything but this length up front, so
/// shorter draws only test the length check.
const REPORT_LEN: usize = 1184;

fn cert_table_entry(guid: [u8; 16], offset: u32, length: u32) -> Vec<u8> {
    let mut out = guid.to_vec();
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out
}

/// A certificate table whose entry offsets and lengths come from the strategy,
/// so the walk is reached rather than failing on the first bound.
fn cert_table() -> impl Strategy<Value = Vec<u8>> {
    let guid = prop_oneof![
        2 => Just(ASK_CERT_GUID),
        2 => Just(VCEK_CERT_GUID),
        1 => Just(VLEK_CERT_GUID),
        1 => Just([0u8; 16]),
        2 => any::<[u8; 16]>(),
    ];
    let entry = (
        guid,
        prop_oneof![4 => 0u32..512, 2 => Just(CERT_TABLE_ENTRY_SIZE as u32), 2 => any::<u32>()],
        prop_oneof![4 => 0u32..512, 2 => Just(u32::MAX), 2 => any::<u32>()],
    );
    (
        prop::collection::vec(entry, 0..8),
        // Whether the table is closed by the all-zero terminator, and how much
        // certificate data follows it.
        any::<bool>(),
        0usize..512,
    )
        .prop_map(|(entries, terminated, trailing)| {
            let mut blob = vec![];
            for (guid, offset, length) in entries {
                blob.extend_from_slice(&cert_table_entry(guid, offset, length));
            }
            if terminated {
                blob.extend_from_slice(&cert_table_entry([0u8; 16], 0, 0));
            }
            blob.extend(std::iter::repeat_n(0x30u8, trailing));
            blob
        })
}

/// An auxblob that is nothing but entries, each naming the whole blob. This is
/// the shape whose decoded size is quadratic in the input.
fn amplifying_auxblob(len: usize) -> Vec<u8> {
    let mut blob = vec![0u8; len];
    let entries = len / CERT_TABLE_ENTRY_SIZE;
    for index in 0..entries {
        let at = index * CERT_TABLE_ENTRY_SIZE;
        let entry = cert_table_entry(
            [0x11u8; 16],
            CERT_TABLE_ENTRY_SIZE as u32,
            (len - CERT_TABLE_ENTRY_SIZE) as u32,
        );
        blob[at..at + CERT_TABLE_ENTRY_SIZE].copy_from_slice(&entry);
    }
    blob
}

#[test]
fn parse_amd_snp_report_never_panics_on_arbitrary_bytes() {
    check(
        "parse_amd_snp_report over arbitrary bytes",
        SEED,
        prop_oneof![
            6 => prop::collection::vec(any::<u8>(), REPORT_LEN),
            2 => prop::collection::vec(any::<u8>(), 0..REPORT_LEN),
            1 => prop::collection::vec(any::<u8>(), REPORT_LEN..REPORT_LEN * 2),
        ],
        |bytes| {
            let _ = parse_amd_snp_report(&bytes);
            Ok(())
        },
    );
}

#[test]
fn parse_kernel_cert_table_never_panics_on_arbitrary_bytes() {
    check(
        "parse_kernel_cert_table over arbitrary bytes",
        SEED,
        prop::collection::vec(any::<u8>(), 0..1024),
        |bytes| {
            let _ = parse_kernel_cert_table(&bytes);
            let _ = normalize_ask_vcek_certs(&[bytes]);
            Ok(())
        },
    );
}

/// What the table decodes to must be bounded by the table: an entry is 24
/// bytes and can name the whole blob, so without a limit the decoded size is
/// quadratic in the input and every copy is held at once.
#[test]
fn a_certificate_table_decodes_to_a_bounded_amount_of_data() {
    check(
        "parse_kernel_cert_table output bound",
        SEED,
        cert_table(),
        |blob| {
            let Ok(entries) = parse_kernel_cert_table(&blob) else {
                return Ok(());
            };
            prop_assert!(
                entries.len() <= MAX_CERT_TABLE_ENTRIES,
                "{} entries decoded from a {}-byte table",
                entries.len(),
                blob.len()
            );
            let decoded: usize = entries.iter().map(|(_, data)| data.len()).sum();
            prop_assert!(
                decoded <= MAX_CERT_TABLE_ENTRIES * blob.len(),
                "a {}-byte table decoded to {decoded} bytes",
                blob.len()
            );
            Ok(())
        },
    );
}

/// A 1 MiB auxblob laid out entirely as entries naming the whole blob decoded
/// to about 46 GiB before the entry limit, held all at once, on the unverified
/// path. It has to be an error now, and a fast one.
#[test]
fn an_amplifying_auxblob_is_rejected_rather_than_copied() {
    for len in [64 * 1024usize, 1024 * 1024] {
        let blob = amplifying_auxblob(len);
        case(&format!("amplifying auxblob of {len} bytes"), move || {
            let err =
                parse_kernel_cert_table(&blob).expect_err("an amplifying auxblob must be rejected");
            assert!(
                format!("{err:#}").contains("entries"),
                "unexpected error: {err:#}"
            );
        });
    }
}

/// The limit must not have excluded the table the SNP guest driver actually
/// produces: ARK, ASK and VCEK laid out end to end.
#[test]
fn a_real_certificate_table_still_parses() {
    let payload_at = CERT_TABLE_ENTRY_SIZE * 4;
    let mut blob = vec![];
    for (index, guid) in [ASK_CERT_GUID, VCEK_CERT_GUID, [0x22u8; 16]]
        .into_iter()
        .enumerate()
    {
        blob.extend_from_slice(&cert_table_entry(
            guid,
            (payload_at + index * 16) as u32,
            16,
        ));
    }
    blob.extend_from_slice(&cert_table_entry([0u8; 16], 0, 0));
    blob.extend(std::iter::repeat_n(0x30u8, 48));

    let entries = parse_kernel_cert_table(&blob).expect("a real table must parse");
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|(_, data)| data.len() == 16));
}
