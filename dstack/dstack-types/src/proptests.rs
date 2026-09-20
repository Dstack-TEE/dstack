// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the CBOR measurement decoders and the sha256sum parser.
//!
//! `*OsImageMeasurement::from_cbor_slice` decodes `measurement.*.cbor` out of
//! the image-measurement document a requester supplies, and
//! `sha256sum_entry_hash` reads the `sha256sum.txt` that document carries.
//! Both are attacker-shaped bytes on the KMS and verifier path, where release
//! binaries are `panic = "abort"`.
//!
//! Random bytes are not a CBOR document, so the strategies here mostly work
//! from a *valid* measurement and mutate it, which is what reaches the
//! per-field checks past the decoder.

use prop_harness::{case, check};
use proptest::prelude::*;

use crate::{
    sha256sum_entry_hash, AwsOsImageMeasurement, GcpOsImageMeasurement, OvmfSection, OvmfVariant,
    SevOsImageMeasurement, TdxImageMeasurement, TdxMrtdCandidates, TdxOsImageMeasurement,
    TdxTdvfMeasurement,
};

/// Fixed so a failure reproduces exactly.
const SEED: [u8; 32] = *b"dstack-types measurement seed001";

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

fn decode_all(blob: &[u8]) {
    let _ = TdxOsImageMeasurement::from_cbor_slice(blob);
    let _ = SevOsImageMeasurement::from_cbor_slice(blob);
    let _ = GcpOsImageMeasurement::from_cbor_slice(blob);
    let _ = AwsOsImageMeasurement::from_cbor_slice(blob);
    let _ = TdxOsImageMeasurement::cbor_json_value_from_slice(blob);
    let _ = SevOsImageMeasurement::cbor_json_value_from_slice(blob);
    let _ = GcpOsImageMeasurement::cbor_json_value_from_slice(blob);
}

fn tdx_measurement() -> impl Strategy<Value = TdxOsImageMeasurement> {
    (
        ".{0,64}",
        bytes(48),
        bytes(48),
        bytes(48),
        bytes(48),
        bytes(32),
        any::<bool>(),
    )
        .prop_map(
            |(
                base_cmdline,
                kernel_authenticode,
                initrd_sha384,
                single_pass,
                two_pass,
                td_hob_witness,
                kernel_header_normalized,
            )| TdxOsImageMeasurement {
                image: TdxImageMeasurement {
                    base_cmdline,
                    kernel_authenticode,
                    initrd_sha384,
                },
                tdvf: TdxTdvfMeasurement {
                    ovmf_variant: OvmfVariant::Pre202505,
                    mrtd: TdxMrtdCandidates {
                        single_pass,
                        two_pass,
                    },
                    td_hob_witness,
                },
                kernel_header_normalized,
            },
        )
}

fn sev_measurement() -> impl Strategy<Value = SevOsImageMeasurement> {
    let section =
        (any::<u64>(), any::<u64>(), any::<u32>()).prop_map(|(gpa, size, section_type)| {
            OvmfSection {
                gpa,
                size,
                section_type,
            }
        });
    (
        ".{0,64}",
        bytes(48),
        bytes(32),
        bytes(32),
        any::<u64>(),
        any::<u32>(),
        prop::collection::vec(section, 0..4),
    )
        .prop_map(
            |(
                base_cmdline,
                ovmf_hash,
                kernel_hash,
                initrd_hash,
                sev_hashes_table_gpa,
                sev_es_reset_eip,
                ovmf_sections,
            )| SevOsImageMeasurement {
                base_cmdline,
                ovmf_hash,
                kernel_hash,
                initrd_hash,
                sev_hashes_table_gpa,
                sev_es_reset_eip,
                ovmf_sections,
            },
        )
}

/// A valid encoding of one of the four documents.
fn measurement_cbor() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        tdx_measurement().prop_map(|m| m.to_cbor_vec()),
        sev_measurement().prop_map(|m| m.to_cbor_vec()),
        prop::collection::vec(any::<u8>(), 32).prop_map(|digest| {
            GcpOsImageMeasurement::new(digest)
                .map(|m| m.to_cbor_vec())
                .unwrap_or_default()
        }),
        prop::collection::vec(any::<u8>(), 32).prop_map(|digest| {
            AwsOsImageMeasurement::new(digest)
                .map(|m| m.to_cbor_vec())
                .unwrap_or_default()
        }),
    ]
}

#[test]
fn the_cbor_decoders_never_panic_on_arbitrary_bytes() {
    check(
        "*OsImageMeasurement::from_cbor_slice over arbitrary bytes",
        SEED,
        bytes(1024),
        |blob| {
            decode_all(&blob);
            Ok(())
        },
    );
}

/// Every decoder over every document, plus byte mutations and truncations:
/// a document meant for one platform must be rejected by the other three, and
/// a corrupted one by all four.
#[test]
fn the_cbor_decoders_never_panic_on_mutated_documents() {
    check(
        "*OsImageMeasurement::from_cbor_slice over mutated documents",
        SEED,
        (
            measurement_cbor(),
            prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..4),
            0usize..8,
        ),
        |(mut blob, patches, truncate)| {
            for (index, patch) in patches {
                if blob.is_empty() {
                    break;
                }
                let at = index.index(blob.len());
                blob[at] ^= patch;
            }
            blob.truncate(blob.len().saturating_sub(truncate));
            decode_all(&blob);
            Ok(())
        },
    );
}

/// Whatever the encoder produces, the decoder accepts and reproduces.
#[test]
fn the_cbor_documents_round_trip() {
    check(
        "TdxOsImageMeasurement CBOR round trip",
        SEED,
        tdx_measurement(),
        |measurement| {
            let decoded = TdxOsImageMeasurement::from_cbor_slice(&measurement.to_cbor_vec())
                .map_err(TestCaseError::fail)?;
            prop_assert_eq!(measurement, decoded);
            Ok(())
        },
    );
    check(
        "SevOsImageMeasurement CBOR round trip",
        SEED,
        sev_measurement(),
        |measurement| {
            let decoded = SevOsImageMeasurement::from_cbor_slice(&measurement.to_cbor_vec())
                .map_err(TestCaseError::fail)?;
            prop_assert_eq!(measurement, decoded);
            Ok(())
        },
    );
}

/// The decoders are recursive descent over an attacker-chosen document, so a
/// deeply nested value is the shape that would blow the stack. `ciborium`
/// reports `RecursionLimitExceeded` instead; this pins that, because losing it
/// would turn a 100 KiB request body into a process-killing segfault.
#[test]
fn deeply_nested_cbor_is_rejected_rather_than_recursed() {
    for depth in [1_000usize, 100_000] {
        // `{"unknown": [[[[ ... 0 ... ]]]], "version": 1}`. The unknown key is
        // what forces the decoder to walk the nested value rather than fail on
        // its type straight away.
        let mut blob = vec![0xa2, 0x67];
        blob.extend_from_slice(b"unknown");
        blob.extend(std::iter::repeat_n(0x81u8, depth));
        blob.push(0x00);
        blob.push(0x67);
        blob.extend_from_slice(b"version");
        blob.push(0x01);

        case(&format!("cbor nested {depth} deep"), move || {
            decode_all(&blob);
        });
    }
}

/// A byte string that declares a length nobody can allocate must fail on the
/// missing bytes, not on the allocation.
#[test]
fn an_impossible_cbor_length_is_rejected_rather_than_allocated() {
    let mut blob = vec![0xa1, 0x68];
    blob.extend_from_slice(b"uki_auth");
    blob.push(0x5b); // byte string with an 8-byte length
    blob.extend_from_slice(&u64::MAX.to_be_bytes());
    case("cbor byte string of u64::MAX", move || decode_all(&blob));
}

/// A manifest that names `filename` twice must never quietly answer with one
/// of the two digests, whatever separates the entries.
///
/// The separator decides how the text reads, and every reading is a refusal.
/// A newline makes two entries, which is a duplicate. A space, a tab, a form
/// feed or a vertical tab makes one line, which `sha256sum -c` reads as a
/// single entry whose filename runs to the end of it. Either way the text
/// names two digests for one file and no single answer is right.
///
/// Stated this way rather than as a second reading of a line, so that it is
/// not the parser's own logic checking the parser: taking only the second
/// whitespace token as the filename returned the first digest for every
/// separator here but the newline.
#[test]
fn a_manifest_naming_one_file_twice_is_rejected() {
    let digest = prop::collection::vec(any::<u8>(), 32).prop_map(hex::encode);
    let separator = prop_oneof![
        Just("\n".to_string()),
        Just("\r\n".to_string()),
        Just(" ".to_string()),
        Just("  ".to_string()),
        Just("\t".to_string()),
        Just("\x0c".to_string()),
        Just("\x0b".to_string()),
    ];
    check(
        "sha256sum_entry_hash ambiguity",
        SEED,
        (
            digest.clone(),
            digest,
            separator,
            prop_oneof![Just("measurement.tdx.cbor"), Just("initrd")],
        ),
        |(first, second, separator, filename)| {
            prop_assume!(first != second);
            let text = format!("{first}  {filename}{separator}{second}  {filename}\n");
            let found = sha256sum_entry_hash(text.as_bytes(), filename);
            prop_assert!(
                found.is_err(),
                "manifest {:?} names {filename} twice but answered {:?}",
                text,
                found.map(hex::encode)
            );
            Ok(())
        },
    );
}

/// Whatever the parser answers with has to be in the text it was given.
#[test]
fn a_returned_digest_comes_from_the_manifest() {
    check(
        "sha256sum_entry_hash provenance",
        SEED,
        (
            manifest_text(),
            prop_oneof![Just("measurement.tdx.cbor"), Just("initrd")],
        ),
        |(text, filename)| {
            let Ok(found) = sha256sum_entry_hash(text.as_bytes(), filename) else {
                return Ok(());
            };
            prop_assert!(
                text.contains(&hex::encode(found)),
                "manifest {:?} does not contain the digest returned for {filename}",
                text
            );
            Ok(())
        },
    );
}

fn manifest_text() -> impl Strategy<Value = String> {
    let digest = prop::collection::vec(any::<u8>(), 32).prop_map(hex::encode);
    let name = prop_oneof![
        4 => Just("measurement.tdx.cbor".to_string()),
        2 => Just("initrd".to_string()),
        1 => "[a-z.]{0,8}".prop_map(|s| s.to_string()),
    ];
    // The separators a `sha256sum.txt` can contain. Form feed and vertical tab
    // matter because `lines()` and `split_whitespace()` disagree about them.
    let separator = prop_oneof![
        5 => Just("\n".to_string()),
        2 => Just("  ".to_string()),
        1 => Just(" ".to_string()),
        1 => Just("\x0c".to_string()),
        1 => Just("\x0b".to_string()),
        1 => Just("\r\n".to_string()),
    ];
    prop::collection::vec((digest, name, separator.clone(), separator), 0..5).prop_map(|entries| {
        let mut out = String::new();
        for (digest, name, inner, outer) in entries {
            out.push_str(&digest);
            out.push_str(&inner);
            out.push_str(&name);
            out.push_str(&outer);
        }
        out
    })
}

#[test]
fn sha256sum_entry_hash_never_panics_on_arbitrary_text() {
    check(
        "sha256sum_entry_hash over arbitrary text",
        SEED,
        (bytes(512), "[a-z.]{0,20}"),
        |(blob, filename)| {
            let _ = sha256sum_entry_hash(&blob, &filename);
            Ok(())
        },
    );
}
