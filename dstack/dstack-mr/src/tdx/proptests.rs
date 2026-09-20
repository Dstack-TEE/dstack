// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the TD HOB witness decoder.
//!
//! On the TDX-lite path the witness bytes come from `vm_config.tdx_measurement`,
//! which the requester authors, and the decoder turns LEB128 varints straight
//! into page counts and guest addresses. Two properties matter here, not one:
//! the call must not panic, and it must finish -- `MemoryAcceptor::accept`
//! rebuilds and re-sorts the whole range vector per call, so an unbounded range
//! count is quadratic work for a body an attacker posts in one request.

use prop_harness::{case, check, corpus_files};
use proptest::prelude::*;

use super::*;

/// Fixed so a failure reproduces exactly.
const SEED: [u8; 32] = *b"dstack-mr td hob witness seed001";

fn put_varuint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

/// A witness whose varints are well formed but whose values are not, which is
/// the shape that reaches the arithmetic. Random bytes mostly die on the
/// trailing-byte check before they get there.
///
/// The emitted range count is drawn separately from the range *values*, which
/// are cycled from a short vector: the work the decoder does is quadratic in
/// the count, so the count has to be able to get large without making the
/// strategy -- or its shrinking -- generate thousands of independent values.
fn witness() -> impl Strategy<Value = Vec<u8>> {
    let page = prop_oneof![
        4 => 0u64..0x10000,
        2 => Just(0u64),
        1 => Just(u64::MAX),
        1 => Just(u64::MAX / 0x1000),
        2 => any::<u64>(),
    ];
    (
        page.clone(),
        page.clone(),
        // A real witness carries one range per TD_HOB/TEMP_MEM section, four
        // in the current metadata. The large counts are what an attacker can
        // put in a request body at about two bytes a range.
        prop_oneof![6 => 0usize..8, 2 => 0usize..64, 1 => Just(200usize), 1 => Just(20_000usize)],
        prop_oneof![7 => Just(None), 3 => page.clone().prop_map(Some)],
        prop::collection::vec((page.clone(), page), 1..8),
    )
        .prop_map(
            |(base_page, td_hob_page_delta, emitted, declared, values)| {
                let mut out = vec![];
                put_varuint(base_page, &mut out);
                put_varuint(td_hob_page_delta, &mut out);
                put_varuint(declared.unwrap_or(emitted as u64), &mut out);
                for index in 0..emitted {
                    let (start_page_delta, page_count) = values[index % values.len()];
                    // Cycled values would overlap, which the decoder rejects
                    // before it does the quadratic work; step them apart.
                    put_varuint(start_page_delta.wrapping_add(index as u64 * 2), &mut out);
                    put_varuint(page_count, &mut out);
                }
                out
            },
        )
}

fn exercise(data: &[u8]) {
    for memory_size in [0u64, 0x1000, 0x8000_0000, Q35_HIGH_MEMORY_SPLIT, u64::MAX] {
        let _ = measure_td_hob_from_witness_data(data, memory_size);
    }
}

#[test]
fn the_witness_decoder_never_panics_on_arbitrary_bytes() {
    check(
        "measure_td_hob_from_witness_data over arbitrary bytes",
        SEED,
        prop::collection::vec(any::<u8>(), 0..256),
        |bytes| {
            exercise(&bytes);
            Ok(())
        },
    );
}

#[test]
fn the_witness_decoder_terminates_on_arbitrary_varints() {
    check(
        "measure_td_hob_from_witness_data over arbitrary varints",
        SEED,
        witness(),
        |bytes| {
            exercise(&bytes);
            Ok(())
        },
    );
}

/// The range bound must not have excluded a real witness: the four ranges the
/// current metadata generates still measure.
#[test]
fn a_real_witness_still_measures() {
    let mut witness = vec![];
    put_varuint(0x809, &mut witness); // base_page
    put_varuint(0, &mut witness); // td_hob_page_delta
    put_varuint(2, &mut witness); // range_count
    put_varuint(0, &mut witness);
    put_varuint(2, &mut witness);
    put_varuint(7, &mut witness);
    put_varuint(16, &mut witness);
    let digest =
        measure_td_hob_from_witness_data(&witness, 0x1_0000_0000).expect("a real witness measures");
    assert_eq!(digest.len(), 48);
}

#[test]
fn the_witness_corpus_never_panics() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/td_hob_witness");
    for (name, bytes) in corpus_files(dir) {
        case(&format!("witness corpus {name}"), move || exercise(&bytes));
    }
}
