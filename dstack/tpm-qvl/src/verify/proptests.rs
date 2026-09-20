// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the TPMS_ATTEST parser.
//!
//! `parse_tpm_attest` is the first thing `verify_quote_with_ca` does, on
//! `quote.message` straight out of an unverified attestation and before any
//! signature is checked. Release binaries are `panic = "abort"`, so the bar is
//! that arbitrary bytes return `Ok` or `Err`, that the walk over the PCR
//! selection list terminates, and that what it decodes to stays proportional
//! to the bytes it came from.

use prop_harness::{case, check};
use proptest::prelude::*;

use super::*;

/// Fixed so a failure reproduces exactly.
const SEED: [u8; 32] = *b"tpm-qvl attest parser seed000001";

const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

fn put_sized(out: &mut Vec<u8>, declared: Option<u16>, bytes: &[u8]) {
    out.extend_from_slice(&declared.unwrap_or(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A TPMS_ATTEST whose fixed header is well formed, so the PCR selection walk
/// is reached, and whose counts and sizes come from the strategy.
fn attest_message() -> impl Strategy<Value = Vec<u8>> {
    let sized = (
        prop::collection::vec(any::<u8>(), 0..32),
        prop_oneof![8 => Just(None), 2 => any::<u16>().prop_map(Some)],
    );
    let selection = (
        any::<u16>(),
        prop::collection::vec(any::<u8>(), 0..8),
        prop_oneof![8 => Just(None), 2 => any::<u8>().prop_map(Some)],
    );
    (
        prop_oneof![6 => Just(TPM_GENERATED_VALUE), 1 => any::<u32>()],
        prop_oneof![6 => Just(TPM_ST_ATTEST_QUOTE), 1 => any::<u16>()],
        sized.clone(),
        sized.clone(),
        any::<(u64, u32, u32, u8, u64)>(),
        prop::collection::vec(selection, 0..4),
        prop_oneof![7 => Just(None), 3 => any::<u32>().prop_map(Some)],
        sized,
    )
        .prop_map(
            |(
                magic,
                type_,
                (signer, declared_signer),
                (data, declared_data),
                (clock, reset, restart, safe, firmware),
                selections,
                declared_selections,
                (digest, declared_digest),
            )| {
                let mut out = vec![];
                out.extend_from_slice(&magic.to_be_bytes());
                out.extend_from_slice(&type_.to_be_bytes());
                put_sized(&mut out, declared_signer, &signer);
                put_sized(&mut out, declared_data, &data);
                out.extend_from_slice(&clock.to_be_bytes());
                out.extend_from_slice(&reset.to_be_bytes());
                out.extend_from_slice(&restart.to_be_bytes());
                out.push(safe);
                out.extend_from_slice(&firmware.to_be_bytes());
                out.extend_from_slice(
                    &declared_selections
                        .unwrap_or(selections.len() as u32)
                        .to_be_bytes(),
                );
                for (hash_alg, bitmap, declared_bitmap) in selections {
                    out.extend_from_slice(&hash_alg.to_be_bytes());
                    out.push(declared_bitmap.unwrap_or(bitmap.len() as u8));
                    out.extend_from_slice(&bitmap);
                }
                put_sized(&mut out, declared_digest, &digest);
                out
            },
        )
}

#[test]
fn parse_tpm_attest_never_panics_on_arbitrary_bytes() {
    check(
        "parse_tpm_attest over arbitrary bytes",
        SEED,
        prop::collection::vec(any::<u8>(), 0..1024),
        |bytes| {
            let _ = parse_tpm_attest(&bytes);
            Ok(())
        },
    );
}

/// The PCR selection walk is a `for` over a `u32` count read from the message,
/// so it must be the *input* that stops it, not the count.
#[test]
fn the_pcr_selection_walk_always_terminates() {
    check(
        "parse_tpm_attest over arbitrary TPMS_ATTEST messages",
        SEED,
        attest_message(),
        |bytes| {
            let _ = parse_tpm_attest(&bytes);
            Ok(())
        },
    );
}

/// Each selection costs at least three bytes of message and yields at most
/// `8 * sizeof_select` indices, so the decoded index list stays a small
/// multiple of the message. Pinned because the walk trusts a `u32` count.
#[test]
fn the_decoded_pcr_indices_stay_proportional_to_the_message() {
    check(
        "parse_tpm_attest output bound",
        SEED,
        attest_message(),
        |bytes| {
            let Ok(attest) = parse_tpm_attest(&bytes) else {
                return Ok(());
            };
            let indices: usize = attest
                .attested_quote_info
                .pcr_selections
                .iter()
                .map(|selection| selection.pcr_indices.len())
                .sum();
            prop_assert!(
                indices <= bytes.len() * 8,
                "a {}-byte message decoded to {indices} PCR indices",
                bytes.len()
            );
            Ok(())
        },
    );
}

/// A message that declares far more selections than it carries must fail on
/// the missing bytes rather than looping on the count.
#[test]
fn an_impossible_pcr_selection_count_is_rejected() {
    let mut message = vec![];
    message.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
    message.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
    put_sized(&mut message, None, &[]);
    put_sized(&mut message, None, &[]);
    message.extend_from_slice(&0u64.to_be_bytes());
    message.extend_from_slice(&0u32.to_be_bytes());
    message.extend_from_slice(&0u32.to_be_bytes());
    message.push(1);
    message.extend_from_slice(&0u64.to_be_bytes());
    message.extend_from_slice(&u32::MAX.to_be_bytes());

    case("pcr selection count of u32::MAX", move || {
        assert!(parse_tpm_attest(&message).is_err());
    });
}
