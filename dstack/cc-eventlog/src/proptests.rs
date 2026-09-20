// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the event-log decoders and the runtime-event digest.
//!
//! `decode_ccel` is handed the CCEL blob carried in an attestation, and
//! `TpmEventLog::decode` the `binary_bios_measurements` blob; both are
//! attacker-chosen bytes on the verification path, and release binaries are
//! `panic = "abort"`. Both are also *loops* over length-prefixed records, so
//! "terminates" is as much of the property as "does not panic".
//!
//! The last two tests are about the digest rather than the decoder: the V1
//! runtime-event preimage concatenates `name` and `payload` without length
//! prefixes, so it is not injective, and the V2 canonical JSON is. See
//! [`the_v1_digest_preimage_is_not_injective`].

use prop_harness::{case, check};
use proptest::prelude::*;

use crate::runtime_events::{canonical_event_json_v2, RuntimeEvent, DSTACK_RUNTIME_EVENT_TYPE};
use crate::tcg::TcgEventLog;
use crate::tdx::decode_ccel;
use crate::tpm::TpmEventLog;
use dstack_types::EventLogVersion;

/// Fixed so a failure reproduces exactly.
const SEED: [u8; 32] = *b"cc-eventlog decoder prop seed001";

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, declared_len: Option<u32>, bytes: &[u8]) {
    put_u32(out, declared_len.unwrap_or(bytes.len() as u32));
    out.extend_from_slice(bytes);
}

/// The algorithms `alg_id_to_digest_size` knows, plus values it does not, so
/// the unsupported-algorithm path is reached as well as the sized ones.
fn algorithm() -> impl Strategy<Value = (u16, usize)> {
    prop_oneof![
        3 => Just((0x0004u16, 20usize)),
        3 => Just((0x000bu16, 32usize)),
        2 => Just((0x000cu16, 48usize)),
        2 => Just((0x000du16, 64usize)),
        2 => any::<u16>().prop_map(|algo| (algo, 32usize)),
    ]
}

/// A `TCG_EfiSpecIDEventStruct`, which both decoders parse out of the first
/// event's body.
fn spec_id_event() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<[u8; 16]>(),
        any::<u32>(),
        any::<[u8; 4]>(),
        prop::collection::vec(algorithm(), 0..4),
        prop_oneof![9 => Just(None), 1 => any::<u32>().prop_map(Some)],
        prop::collection::vec(any::<u8>(), 0..8),
        prop_oneof![9 => Just(None), 1 => any::<u8>().prop_map(Some)],
    )
        .prop_map(
            |(
                signature,
                platform_class,
                version,
                algorithms,
                declared_algs,
                vendor,
                declared_vendor,
            )| {
                let mut out = vec![];
                out.extend_from_slice(&signature);
                put_u32(&mut out, platform_class);
                out.extend_from_slice(&version);
                put_u32(&mut out, declared_algs.unwrap_or(algorithms.len() as u32));
                for (algo, size) in algorithms {
                    out.extend_from_slice(&algo.to_le_bytes());
                    out.extend_from_slice(&(size as u16).to_le_bytes());
                }
                out.push(declared_vendor.unwrap_or(vendor.len() as u8));
                out.extend_from_slice(&vendor);
                out
            },
        )
}

/// One `TCG_PCR_EVENT2`: index, type, a digest list, and a sized body.
fn crypto_agile_event() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![5 => 0u32..5, 2 => Just(0xffff_fffeu32), 1 => any::<u32>()],
        prop_oneof![5 => 0u32..16, 2 => Just(DSTACK_RUNTIME_EVENT_TYPE), 1 => any::<u32>()],
        prop::collection::vec(algorithm(), 0..3),
        prop_oneof![9 => Just(None), 1 => any::<u32>().prop_map(Some)],
        prop::collection::vec(any::<u8>(), 0..32),
        prop_oneof![9 => Just(None), 1 => any::<u32>().prop_map(Some)],
    )
        .prop_map(
            |(index, event_type, digests, declared_digests, body, declared_body)| {
                let mut out = vec![];
                put_u32(&mut out, index);
                put_u32(&mut out, event_type);
                put_u32(&mut out, declared_digests.unwrap_or(digests.len() as u32));
                for (algo, size) in digests {
                    out.extend_from_slice(&algo.to_le_bytes());
                    out.extend(std::iter::repeat_n(0xabu8, size));
                }
                put_bytes(&mut out, declared_body, &body);
                out
            },
        )
}

/// A whole log: the legacy spec-id header, crypto-agile events, and an
/// optional `0xffff_ffff` terminator.
fn event_log() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![5 => 0u32..5, 1 => any::<u32>()],
        any::<u32>(),
        any::<[u8; 20]>(),
        spec_id_event(),
        prop_oneof![9 => Just(None), 1 => any::<u32>().prop_map(Some)],
        prop::collection::vec(crypto_agile_event(), 0..6),
        prop_oneof![9 => Just(true), 1 => Just(false)],
    )
        .prop_map(
            |(index, event_type, digest, spec_id, declared_spec_len, events, terminated)| {
                let mut out = vec![];
                put_u32(&mut out, index);
                put_u32(&mut out, event_type);
                out.extend_from_slice(&digest);
                put_bytes(&mut out, declared_spec_len, &spec_id);
                for event in events {
                    out.extend_from_slice(&event);
                }
                if terminated {
                    put_u32(&mut out, 0xffff_ffff);
                }
                out
            },
        )
}

/// Every decoder over the same blob, plus the work `decode_ccel`'s callers do
/// with the result.
fn exercise(data: &[u8]) {
    let _ = TcgEventLog::decode(&mut &data[..]);
    let _ = TpmEventLog::decode(&mut &data[..]);
    let _ = TpmEventLog::decode(&mut &data[..]);
    if let Ok(mut events) = decode_ccel(data) {
        crate::tdx::fill_v2_preimages(&mut events);
        let _ = crate::tdx::validate_v2_preimages(&events);
        for event in &events {
            let _ = event.digest();
            let _ = event.stripped();
        }
    }
}

#[test]
fn the_event_log_decoders_never_panic_on_arbitrary_bytes() {
    check(
        "cc-eventlog decoders over arbitrary bytes",
        SEED,
        prop::collection::vec(any::<u8>(), 0..1024),
        |bytes| {
            exercise(&bytes);
            Ok(())
        },
    );
}

#[test]
fn the_event_log_decoders_always_terminate() {
    check(
        "cc-eventlog decoders over arbitrary event logs",
        SEED,
        event_log(),
        |bytes| {
            exercise(&bytes);
            Ok(())
        },
    );
}

/// A truncated log must be an error, not a hang: the decode loop peeks the
/// next index from a copy of the cursor, so a body that ends mid-record is the
/// shape that could leave the cursor where it is.
#[test]
fn a_truncated_log_is_rejected() {
    let mut full = vec![];
    put_u32(&mut full, 0);
    put_u32(&mut full, 3);
    full.extend_from_slice(&[0u8; 20]);
    let mut spec_id = vec![];
    spec_id.extend_from_slice(b"Spec ID Event03\0");
    put_u32(&mut spec_id, 0);
    spec_id.extend_from_slice(&[0, 2, 0, 8]);
    put_u32(&mut spec_id, 1);
    spec_id.extend_from_slice(&0x000bu16.to_le_bytes());
    spec_id.extend_from_slice(&32u16.to_le_bytes());
    spec_id.push(0);
    put_bytes(&mut full, None, &spec_id);

    for len in 0..full.len() {
        let truncated = full[..len].to_vec();
        case(&format!("truncated log of {len} bytes"), move || {
            exercise(&truncated)
        });
    }
}

/// The **V1 runtime-event digest preimage is not injective**, and this test
/// records the boundary rather than closing it: the encoding is frozen, since
/// changing it would change the RTMR3 replay of every existing deployment.
///
/// The preimage is `type_le || b':' || name || b':' || payload` with no length
/// prefix on either field, so any re-split of the same byte string collides.
/// Searching `(name, payload)` pairs over the alphabet `{'a', ':'}` -- see
/// `the_v2_digest_preimage_is_injective` for the same search over V2 -- finds
/// a counterexample immediately; proptest minimises it to `("::", b":")`
/// against `(":::", b"")`, both of which encode to five colons.
///
/// It is not hypothetical either. `emit_event` lets a workload choose the
/// event name, and real payloads contain `:`: `key-provider` carries a JSON
/// document (`dstack-util/src/system_setup.rs`, `kms/src/main_service.rs`).
/// What it costs is bounded by what a relying party does with the *name*:
/// RTMR3 is replayed over digests, so two logs that differ only by this
/// re-split replay to the same RTMR3 while displaying different
/// `(name, payload)` pairs. V2 closes it, which is what the next test pins.
#[test]
fn the_v1_digest_preimage_is_not_injective() {
    let collide = |(name_a, payload_a): (&str, &[u8]), (name_b, payload_b): (&str, &[u8])| {
        let a = RuntimeEvent::new(name_a.into(), payload_a.to_vec(), EventLogVersion::V1);
        let b = RuntimeEvent::new(name_b.into(), payload_b.to_vec(), EventLogVersion::V1);
        assert_ne!((name_a, payload_a), (name_b, payload_b));
        assert_eq!(
            a.preimage(),
            b.preimage(),
            "the V1 preimage is an unprefixed concatenation, so a re-split collides"
        );
        assert_eq!(
            a.sha384_digest(),
            b.sha384_digest(),
            "colliding preimages mean colliding digests, and so equal RTMR3 replays"
        );
    };

    // The minimal counterexample proptest reports.
    collide(("::", b":"), (":::", b""));
    // The same re-split against an event dstack really emits.
    collide(
        ("key-provider", br#"{"name":"kms"}"#),
        (r#"key-provider:{"name""#, br#""kms"}"#),
    );
}

/// V2 hashes JCS canonical JSON, where the name is a JSON string and the
/// payload is hex, so neither field can absorb a delimiter from the other.
///
/// This is the search that finds the V1 counterexample in one step, run over
/// the same tiny alphabet and widened with the JSON metacharacters that would
/// be the same trick one level up.
#[test]
fn the_v2_digest_preimage_is_injective() {
    let name = prop::collection::vec(
        prop_oneof![Just('a'), Just(':'), Just('"'), Just('\\')],
        0..3,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>());
    let payload = prop::collection::vec(
        prop_oneof![Just(b':'), Just(b'a'), Just(b'"'), Just(b'\\')],
        0..3,
    );
    let event = (name, payload);
    check(
        "canonical_event_json_v2 injectivity",
        SEED,
        (event.clone(), event),
        |((name_a, payload_a), (name_b, payload_b))| {
            let a = canonical_event_json_v2(&name_a, &payload_a);
            let b = canonical_event_json_v2(&name_b, &payload_b);
            let same_input = name_a == name_b && payload_a == payload_b;
            prop_assert_eq!(
                same_input,
                a == b,
                "v2 preimages must be equal exactly when the events are: \
                 ({:?}, {:?}) vs ({:?}, {:?})",
                name_a,
                payload_a,
                name_b,
                payload_b
            );
            Ok(())
        },
    );
}
