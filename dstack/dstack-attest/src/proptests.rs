// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Property tests for versioned attestation decoding.
//!
//! `VersionedAttestation::from_bytes` is the outermost decoder on the
//! verification path: it sniffs the first byte and dispatches to either the
//! SCALE v0 form or the MessagePack v1 form, both over bytes a caller chose.
//! Two properties:
//!
//! - arbitrary bytes return `Ok` or `Err` and never panic;
//! - anything that encodes decodes back to the same bytes. `Attestation` has
//!   no `PartialEq`, and the SCALE form deliberately drops `#[codec(skip)]`
//!   fields, so the round-trip is stated on the encoding: `to_bytes` after
//!   `from_bytes` after `to_bytes` is `to_bytes`. That is the property the
//!   wire format actually has to have -- a re-encode that moved would change
//!   the CSR bytes a KMS signs.

use prop_harness::check;
use proptest::prelude::*;

use crate::attestation::{
    Attestation, AttestationQuote, DstackAwsNitroTpmQuote, DstackGcpTdxQuote, DstackNitroQuote,
    SnpQuote, TdxQuote, VersionedAttestation,
};
use crate::v1::{Attestation as AttestationV1, PlatformEvidence, StackEvidence};
use cc_eventlog::{RuntimeEvent, TdxEvent, DSTACK_RUNTIME_EVENT_TYPE};
use dstack_types::{EventLogVersion, Platform};
use tpm_types::{PcrValue, TpmEvent, TpmQuote};

/// Fixed so a failure reproduces exactly.
const SEED: [u8; 32] = *b"dstack-attest versioned seed0001";

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

fn event_log_version() -> impl Strategy<Value = EventLogVersion> {
    prop_oneof![Just(EventLogVersion::V1), Just(EventLogVersion::V2)]
}

fn tdx_event() -> impl Strategy<Value = TdxEvent> {
    (
        0u32..4,
        prop_oneof![3 => Just(DSTACK_RUNTIME_EVENT_TYPE), 1 => any::<u32>()],
        bytes(48),
        "[a-z-]{0,12}",
        bytes(16),
        event_log_version(),
        prop_oneof![3 => Just(None), 1 => Just(Some("00".to_string()))],
    )
        .prop_map(
            |(imr, event_type, digest, event, event_payload, version, preimage)| TdxEvent {
                imr,
                event_type,
                digest,
                event,
                event_payload,
                version,
                preimage,
            },
        )
}

fn runtime_event() -> impl Strategy<Value = RuntimeEvent> {
    ("[a-z-]{0,12}", bytes(16), event_log_version())
        .prop_map(|(event, payload, version)| RuntimeEvent::new(event, payload, version))
}

/// The SCALE-side quote types carry no `Debug`, and proptest needs one to
/// report a counterexample. Draw the *fields* instead and assemble them in the
/// property, so the reported case is the input rather than the object.
#[derive(Debug, Clone)]
enum QuoteSpec {
    Tdx(Vec<u8>, Vec<TdxEvent>),
    GcpTdx(Vec<u8>, Vec<TdxEvent>, TpmQuote),
    NitroEnclave(Vec<u8>),
    SevSnp(Vec<u8>, Vec<Vec<u8>>, String),
    AwsNitroTpm(Vec<u8>),
}

impl QuoteSpec {
    fn build(self) -> AttestationQuote {
        match self {
            Self::Tdx(quote, event_log) => {
                AttestationQuote::DstackTdx(TdxQuote { quote, event_log })
            }
            Self::GcpTdx(quote, event_log, tpm_quote) => {
                AttestationQuote::DstackGcpTdx(DstackGcpTdxQuote {
                    tdx_quote: TdxQuote { quote, event_log },
                    tpm_quote,
                })
            }
            Self::NitroEnclave(nsm_quote) => {
                AttestationQuote::DstackNitroEnclave(DstackNitroQuote { nsm_quote })
            }
            Self::SevSnp(report, cert_chain, mr_config) => {
                AttestationQuote::DstackAmdSevSnp(SnpQuote {
                    report,
                    cert_chain,
                    mr_config,
                })
            }
            Self::AwsNitroTpm(attestation_doc) => {
                AttestationQuote::DstackAwsNitroTpm(DstackAwsNitroTpmQuote { attestation_doc })
            }
        }
    }
}

#[derive(Debug, Clone)]
struct V0Spec {
    quote: QuoteSpec,
    runtime_events: Vec<RuntimeEvent>,
    report_data: [u8; 64],
    config: String,
}

/// Either wire form, as the fields it is built from.
#[derive(Debug, Clone)]
enum Spec {
    V0(V0Spec),
    V1(AttestationV1),
}

impl Spec {
    fn is_v0(&self) -> bool {
        matches!(self, Self::V0(_))
    }

    fn build(self) -> VersionedAttestation {
        match self {
            Self::V0(spec) => VersionedAttestation::V0 {
                attestation: Attestation {
                    quote: spec.quote.build(),
                    runtime_events: spec.runtime_events,
                    report_data: spec.report_data,
                    config: spec.config,
                    report: (),
                },
            },
            Self::V1(attestation) => VersionedAttestation::V1 { attestation },
        }
    }
}

fn tpm_quote() -> impl Strategy<Value = TpmQuote> {
    let pcr_value =
        (0u32..24, "[a-z0-9]{0,8}", bytes(32)).prop_map(|(index, algorithm, value)| PcrValue {
            index,
            algorithm,
            value,
        });
    let tpm_event =
        (0u32..24, bytes(32)).prop_map(|(pcr_index, digest)| TpmEvent { pcr_index, digest });
    (
        bytes(64),
        bytes(64),
        prop::collection::vec(pcr_value, 0..3),
        bytes(64),
        prop_oneof![
            Just(Platform::Dstack),
            Just(Platform::Gcp),
            Just(Platform::NitroEnclave),
            Just(Platform::AwsEc2),
        ],
        prop::collection::vec(tpm_event, 0..3),
    )
        .prop_map(
            |(message, signature, pcr_values, ak_cert, platform, event_log)| TpmQuote {
                message,
                signature,
                pcr_values,
                ak_cert,
                platform,
                event_log,
            },
        )
}

fn event_log() -> impl Strategy<Value = Vec<TdxEvent>> {
    prop::collection::vec(tdx_event(), 0..3)
}

fn quote_spec() -> impl Strategy<Value = QuoteSpec> {
    prop_oneof![
        (bytes(64), event_log()).prop_map(|(quote, log)| QuoteSpec::Tdx(quote, log)),
        (bytes(64), event_log(), tpm_quote())
            .prop_map(|(quote, log, tpm)| QuoteSpec::GcpTdx(quote, log, tpm)),
        bytes(64).prop_map(QuoteSpec::NitroEnclave),
        (bytes(64), prop::collection::vec(bytes(32), 0..3), ".{0,32}")
            .prop_map(|(report, chain, config)| QuoteSpec::SevSnp(report, chain, config)),
        bytes(64).prop_map(QuoteSpec::AwsNitroTpm),
    ]
}

fn v0_spec() -> impl Strategy<Value = Spec> {
    (
        quote_spec(),
        prop::collection::vec(runtime_event(), 0..3),
        any::<[u8; 64]>(),
        ".{0,32}",
    )
        .prop_map(|(quote, runtime_events, report_data, config)| {
            Spec::V0(V0Spec {
                quote,
                runtime_events,
                report_data,
                config,
            })
        })
}

fn platform_evidence() -> impl Strategy<Value = PlatformEvidence> {
    prop_oneof![
        (bytes(64), prop::collection::vec(tdx_event(), 0..3))
            .prop_map(|(quote, event_log)| PlatformEvidence::Tdx { quote, event_log }),
        (
            bytes(64),
            prop::collection::vec(tdx_event(), 0..3),
            tpm_quote()
        )
            .prop_map(|(quote, event_log, tpm_quote)| PlatformEvidence::GcpTdx {
                quote,
                event_log,
                tpm_quote
            }),
        bytes(64).prop_map(|nsm_quote| PlatformEvidence::NitroEnclave { nsm_quote }),
        bytes(64).prop_map(|attestation_doc| PlatformEvidence::AwsNitroTpm { attestation_doc }),
        (bytes(64), prop::collection::vec(bytes(32), 0..3), ".{0,32}").prop_map(
            |(report, cert_chain, mr_config)| PlatformEvidence::SevSnp {
                report,
                cert_chain,
                mr_config
            }
        ),
    ]
}

fn stack_fields() -> impl Strategy<Value = (Vec<u8>, Vec<RuntimeEvent>, String)> {
    (
        bytes(72),
        prop::collection::vec(runtime_event(), 0..3),
        ".{0,32}",
    )
}

fn stack_evidence() -> impl Strategy<Value = StackEvidence> {
    prop_oneof![
        stack_fields().prop_map(|(report_data, runtime_events, config)| {
            StackEvidence::Dstack {
                report_data,
                runtime_events,
                config,
            }
        }),
        (stack_fields(), ".{0,16}").prop_map(
            |((report_data, runtime_events, config), report_data_payload)| {
                StackEvidence::DstackPod {
                    report_data,
                    runtime_events,
                    config,
                    report_data_payload,
                }
            }
        ),
    ]
}

fn v1_spec() -> impl Strategy<Value = Spec> {
    (any::<u64>(), platform_evidence(), stack_evidence()).prop_map(|(version, platform, stack)| {
        let mut attestation = AttestationV1::new(platform, stack);
        attestation.version = version;
        Spec::V1(attestation)
    })
}

#[test]
fn from_bytes_never_panics_on_arbitrary_bytes() {
    check(
        "VersionedAttestation::from_bytes over arbitrary bytes",
        SEED,
        bytes(4096),
        |bytes| {
            let _ = VersionedAttestation::from_bytes(&bytes);
            Ok(())
        },
    );
}

/// The first byte selects the wire form, so a search that never produces a
/// SCALE `0x00` or a MessagePack map prefix only tests the "unknown format"
/// branch. Prefix the bytes explicitly.
#[test]
fn from_bytes_never_panics_on_arbitrary_tagged_bytes() {
    let prefix = prop_oneof![
        3 => Just(0x00u8),
        3 => 0x80u8..=0x8f,
        2 => prop_oneof![Just(0xdeu8), Just(0xdfu8)],
        2 => any::<u8>(),
    ];
    check(
        "VersionedAttestation::from_bytes over arbitrary tagged bytes",
        SEED,
        (prefix, bytes(2048)),
        |(prefix, body)| {
            let mut input = vec![prefix];
            input.extend_from_slice(&body);
            let _ = VersionedAttestation::from_bytes(&input);
            Ok(())
        },
    );
}

/// Bytes that are a *valid* encoding with one byte flipped: the decoder should
/// still return, and the shape is the one a truncating or corrupting transport
/// produces.
#[test]
fn from_bytes_never_panics_on_mutated_encodings() {
    check(
        "VersionedAttestation::from_bytes over mutated encodings",
        SEED,
        (
            prop_oneof![v0_spec(), v1_spec()],
            any::<prop::sample::Index>(),
            any::<u8>(),
            0usize..4,
        ),
        |(spec, index, patch, truncate)| {
            let Ok(mut encoded) = spec.build().to_bytes() else {
                return Ok(());
            };
            if !encoded.is_empty() {
                let at = index.index(encoded.len());
                encoded[at] ^= patch;
            }
            encoded.truncate(encoded.len().saturating_sub(truncate));
            let _ = VersionedAttestation::from_bytes(&encoded);
            Ok(())
        },
    );
}

/// `to_bytes` after `from_bytes` after `to_bytes` is `to_bytes`: whatever the
/// decoder makes of an encoding, re-encoding it does not move the bytes.
fn round_trips(spec: Spec) -> Result<(), TestCaseError> {
    let attestation = spec.build();
    let encoded = attestation
        .to_bytes()
        .map_err(|err| TestCaseError::fail(format!("encode failed: {err:#}")))?;
    let decoded = VersionedAttestation::from_bytes(&encoded)
        .map_err(|err| TestCaseError::fail(format!("decode failed: {err:#}")))?;
    let re_encoded = decoded
        .to_bytes()
        .map_err(|err| TestCaseError::fail(format!("re-encode failed: {err:#}")))?;
    prop_assert_eq!(encoded, re_encoded);
    Ok(())
}

#[test]
fn the_scale_v0_form_round_trips() {
    check(
        "VersionedAttestation V0 round trip",
        SEED,
        v0_spec(),
        round_trips,
    );
}

#[test]
fn the_msgpack_v1_form_round_trips() {
    check(
        "VersionedAttestation V1 round trip",
        SEED,
        v1_spec(),
        round_trips,
    );
}

/// The sniff must be total: whichever form an encoder produced, the decoder
/// has to pick the same one back.
#[test]
fn the_wire_form_survives_a_round_trip() {
    check(
        "VersionedAttestation wire form sniffing",
        SEED,
        prop_oneof![v0_spec(), v1_spec()],
        |spec| {
            let was_v0 = spec.is_v0();
            let encoded = spec
                .build()
                .to_bytes()
                .map_err(|err| TestCaseError::fail(format!("encode failed: {err:#}")))?;
            let decoded = VersionedAttestation::from_bytes(&encoded)
                .map_err(|err| TestCaseError::fail(format!("decode failed: {err:#}")))?;
            prop_assert_eq!(
                was_v0,
                matches!(decoded, VersionedAttestation::V0 { .. }),
                "the first-byte sniff picked the other wire form"
            );
            Ok(())
        },
    );
}
