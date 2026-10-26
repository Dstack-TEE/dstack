// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use dstack_types::EventLogVersion;
use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha384 as Sha384Digest};

use crate::{
    runtime_events::{RuntimeEvent, DSTACK_RUNTIME_EVENT_TYPE},
    tcg::TcgEventLog,
};

pub const TDX_ACPI_DATA_EVENT_TYPE: u32 = 10;
pub const TDX_ACPI_DATA_EVENT_PAYLOAD: &[u8] = b"ACPI DATA";
pub const TDX_ACPI_LOADER_EVENT: &str = "acpi-loader";
pub const TDX_ACPI_RSDP_EVENT: &str = "acpi-rsdp";
pub const TDX_ACPI_TABLES_EVENT: &str = "acpi-tables";
pub const TDX_ACPI_DATA_EVENT_NAMES: [&str; 3] = [
    TDX_ACPI_LOADER_EVENT,
    TDX_ACPI_RSDP_EVENT,
    TDX_ACPI_TABLES_EVENT,
];

/// This is the TDX event log format that is used to store the event log in the TDX guest.
/// It is a simplified version of the TCG event log format, containing only a single digest
/// and the raw event data. The IMR index is zero-based, unlike the TCG event log format
/// which is one-based.
///
/// For dstack runtime events (`event_type == DSTACK_RUNTIME_EVENT_TYPE`), the digest is:
/// - V1: `sha384(event_type_le || ":" || event || ":" || payload)`
/// - V2: `sha384(canonical_json({"name":"...","type":134217729,"payload":"hex..."}))`
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
pub struct TdxEvent {
    /// IMR index, starts from 0
    pub imr: u32,
    /// Event type
    pub event_type: u32,
    /// Digest
    #[serde(with = "serde_human_bytes", default)]
    pub digest: Vec<u8>,
    /// Event name
    pub event: String,
    /// Event payload
    #[serde(with = "serde_human_bytes")]
    pub event_payload: Vec<u8>,
    /// Event log version (for dstack runtime events).
    /// Skipped by scale codec for binary compat with legacy attestations
    /// (which only ever contain V1 events).
    /// Serde skips serialization when V1 so existing JSON outputs stay clean.
    #[serde(default, skip_serializing_if = "EventLogVersion::is_v1")]
    #[codec(skip)]
    pub version: EventLogVersion,

    /// Optional digest pre-image, hex-encoded.
    ///
    /// The exact bytes hashed to produce `digest`. V2 events exposed through
    /// quote and attestation APIs always include it, allowing relying parties
    /// to verify `sha384(hex_decode(preimage)) == digest`.
    /// Never included in scale encoding (derivable from other fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[codec(skip)]
    pub preimage: Option<String>,
}

impl TdxEvent {
    pub fn new(imr: u32, event_type: u32, event: String, event_payload: Vec<u8>) -> Self {
        Self {
            imr,
            event_type,
            digest: vec![],
            event,
            event_payload,
            version: EventLogVersion::default(),
            preimage: None,
        }
    }

    /// Create a version of this event with payload stripped (for size reduction).
    /// Only call this on events where can_strip_payload() returns true.
    pub fn stripped(&self) -> Self {
        if self.is_runtime_event() {
            Self {
                imr: self.imr,
                event_type: self.event_type,
                digest: self.digest.clone(),
                event: self.event.clone(),
                event_payload: self.event_payload.clone(),
                version: self.version,
                preimage: self.preimage.clone(),
            }
        } else {
            Self {
                imr: self.imr,
                event_type: self.event_type,
                digest: self.digest.clone(),
                event: self.event.clone(),
                event_payload: Vec::new(),
                version: self.version,
                preimage: self.preimage.clone(),
            }
        }
    }

    /// Populate `preimage` with the digest pre-image.
    ///
    /// For runtime events, this is the byte sequence defined by V1/V2 digest algorithms.
    /// For boot-time TCG events, the pre-image is inherent in the original log format
    /// and not reconstructable from this struct, so `preimage` stays `None`.
    pub fn fill_preimage(&mut self) {
        if self.preimage.is_some() {
            return;
        }
        if let Some(runtime_event) = self.to_runtime_event() {
            self.preimage = Some(hex::encode(runtime_event.preimage()));
        }
    }

    pub fn digest(&self) -> Vec<u8> {
        if let Some(runtime_event) = self.to_runtime_event() {
            return runtime_event.sha384_digest().to_vec();
        }
        self.digest.clone()
    }

    pub fn is_runtime_event(&self) -> bool {
        self.event_type == DSTACK_RUNTIME_EVENT_TYPE
    }

    pub fn to_runtime_event(&self) -> Option<RuntimeEvent> {
        if !self.is_runtime_event() {
            return None;
        }
        Some(RuntimeEvent {
            event: self.event.clone(),
            payload: self.event_payload.clone(),
            version: self.version,
        })
    }
}

impl From<RuntimeEvent> for TdxEvent {
    fn from(value: RuntimeEvent) -> Self {
        let event_type = value.cc_event_type();
        let version = value.version;
        let digest = value.sha384_digest().to_vec();
        TdxEvent {
            imr: 3,
            event_type,
            digest,
            event: value.event,
            event_payload: value.payload,
            version,
            preimage: None,
        }
    }
}

/// Populate digest preimages for all V2 runtime events.
pub fn fill_v2_preimages(events: &mut [TdxEvent]) {
    for event in events {
        if matches!(event.version, EventLogVersion::V2) {
            event.fill_preimage();
        }
    }
}

/// Validate the externally supplied digest preimage of every V2 runtime event.
///
/// The preimage must be present, valid hex, hash to the advertised digest, and
/// equal the canonical representation reconstructed from the public event
/// fields. This binds RTMR replay and displayed fields to the same bytes.
pub fn validate_v2_preimages(events: &[TdxEvent]) -> Result<()> {
    for (index, event) in events.iter().enumerate() {
        if !event.is_runtime_event() || !matches!(event.version, EventLogVersion::V2) {
            continue;
        }
        let supplied_hex = event
            .preimage
            .as_deref()
            .with_context(|| format!("V2 runtime event {index} is missing its digest preimage"))?;
        let supplied = hex::decode(supplied_hex)
            .with_context(|| format!("V2 runtime event {index} has a malformed digest preimage"))?;
        let advertised = Sha384Digest::digest(&supplied);
        if advertised.as_slice() != event.digest.as_slice() {
            bail!("V2 runtime event {index} digest does not match its preimage");
        }
        let Some(runtime_event) = event.to_runtime_event() else {
            continue;
        };
        let canonical = runtime_event.preimage();
        if supplied != canonical {
            bail!("V2 runtime event {index} preimage is not the canonical event representation");
        }
    }
    Ok(())
}

pub fn is_tdx_acpi_data_event(event: &TdxEvent) -> bool {
    event.imr == 0
        && event.event_type == TDX_ACPI_DATA_EVENT_TYPE
        && event.event_payload == TDX_ACPI_DATA_EVENT_PAYLOAD
}

/// Give dstack's three Pre202505 OVMF ACPI DATA RTMR0 events stable semantic
/// names. The firmware event payload is the same "ACPI DATA" marker for all
/// three entries, so the guest labels them before exposing the event log.
pub fn label_tdx_acpi_data_events(event_logs: &mut [TdxEvent]) {
    for (acpi_idx, event) in event_logs
        .iter_mut()
        .filter(|event| is_tdx_acpi_data_event(event))
        .enumerate()
    {
        if let Some(name) = TDX_ACPI_DATA_EVENT_NAMES.get(acpi_idx) {
            event.event = (*name).to_string();
        }
    }
}

/// Decode a raw CCEL byte stream into dstack's TDX event representation.
pub fn decode_ccel(data: &[u8]) -> Result<Vec<TdxEvent>> {
    let mut input = data;
    let mut event_logs = TcgEventLog::decode(&mut input)?.to_cc_event_log()?;
    label_tdx_acpi_data_events(&mut event_logs);
    Ok(event_logs)
}

/// Read both boottime and runtime event logs.
pub fn read_event_log() -> Result<Vec<TdxEvent>> {
    let mut event_logs = TcgEventLog::decode_from_ccel_file()?.to_cc_event_log()?;
    label_tdx_acpi_data_events(&mut event_logs);
    event_logs.extend(RuntimeEvent::read_all()?.into_iter().map(Into::into));
    Ok(event_logs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ez_hash::{Hasher, Sha384};
    use sha2::Sha384 as Sha384Hasher;

    fn acpi_data_event(digest_byte: u8) -> TdxEvent {
        TdxEvent {
            imr: 0,
            event_type: TDX_ACPI_DATA_EVENT_TYPE,
            digest: vec![digest_byte; 48],
            event: String::new(),
            event_payload: TDX_ACPI_DATA_EVENT_PAYLOAD.to_vec(),
            version: EventLogVersion::V1,
            preimage: None,
        }
    }

    #[test]
    fn labels_pre202505_acpi_data_events_in_order() {
        let mut events = vec![
            TdxEvent::new(0, 4, String::new(), vec![0]),
            acpi_data_event(1),
            acpi_data_event(2),
            acpi_data_event(3),
            TdxEvent::new(3, DSTACK_RUNTIME_EVENT_TYPE, "app-id".into(), vec![4]),
        ];

        label_tdx_acpi_data_events(&mut events);

        let names = events
            .iter()
            .filter(|event| is_tdx_acpi_data_event(event))
            .map(|event| event.event.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, TDX_ACPI_DATA_EVENT_NAMES);
        assert_eq!(events[0].event, "");
        assert_eq!(events[4].event, "app-id");
    }

    #[test]
    fn decodes_the_bundled_ccel() {
        let events = decode_ccel(include_bytes!("../samples/ccel.bin")).unwrap();
        assert!(!events.is_empty());
        assert!(events.iter().all(|event| event.imr <= 3));
        assert!(events.iter().all(|event| event.digest().len() == 48));
    }

    #[test]
    fn fill_preimage_v1() {
        let runtime = RuntimeEvent::new(
            "compose-hash".to_string(),
            vec![0xde, 0xad],
            EventLogVersion::V1,
        );
        let mut tdx: TdxEvent = runtime.into();
        assert_eq!(tdx.preimage, None);
        tdx.fill_preimage();
        let input_hex = tdx.preimage.as_ref().expect("preimage populated");
        let input = hex::decode(input_hex).unwrap();
        // Hashing the preimage must reproduce the event digest
        let actual = Sha384Hasher::digest(&input);
        assert_eq!(actual.as_slice(), &tdx.digest);
    }

    #[test]
    fn fill_preimage_v2_is_canonical_json() {
        let runtime = RuntimeEvent::new(
            "compose-hash".to_string(),
            vec![0xab, 0xcd],
            EventLogVersion::V2,
        );
        let mut tdx: TdxEvent = runtime.into();
        tdx.fill_preimage();
        let input_hex = tdx.preimage.as_ref().expect("preimage populated");
        let input = hex::decode(input_hex).unwrap();
        let input_str = std::str::from_utf8(&input).unwrap();
        // V2 preimage is the canonical JSON (version is carried out-of-band)
        assert!(input_str.contains(r#""name":"compose-hash""#));
        assert!(input_str.contains(r#""type":134217729"#));
        assert!(input_str.contains(r#""payload":"abcd""#));
        assert!(!input_str.contains(r#""version""#));
        // And hashing it reproduces the digest
        let actual = Sha384::hash([input.as_slice()]);
        assert_eq!(actual.as_slice(), &tdx.digest);
    }

    #[test]
    fn stripped_v2_runtime_event_preserves_digest_binding() {
        let mut event = v2_event();
        event.fill_preimage();

        let stripped = event.stripped();

        assert_eq!(stripped.digest, event.digest);
        validate_v2_preimages(&[stripped]).expect("stripped V2 event remains verifiable");
    }

    #[test]
    fn fill_preimage_skips_non_runtime_events() {
        let mut boot_event = TdxEvent::new(0, 0x1, "EV_POST_CODE".to_string(), vec![1, 2, 3]);
        boot_event.fill_preimage();
        assert_eq!(boot_event.preimage, None);
    }

    #[test]
    fn preimage_not_serialized_by_scale() {
        use scale::{Decode, Encode};
        let runtime = RuntimeEvent::new("test".to_string(), vec![1, 2], EventLogVersion::V2);
        let mut tdx: TdxEvent = runtime.into();
        tdx.fill_preimage();
        assert!(tdx.preimage.is_some());
        let encoded = tdx.encode();
        let decoded = TdxEvent::decode(&mut &encoded[..]).unwrap();
        // preimage is codec(skip) so it's None after round-trip
        assert_eq!(decoded.preimage, None);
    }

    #[test]
    fn preimage_skipped_from_json_when_none() {
        let runtime = RuntimeEvent::new("test".to_string(), vec![1], EventLogVersion::V1);
        let tdx: TdxEvent = runtime.into();
        let json = serde_json::to_string(&tdx).unwrap();
        assert!(!json.contains("preimage"));
    }

    fn v2_event() -> TdxEvent {
        let mut event = TdxEvent::from(RuntimeEvent::new(
            "app-id".into(),
            b"fixture".to_vec(),
            EventLogVersion::V2,
        ));
        event.fill_preimage();
        event
    }

    #[test]
    fn validates_v2_digest_preimage_before_use() {
        validate_v2_preimages(&[v2_event()]).expect("valid V2 preimage");
    }

    #[test]
    fn rejects_missing_or_malformed_v2_preimage() {
        let mut missing = v2_event();
        missing.preimage = None;
        assert!(validate_v2_preimages(&[missing]).is_err());

        let mut malformed = v2_event();
        malformed.preimage = Some("not-hex".into());
        assert!(validate_v2_preimages(&[malformed]).is_err());
    }

    #[test]
    fn rejects_v2_preimage_digest_mismatch() {
        let mut event = v2_event();
        event.digest[0] ^= 1;
        assert!(validate_v2_preimages(&[event]).is_err());
    }

    #[test]
    fn rejects_noncanonical_v2_preimage_with_matching_digest() {
        let mut event = v2_event();
        let supplied = br#"{"type":134217729,"name":"app-id","payload":"66697874757265"}"#;
        event.preimage = Some(hex::encode(supplied));
        event.digest = Sha384Hasher::digest(supplied).to_vec();
        assert!(validate_v2_preimages(&[event]).is_err());
    }
}
