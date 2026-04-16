// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use dstack_types::EventLogVersion;
use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    runtime_events::{RuntimeEvent, DSTACK_RUNTIME_EVENT_TYPE},
    tcg::TcgEventLog,
};

/// This is the TDX event log format that is used to store the event log in the TDX guest.
/// It is a simplified version of the TCG event log format, containing only a single digest
/// and the raw event data. The IMR index is zero-based, unlike the TCG event log format
/// which is one-based.
///
/// For dstack runtime events (`event_type == DSTACK_RUNTIME_EVENT_TYPE`), the digest is:
/// - V1: `sha384(event_type_le || ":" || event || ":" || payload)`
/// - V2: `sha384(canonical_json({"name":"...","type":134217729,"content":"hex..."}))`
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
    #[serde(default, skip_serializing_if = "is_v1")]
    #[codec(skip)]
    pub version: EventLogVersion,

    /// Optional digest pre-image, hex-encoded.
    ///
    /// The exact bytes hashed to produce `digest`. Only populated when
    /// explicitly requested (e.g., via RPC opt-in) so that relying parties can
    /// verify the digest computation or inspect v2 JSON content without
    /// knowing the dstack schema.
    /// Never included in scale encoding (derivable from other fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[codec(skip)]
    pub hash_input: Option<String>,
}

fn is_v1(v: &EventLogVersion) -> bool {
    matches!(v, EventLogVersion::V1)
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
            hash_input: None,
        }
    }

    /// Create a version of this event with payload stripped (for size reduction).
    /// Only call this on events where can_strip_payload() returns true.
    pub fn stripped(&self) -> Self {
        if self.is_runtime_event() {
            Self {
                imr: self.imr,
                event_type: self.event_type,
                digest: Vec::new(),
                event: self.event.clone(),
                event_payload: self.event_payload.clone(),
                version: self.version,
                hash_input: self.hash_input.clone(),
            }
        } else {
            Self {
                imr: self.imr,
                event_type: self.event_type,
                digest: self.digest.clone(),
                event: self.event.clone(),
                event_payload: Vec::new(),
                version: self.version,
                hash_input: self.hash_input.clone(),
            }
        }
    }

    /// Populate `hash_input` with the digest pre-image.
    ///
    /// For runtime events, this is the byte sequence defined by V1/V2 digest algorithms.
    /// For boot-time TCG events, the pre-image is inherent in the original log format
    /// and not reconstructable from this struct, so `hash_input` stays `None`.
    pub fn fill_hash_input(&mut self) {
        if let Some(runtime_event) = self.to_runtime_event() {
            self.hash_input = Some(hex::encode(runtime_event.hash_input()));
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
            hash_input: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ez_hash::{Hasher, Sha384};
    use sha2::{Digest as _, Sha384 as Sha384Hasher};

    #[test]
    fn fill_hash_input_v1() {
        let runtime = RuntimeEvent::new(
            "compose-hash".to_string(),
            vec![0xde, 0xad],
            EventLogVersion::V1,
        );
        let mut tdx: TdxEvent = runtime.into();
        assert_eq!(tdx.hash_input, None);
        tdx.fill_hash_input();
        let input_hex = tdx.hash_input.as_ref().expect("hash_input populated");
        let input = hex::decode(input_hex).unwrap();
        // Hashing the hash_input must reproduce the event digest
        let actual = Sha384Hasher::digest(&input);
        assert_eq!(actual.as_slice(), &tdx.digest);
    }

    #[test]
    fn fill_hash_input_v2_is_canonical_json() {
        let runtime = RuntimeEvent::new(
            "compose-hash".to_string(),
            vec![0xab, 0xcd],
            EventLogVersion::V2,
        );
        let mut tdx: TdxEvent = runtime.into();
        tdx.fill_hash_input();
        let input_hex = tdx.hash_input.as_ref().expect("hash_input populated");
        let input = hex::decode(input_hex).unwrap();
        let input_str = std::str::from_utf8(&input).unwrap();
        // V2 hash_input is the canonical JSON (version is carried out-of-band)
        assert!(input_str.contains(r#""name":"compose-hash""#));
        assert!(input_str.contains(r#""type":134217729"#));
        assert!(input_str.contains(r#""content":"abcd""#));
        assert!(!input_str.contains(r#""version""#));
        // And hashing it reproduces the digest
        let actual = Sha384::hash([input.as_slice()]);
        assert_eq!(actual.as_slice(), &tdx.digest);
    }

    #[test]
    fn fill_hash_input_skips_non_runtime_events() {
        let mut boot_event = TdxEvent::new(0, 0x1, "EV_POST_CODE".to_string(), vec![1, 2, 3]);
        boot_event.fill_hash_input();
        assert_eq!(boot_event.hash_input, None);
    }

    #[test]
    fn hash_input_not_serialized_by_scale() {
        use scale::{Decode, Encode};
        let runtime = RuntimeEvent::new("test".to_string(), vec![1, 2], EventLogVersion::V2);
        let mut tdx: TdxEvent = runtime.into();
        tdx.fill_hash_input();
        assert!(tdx.hash_input.is_some());
        let encoded = tdx.encode();
        let decoded = TdxEvent::decode(&mut &encoded[..]).unwrap();
        // hash_input is codec(skip) so it's None after round-trip
        assert_eq!(decoded.hash_input, None);
    }

    #[test]
    fn hash_input_skipped_from_json_when_none() {
        let runtime = RuntimeEvent::new("test".to_string(), vec![1], EventLogVersion::V1);
        let tdx: TdxEvent = runtime.into();
        let json = serde_json::to_string(&tdx).unwrap();
        assert!(!json.contains("hash_input"));
    }
}

/// Read both boottime and runtime event logs.
pub fn read_event_log() -> Result<Vec<TdxEvent>> {
    let mut event_logs = TcgEventLog::decode_from_ccel_file()?.to_cc_event_log()?;
    event_logs.extend(RuntimeEvent::read_all()?.into_iter().map(Into::into));
    Ok(event_logs)
}
