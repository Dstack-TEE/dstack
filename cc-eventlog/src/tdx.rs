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
/// - V2: `sha384(canonical_json({"event":"...","event_type":134217729,"payload":"hex...","version":2}))`
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
            }
        } else {
            Self {
                imr: self.imr,
                event_type: self.event_type,
                digest: self.digest.clone(),
                event: self.event.clone(),
                event_payload: Vec::new(),
                version: self.version,
            }
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
        }
    }
}

/// Read both boottime and runtime event logs.
pub fn read_event_log() -> Result<Vec<TdxEvent>> {
    let mut event_logs = TcgEventLog::decode_from_ccel_file()?.to_cc_event_log()?;
    event_logs.extend(RuntimeEvent::read_all()?.into_iter().map(Into::into));
    Ok(event_logs)
}
