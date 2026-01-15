// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
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
/// As for RTMR3, the digest extended is calculated as `sha384(event_type.to_ne_bytes() || b":" || event || b":" || event_payload)`.
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
}

impl TdxEvent {
    pub fn new(imr: u32, event_type: u32, event: String, event_payload: Vec<u8>) -> Self {
        Self {
            imr,
            event_type,
            digest: vec![],
            event,
            event_payload,
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
            }
        } else {
            Self {
                imr: self.imr,
                event_type: self.event_type,
                digest: self.digest.clone(),
                event: self.event.clone(),
                event_payload: Vec::new(),
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
        self.is_runtime_event().then_some(RuntimeEvent {
            event: self.event.clone(),
            payload: self.event_payload.clone(),
        })
    }
}

impl From<RuntimeEvent> for TdxEvent {
    fn from(value: RuntimeEvent) -> Self {
        TdxEvent {
            imr: 3,
            event_type: DSTACK_RUNTIME_EVENT_TYPE,
            digest: value.sha384_digest().to_vec(),
            event: value.event,
            event_payload: value.payload,
        }
    }
}

/// Read both boottime and runtime event logs.
pub fn read_event_log() -> Result<Vec<TdxEvent>> {
    let mut event_logs = TcgEventLog::decode_from_ccel_file()?.to_cc_event_log()?;
    event_logs.extend(RuntimeEvent::read_all()?.into_iter().map(Into::into));
    Ok(event_logs)
}
