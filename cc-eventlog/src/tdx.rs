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

    fn acpi_data_event(digest_byte: u8) -> TdxEvent {
        TdxEvent {
            imr: 0,
            event_type: TDX_ACPI_DATA_EVENT_TYPE,
            digest: vec![digest_byte; 48],
            event: String::new(),
            event_payload: TDX_ACPI_DATA_EVENT_PAYLOAD.to_vec(),
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
}
