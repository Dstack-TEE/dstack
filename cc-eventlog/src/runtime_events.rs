// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use dstack_types::EventLogVersion;
use fs_err as fs;
use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_human_bytes::base64;
use std::io::Write;

use ez_hash::{Hasher, Sha256, Sha384};

/// The event type for dstack runtime events.
/// This code is not defined in the TCG specification.
/// See https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
///
/// V1 and V2 use the same event type; the digest format is distinguished by
/// `EventLogVersion` (carried on `RuntimeEvent`/`TdxEvent` or inferred from
/// the v2 canonical JSON content).
pub const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x08000001;
/// The path to the userspace TDX event log file.
pub const RUNTIME_EVENT_LOG_FILE: &str = "/run/log/dstack/runtime_events.log";

/// Abstraction of cross-platform runtime events.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
pub struct RuntimeEvent {
    /// Event name
    pub event: String,
    /// Event payload
    #[serde(with = "base64")]
    pub payload: Vec<u8>,
    /// Event log version
    #[serde(default)]
    #[codec(skip)]
    pub version: EventLogVersion,
}

impl RuntimeEvent {
    pub fn new(event: String, payload: Vec<u8>, version: EventLogVersion) -> Self {
        Self {
            event,
            payload,
            version,
        }
    }

    pub fn read_all() -> Result<Vec<RuntimeEvent>> {
        let data = match fs_err::read_to_string(RUNTIME_EVENT_LOG_FILE) {
            Ok(data) => data,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Ok(vec![]);
                }
                return Err(e).context("Failed to read user event log");
            }
        };
        let mut event_logs = vec![];
        for line in data.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let event_log = serde_json::from_str::<RuntimeEvent>(line)
                .context("Failed to decode user event log")?;
            event_logs.push(event_log);
        }
        Ok(event_logs)
    }

    pub fn emit(&self) -> Result<()> {
        let logline = serde_json::to_string(self).context("failed to serialize event log")?;

        let logfile_path = std::path::Path::new(RUNTIME_EVENT_LOG_FILE);
        let logfile_dir = logfile_path
            .parent()
            .context("failed to get event log directory")?;
        fs::create_dir_all(logfile_dir).context("failed to create event log directory")?;

        let mut options = fs::OpenOptions::new();
        options.append(true).create(true);

        // Restrict runtime event log visibility and writability to the owner (root).
        // This avoids other processes in the CVM tampering with or reading the log.
        #[cfg(unix)]
        {
            use fs_err::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut logfile = options
            .open(logfile_path)
            .context("failed to open event log file")?;

        logfile
            .write_all(logline.as_bytes())
            .context("failed to write to event log file")?;
        logfile
            .write_all(b"\n")
            .context("failed to write to event log file")?;
        Ok(())
    }

    pub fn sha384_digest(&self) -> [u8; 48] {
        self.digest::<Sha384>()
    }

    pub fn sha256_digest(&self) -> [u8; 32] {
        self.digest::<Sha256>()
    }

    /// Compute the digest of the event.
    ///
    /// - V1: `SHA(event_type_le || ":" || event_name || ":" || payload)`
    /// - V2: `SHA(canonical_json({"event":"...","event_type":134217729,"payload":"hex...","version":2}))`
    pub fn digest<H: Hasher>(&self) -> H::Output {
        match self.version {
            EventLogVersion::V1 => H::hash([
                &DSTACK_RUNTIME_EVENT_TYPE.to_ne_bytes()[..],
                b":",
                self.event.as_bytes(),
                b":",
                &self.payload,
            ]),
            EventLogVersion::V2 => {
                let canonical = canonical_event_json_v2(&self.event, &self.payload);
                H::hash([canonical.as_bytes()])
            }
        }
    }

    /// The event type used when extending RTMR. Always `DSTACK_RUNTIME_EVENT_TYPE`.
    /// Version is distinguished via `EventLogVersion`, not the event type.
    pub fn cc_event_type(&self) -> u32 {
        DSTACK_RUNTIME_EVENT_TYPE
    }
}

/// Construct the JCS (RFC 8785) canonical JSON used as the v2 digest input.
///
/// The JSON includes an explicit `version: 2` field so the content is
/// self-describing for relying parties that don't know dstack's event schema.
/// Keys and number/string formatting are handled by `serde_jcs` per RFC 8785.
pub fn canonical_event_json_v2(event: &str, payload: &[u8]) -> String {
    let obj = serde_json::json!({
        "event": event,
        "event_type": DSTACK_RUNTIME_EVENT_TYPE,
        "payload": hex::encode(payload),
        "version": 2,
    });
    serde_jcs::to_string(&obj).unwrap_or_default()
}

/// Replay event logs
pub fn replay_events<H: Hasher>(eventlog: &[RuntimeEvent], to_event: Option<&str>) -> H::Output {
    let mut mr = H::zeros();
    for event in eventlog.iter() {
        mr = H::hash((mr, event.digest::<H>()));
        if let Some(to_event) = to_event {
            if event.event == to_event {
                break;
            }
        }
    }
    mr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_digest_unchanged() {
        let event = RuntimeEvent::new(
            "app-id".to_string(),
            vec![0xde, 0xad, 0xbe, 0xef],
            EventLogVersion::V1,
        );
        let digest = event.digest::<Sha384>();
        let expected = Sha384::hash([
            &DSTACK_RUNTIME_EVENT_TYPE.to_ne_bytes()[..],
            b":",
            b"app-id",
            b":",
            &[0xde, 0xad, 0xbe, 0xef],
        ]);
        assert_eq!(digest, expected, "v1 digest must be backward compatible");
    }

    #[test]
    fn v2_digest_is_canonical_json_hash() {
        let event = RuntimeEvent::new(
            "compose-hash".to_string(),
            vec![0xab, 0xcd],
            EventLogVersion::V2,
        );
        let canonical = canonical_event_json_v2(&event.event, &event.payload);
        assert_eq!(
            canonical,
            r#"{"event":"compose-hash","event_type":134217729,"payload":"abcd","version":2}"#
        );
        let digest = event.digest::<Sha384>();
        let expected = Sha384::hash([canonical.as_bytes()]);
        assert_eq!(digest, expected);
    }

    #[test]
    fn v2_digest_differs_from_v1() {
        let v1 = RuntimeEvent::new("test".to_string(), vec![1, 2, 3], EventLogVersion::V1);
        let v2 = RuntimeEvent::new("test".to_string(), vec![1, 2, 3], EventLogVersion::V2);
        assert_ne!(
            v1.digest::<Sha384>(),
            v2.digest::<Sha384>(),
            "v1 and v2 digests must differ"
        );
    }

    #[test]
    fn v1_event_type() {
        let event = RuntimeEvent::new("test".to_string(), vec![], EventLogVersion::V1);
        assert_eq!(event.cc_event_type(), DSTACK_RUNTIME_EVENT_TYPE);
    }

    #[test]
    fn v2_event_type() {
        // v2 uses the same event_type as v1 — version is carried separately
        let event = RuntimeEvent::new("test".to_string(), vec![], EventLogVersion::V2);
        assert_eq!(event.cc_event_type(), DSTACK_RUNTIME_EVENT_TYPE);
    }

    #[test]
    fn deserialize_v1_without_version_field() {
        let json = r#"{"event":"app-id","payload":"AQID"}"#;
        let event: RuntimeEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.version, EventLogVersion::V1);
        assert_eq!(event.cc_event_type(), DSTACK_RUNTIME_EVENT_TYPE);
    }

    #[test]
    fn serde_roundtrip_preserves_version() {
        let v2 = RuntimeEvent::new("test".to_string(), vec![1], EventLogVersion::V2);
        let json = serde_json::to_string(&v2).unwrap();
        assert!(json.contains(r#""version":2"#), "v2 must serialize version");
        let decoded: RuntimeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.version, EventLogVersion::V2);
    }

    #[test]
    fn deserialize_without_version_defaults_to_v1() {
        let json = r#"{"event":"test","payload":"AQ=="}"#;
        let decoded: RuntimeEvent = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.version, EventLogVersion::V1);
    }

    #[test]
    fn canonical_json_escapes_special_chars() {
        let canonical = canonical_event_json_v2("event\"with\\special\nchars", &[0xff]);
        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        assert_eq!(
            parsed["event"].as_str().unwrap(),
            "event\"with\\special\nchars"
        );
    }

    #[test]
    fn mixed_v1_v2_replay() {
        let events = vec![
            RuntimeEvent::new("app-id".to_string(), vec![1, 2], EventLogVersion::V1),
            RuntimeEvent::new("compose-hash".to_string(), vec![3, 4], EventLogVersion::V2),
            RuntimeEvent::new("instance-id".to_string(), vec![5, 6], EventLogVersion::V1),
        ];
        let mr = replay_events::<Sha384>(&events, None);
        // Replay manually to verify
        let mut expected = Sha384::zeros();
        expected = Sha384::hash((expected, events[0].digest::<Sha384>()));
        expected = Sha384::hash((expected, events[1].digest::<Sha384>()));
        expected = Sha384::hash((expected, events[2].digest::<Sha384>()));
        assert_eq!(mr, expected, "mixed v1/v2 replay must work correctly");
    }

    #[test]
    fn scale_roundtrip_preserves_event_data() {
        use scale::{Decode, Encode};
        // V1 event
        let v1 = RuntimeEvent::new("test".to_string(), vec![1, 2, 3], EventLogVersion::V1);
        let encoded = v1.encode();
        let decoded = RuntimeEvent::decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.event, v1.event);
        assert_eq!(decoded.payload, v1.payload);
        // version is #[codec(skip)] so it defaults to V1 on decode
        assert_eq!(decoded.version, EventLogVersion::V1);
    }

    #[test]
    fn scale_decode_old_format_without_version() {
        use scale::{Decode, Encode};
        // Encode a current RuntimeEvent (version is skipped by codec),
        // then decode — simulates reading data from before version was added
        let original =
            RuntimeEvent::new("app-id".to_string(), vec![0xaa, 0xbb], EventLogVersion::V2);
        let encoded = original.encode();
        let decoded = RuntimeEvent::decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.event, "app-id");
        assert_eq!(decoded.payload, vec![0xaa, 0xbb]);
        // version is #[codec(skip)] so always decodes as default (V1)
        assert_eq!(decoded.version, EventLogVersion::V1);
    }
}
