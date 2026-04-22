// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

pub use dstack_types::EventLogVersion;
pub use runtime_events::{
    canonical_event_json_v2, replay_events, RuntimeEvent, DSTACK_RUNTIME_EVENT_TYPE,
};
pub use tdx::TdxEvent;

mod codecs;
mod runtime_events;
pub mod tcg;
pub mod tdx;

#[cfg(test)]
mod tests {
    use super::*;
    use dstack_types::EventLogVersion;
    use ez_hash::{Hasher, Sha384};
    use tdx::TdxEvent;

    #[test]
    fn parse_ccel() {
        let boot_time_data = include_bytes!("../samples/ccel.bin");
        let event_logs = tcg::TcgEventLog::decode(&mut boot_time_data.as_slice()).unwrap();
        insta::assert_debug_snapshot!(&event_logs.event_logs);
        let tdx_event_logs = event_logs.to_cc_event_log().unwrap();
        let json = serde_json::to_string_pretty(&tdx_event_logs).unwrap();
        insta::assert_snapshot!(json);
    }

    #[test]
    fn encode_runtime_events_roundtrip() {
        // Synthesize a CCEL: sample boot-time bytes + encoded runtime events.
        // Decode with the same TcgEventLog parser and verify:
        // 1. all boot-time events are preserved
        // 2. runtime events appear with the expected pcrIndex / event_type / digest
        // 3. sha384(event_data) == digest (the property we document)
        let boot_raw = include_bytes!("../samples/ccel.bin");
        let valid = tcg::ccel_content_len(boot_raw).unwrap();

        let runtime_v1: TdxEvent = RuntimeEvent::new(
            "app-id".to_string(),
            vec![0xaa, 0xbb, 0xcc],
            EventLogVersion::V1,
        )
        .into();
        let runtime_v2: TdxEvent = RuntimeEvent::new(
            "compose-hash".to_string(),
            vec![0xde, 0xad, 0xbe, 0xef],
            EventLogVersion::V2,
        )
        .into();
        let runtime_events = vec![runtime_v1.clone(), runtime_v2.clone()];

        let mut merged = boot_raw[..valid].to_vec();
        merged.extend_from_slice(&tcg::encode_runtime_events_as_tcg(&runtime_events));
        merged.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        let parsed = tcg::TcgEventLog::decode(&mut merged.as_slice()).unwrap();
        let boot_count = tcg::TcgEventLog::decode(&mut boot_raw.as_slice())
            .unwrap()
            .event_logs
            .len();
        assert_eq!(parsed.event_logs.len(), boot_count + 2);

        // Convert and verify runtime tail matches what we put in.
        let converted = parsed.to_cc_event_log().unwrap();
        let tail = &converted[converted.len() - 2..];
        for (orig, got) in runtime_events.iter().zip(tail.iter()) {
            assert_eq!(got.imr, orig.imr);
            assert_eq!(got.event_type, orig.event_type);
            assert_eq!(got.digest, orig.digest());
            // The event_payload carried in TdxEvent after TCG round-trip is the
            // hash_input bytes we stored as TCG event data.
            let runtime = orig.to_runtime_event().unwrap();
            assert_eq!(got.event_payload, runtime.hash_input());
            // Property: sha384(event_data) == digest
            let h = Sha384::hash([got.event_payload.as_slice()]);
            assert_eq!(h.as_slice(), got.digest.as_slice());
        }
    }
}
