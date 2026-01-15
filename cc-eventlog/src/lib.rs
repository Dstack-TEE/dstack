// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

pub use runtime_events::{replay_events, RuntimeEvent};
pub use tdx::TdxEvent;

mod codecs;
mod runtime_events;
mod tcg;
pub mod tdx;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ccel() {
        let boot_time_data = include_bytes!("../samples/ccel.bin");
        let event_logs = tcg::TcgEventLog::decode(&mut boot_time_data.as_slice()).unwrap();
        insta::assert_debug_snapshot!(&event_logs.event_logs);
        let tdx_event_logs = event_logs.to_cc_event_log().unwrap();
        let json = serde_json::to_string_pretty(&tdx_event_logs).unwrap();
        insta::assert_snapshot!(json);
    }
}
