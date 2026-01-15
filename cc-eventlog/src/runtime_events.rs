// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use fs_err as fs;
use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_human_bytes::base64;
use std::io::Write;

use ez_hash::{Hasher, Sha256, Sha384};

/// The event type for dstack runtime events.
/// This code is not defined in the TCG specification.
/// See https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
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
}

impl RuntimeEvent {
    pub fn new(event: String, payload: Vec<u8>) -> Self {
        Self { event, payload }
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

        let mut logfile = fs::OpenOptions::new()
            .append(true)
            .create(true)
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
    pub fn digest<H: Hasher>(&self) -> H::Output {
        H::hash([
            &DSTACK_RUNTIME_EVENT_TYPE.to_ne_bytes()[..],
            b":",
            self.event.as_bytes(),
            b":",
            &self.payload,
        ])
    }

    pub fn cc_event_type(&self) -> u32 {
        DSTACK_RUNTIME_EVENT_TYPE
    }
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
