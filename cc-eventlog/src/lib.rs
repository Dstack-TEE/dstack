// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::codecs::VecOf;
use anyhow::{Context, Result};
use scale::Decode;
use serde::{Deserialize, Serialize};
use tcg::{TcgDigest, TcgEfiSpecIdEvent};

mod codecs;
mod tcg;

/// The path to the userspace TDX event log file.
pub const RUNTIME_EVENT_LOG_FILE: &str = "/run/log/tdx_mr3/tdx_events.log";
/// The path to boottime ccel file.
const CCEL_FILE: &str = "/sys/firmware/acpi/tables/data/CCEL";

/// This is the common struct for tcg event logs to be delivered in different formats.
/// Currently TCG supports several event log formats defined in TCG_PCClient Spec,
/// Canonical Eventlog Spec, etc.
/// This struct provides the functionality to convey event logs in different format
/// according to request.
#[derive(Clone, scale::Decode)]
pub struct TcgEventLog {
    /// IMR index, starts from 1
    pub imr_index: u32,
    /// Event type
    pub event_type: u32,
    /// List of digests
    pub digests: VecOf<u32, TcgDigest>,
    /// Raw event data
    pub event: VecOf<u32, u8>,
}

/// This is the TDX event log format that is used to store the event log in the TDX guest.
/// It is a simplified version of the TCG event log format, containing only a single digest
/// and the raw event data. The IMR index is zero-based, unlike the TCG event log format
/// which is one-based.
///
/// As for RTMR3, the digest extended is calculated as `sha384(event_type.to_ne_bytes() || b":" || event || b":" || event_payload)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TdxEventLog {
    /// IMR index, starts from 0
    pub imr: u32,
    /// Event type
    pub event_type: u32,
    /// Digest
    #[serde(with = "serde_human_bytes")]
    pub digest: [u8; 48],
    /// Event name
    pub event: String,
    /// Event payload
    #[serde(with = "serde_human_bytes")]
    pub event_payload: Vec<u8>,
}

fn event_digest(ty: u32, event: &str, payload: &[u8]) -> [u8; 48] {
    use sha2::Digest;
    let mut hasher = sha2::Sha384::new();
    hasher.update(ty.to_ne_bytes());
    hasher.update(b":");
    hasher.update(event.as_bytes());
    hasher.update(b":");
    hasher.update(payload);
    hasher.finalize().into()
}

impl TdxEventLog {
    pub fn new(imr: u32, event_type: u32, event: String, event_payload: Vec<u8>) -> Self {
        let digest = event_digest(event_type, &event, &event_payload);
        Self {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        }
    }

    pub fn new_str(imr: u32, event_type: u32, event: &str, event_payload: &str) -> Self {
        Self::new(
            imr,
            event_type,
            event.to_string(),
            event_payload.as_bytes().to_vec(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.imr != 3 {
            // TODO: validate other imrs
            return Ok(());
        }
        let digest = event_digest(self.event_type, &self.event, &self.event_payload);
        if digest != self.digest {
            return Err(anyhow::anyhow!("invalid digest"));
        }
        Ok(())
    }
}

impl TryFrom<TcgEventLog> for TdxEventLog {
    type Error = anyhow::Error;

    fn try_from(value: TcgEventLog) -> Result<Self> {
        if value.digests.len() != 1 {
            return Err(anyhow::anyhow!(
                "expected 1 digest, got {}",
                value.digests.len()
            ));
        }
        let digest = value
            .digests
            .into_inner()
            .into_iter()
            .next()
            .context("digest not found")?
            .hash
            .try_into()
            .ok()
            .context("invalid digest size")?;
        // TCG event logs use 1-based IMR indices (1-4), while TDX RTMRs are 0-based (0-3).
        // Standard conversion: TCG IMR 1 → RTMR 0, TCG IMR 2 → RTMR 1, etc.
        //
        // However, some cloud platforms (notably GCP) may include events with IMR index 0
        // in their CCEL tables. Rather than failing on these, we pass them through as RTMR 0.
        // This maintains compatibility with both standard TCG format and GCP's implementation.
        let imr = value.imr_index.saturating_sub(1);
        Ok(TdxEventLog {
            imr,
            event_type: value.event_type,
            digest,
            event: Default::default(),
            event_payload: value.event.into(),
        })
    }
}

impl core::fmt::Debug for TcgEventLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcgEventLog")
            .field("imr_index", &self.imr_index)
            .field("event_type", &self.event_type)
            .field(
                "digests",
                &self
                    .digests
                    .iter()
                    .map(|d| hex::encode(&d.hash))
                    .collect::<Vec<_>>(),
            )
            .field("event", &hex::encode(&self.event))
            .finish()
    }
}

const fn alg_id_to_digest_size(alg_id: u16) -> Option<u8> {
    use tcg::*;
    match alg_id {
        TPM_ALG_SHA1 => Some(20),
        TPM_ALG_SHA256 => Some(32),
        TPM_ALG_SHA384 => Some(48),
        TPM_ALG_SHA512 => Some(64),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct EventLogs {
    pub spec_id_header_event: TcgEfiSpecIdEvent,
    pub event_logs: Vec<TcgEventLog>,
}

impl scale::Decode for TcgDigest {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let algo_id = u16::decode(input)?;
        let digest_size =
            alg_id_to_digest_size(algo_id).ok_or(scale::Error::from("Unsupported algorithm ID"))?;
        let mut digest_data = vec![0; digest_size as usize];
        input
            .read(&mut digest_data)
            .map_err(|_| scale::Error::from("failed to read digest_data"))?;
        Ok(TcgDigest {
            algo_id,
            hash: digest_data,
        })
    }
}

impl EventLogs {
    pub fn decode(input: &mut &[u8]) -> Result<Self> {
        let (_spec_id_header, spec_id_header_event) =
            parse_spec_id_event_log(input).context("Failed to parse spec id event")?;
        let mut event_logs = vec![];
        loop {
            // A tmp head_buffer is used to peek the imr and event type
            let head_buffer = &mut &input[..];
            let imr = u32::decode(head_buffer).context("failed to decode imr")?;
            if imr == 0xFFFFFFFF {
                break;
            }
            let event_log = TcgEventLog::decode(input).context("Failed to parse event log")?;
            event_logs.push(event_log);
        }
        Ok(EventLogs {
            spec_id_header_event,
            event_logs,
        })
    }

    pub fn decode_from_ccel_file() -> Result<Self> {
        let data = fs_err::read(CCEL_FILE).context("Failed to read CCEL")?;
        Self::decode(&mut data.as_slice())
    }

    pub fn into_tdx_event_logs(self) -> Result<Vec<TdxEventLog>> {
        self.event_logs
            .into_iter()
            .map(TdxEventLog::try_from)
            .collect()
    }

    pub fn to_tdx_event_logs(&self) -> Result<Vec<TdxEventLog>> {
        self.event_logs
            .iter()
            .cloned()
            .map(TdxEventLog::try_from)
            .collect()
    }
}

fn parse_spec_id_event_log<I: scale::Input>(
    input: &mut I,
) -> Result<(TcgEventLog, TcgEfiSpecIdEvent)> {
    #[derive(Decode)]
    struct Header {
        imr_index: u32,
        header_event_type: u32,
        digest_hash: [u8; 20],
        header_event: VecOf<u32, u8>,
    }

    let decoded_header = Header::decode(input).context("failed to decode log_item")?;
    // Parse EFI Spec Id Event structure
    let input = &mut decoded_header.header_event.as_slice();
    let spec_id_event =
        TcgEfiSpecIdEvent::decode(input).context("failed to decode TcgEfiSpecIdEvent")?;

    let digests = vec![TcgDigest {
        algo_id: tcg::TPM_ALG_ERROR,
        hash: decoded_header.digest_hash.to_vec(),
    }];
    let spec_id_header = TcgEventLog {
        imr_index: decoded_header.imr_index,
        event_type: decoded_header.header_event_type,
        digests: (digests.len() as u32, digests).into(),
        event: decoded_header.header_event,
    };
    Ok((spec_id_header, spec_id_event))
}

fn read_runtime_event_logs() -> Result<Vec<TdxEventLog>> {
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
        let event_log =
            serde_json::from_str::<TdxEventLog>(line).context("Failed to decode user event log")?;
        event_logs.push(event_log);
    }
    Ok(event_logs)
}

/// Read both boottime and runtime event logs.
pub fn read_event_logs() -> Result<Vec<TdxEventLog>> {
    let mut event_logs = EventLogs::decode_from_ccel_file()?.to_tdx_event_logs()?;
    event_logs.extend(read_runtime_event_logs()?);
    Ok(event_logs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ccel() {
        let boot_time_data = include_bytes!("../samples/ccel.bin");
        let event_logs = EventLogs::decode(&mut boot_time_data.as_slice()).unwrap();
        insta::assert_debug_snapshot!(&event_logs.event_logs);
        let tdx_event_logs = event_logs.to_tdx_event_logs().unwrap();
        let json = serde_json::to_string_pretty(&tdx_event_logs).unwrap();
        insta::assert_snapshot!(json);
    }
}
