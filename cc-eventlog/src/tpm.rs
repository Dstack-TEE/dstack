// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! TPM Event Log parsing (binary_bios_measurements format)

use crate::codecs::VecOf;
use crate::tcg::{TcgDigest, TcgEfiSpecIdEvent};
use anyhow::{Context, Result};
use scale::Decode;
use serde::{Deserialize, Serialize};

/// Simplified TPM event for PCR replay
#[derive(Clone, Debug, Serialize, Deserialize, scale::Encode, scale::Decode)]
pub struct TpmEvent {
    /// PCR index this event was extended to
    pub pcr_index: u32,
    /// SHA-256 digest of the event data
    #[serde(with = "serde_human_bytes")]
    pub digest: Vec<u8>,
}

/// TCG_PCR_EVENT2 format
///
/// See TCG PC Client Platform Firmware Profile spec section 9.2.2
#[derive(Clone, Decode)]
struct TpmRawEvent {
    pcr_index: u32,
    event_type: u32,
    digests: VecOf<u32, TcgDigest>,
    event: VecOf<u32, u8>,
}

impl core::fmt::Debug for TpmRawEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmRawEvent")
            .field("pcr_index", &self.pcr_index)
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

impl TpmRawEvent {
    fn sha256_digest(&self) -> Option<Vec<u8>> {
        self.digests
            .iter()
            .find(|d| d.algo_id == crate::tcg::TPM_ALG_SHA256)
            .map(|d| d.hash.clone())
    }

    fn is_extended_to_pcr(&self) -> bool {
        self.event_type != crate::tcg::EV_NO_ACTION
    }

    fn to_simple_event(&self) -> Option<TpmEvent> {
        if !self.is_extended_to_pcr() {
            return None;
        }
        self.sha256_digest().map(|digest| TpmEvent {
            pcr_index: self.pcr_index,
            digest,
        })
    }
}

#[derive(Clone, Debug)]
pub struct TpmEventLog {
    pub spec_id_header_event: TcgEfiSpecIdEvent,
    pub events: Vec<TpmEvent>,
}

impl TpmEventLog {
    /// Decode from binary_bios_measurements format
    ///
    /// First event is TCG_PCClientPCREvent (legacy format with SHA-1).
    /// Subsequent events are TCG_PCR_EVENT2 (crypto-agile format).
    pub fn decode(input: &mut &[u8]) -> Result<Self> {
        let (_spec_id_header, spec_id_header_event) =
            parse_spec_id_event(input).context("Failed to parse spec id event")?;

        let mut events = vec![];
        loop {
            let head_buffer = &mut &input[..];
            let pcr_index = match u32::decode(head_buffer) {
                Ok(idx) => idx,
                Err(_) => break,
            };

            if pcr_index == 0xFFFFFFFF {
                break;
            }

            let raw_event = TpmRawEvent::decode(input).context("Failed to decode TPM event")?;

            if let Some(event) = raw_event.to_simple_event() {
                events.push(event);
            }
        }

        Ok(TpmEventLog {
            spec_id_header_event,
            events,
        })
    }

    /// Read and decode TPM Event Log from kernel sysfs
    pub fn from_kernel_file() -> Result<Self> {
        const TPM_BINARY_BIOS_MEASUREMENTS: &str =
            "/sys/kernel/security/tpm0/binary_bios_measurements";

        let data = fs_err::read(TPM_BINARY_BIOS_MEASUREMENTS)
            .context("Failed to read TPM binary_bios_measurements")?;

        Self::decode(&mut data.as_slice())
    }

    /// Filter events by PCR index
    pub fn filter_by_pcr(&self, pcr_index: u32) -> Vec<TpmEvent> {
        self.events
            .iter()
            .filter(|e| e.pcr_index == pcr_index)
            .cloned()
            .collect()
    }

    /// Get all PCR 2 events (boot loader and OS measurements)
    pub fn pcr2_events(&self) -> Vec<TpmEvent> {
        self.filter_by_pcr(2)
    }
}

/// Parse Spec ID Event in legacy TCG_PCClientPCREvent format
fn parse_spec_id_event<I: scale::Input>(input: &mut I) -> Result<(TpmRawEvent, TcgEfiSpecIdEvent)> {
    #[derive(Decode)]
    struct SpecIdHeader {
        pcr_index: u32,
        event_type: u32,
        digest_sha1: [u8; 20],
        event: VecOf<u32, u8>,
    }

    let header = SpecIdHeader::decode(input).context("failed to decode spec id header")?;

    let spec_id_event = TcgEfiSpecIdEvent::decode(&mut header.event.as_slice())
        .context("failed to decode TcgEfiSpecIdEvent")?;

    let digests = vec![TcgDigest {
        algo_id: crate::tcg::TPM_ALG_SHA1,
        hash: header.digest_sha1.to_vec(),
    }];

    let raw_event = TpmRawEvent {
        pcr_index: header.pcr_index,
        event_type: header.event_type,
        digests: (digests.len() as u32, digests).into(),
        event: header.event,
    };

    Ok((raw_event, spec_id_event))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_empty() {
        let result = TpmEventLog::decode(&mut &[][..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_gcp_tpm_eventlog() {
        let data = include_bytes!("../samples/tpm_eventlog.bin");
        let event_log = TpmEventLog::decode(&mut data.as_slice()).unwrap();

        assert!(!event_log.events.is_empty());
        assert_eq!(event_log.spec_id_header_event.platform_class, 0);

        let pcr2_events = event_log.pcr2_events();
        assert_eq!(pcr2_events.len(), 4);

        assert_eq!(
            hex::encode(&pcr2_events[0].digest),
            "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
        );

        assert_eq!(
            hex::encode(&pcr2_events[1].digest),
            "00b8a357e652623798d1bbd16c375ec90fbed802b4269affa3e78e6eb19386cf"
        );

        // Event 28: UKI Authenticode hash
        assert_eq!(
            hex::encode(&pcr2_events[2].digest),
            "9ab14a46f858662a89adc102d2a57a13f52f75c1769d65a4c34edbbfc8855f0f"
        );

        // Event 41: Linux kernel Authenticode hash
        assert_eq!(
            hex::encode(&pcr2_events[3].digest),
            "ade943a0a7a3189a3201ba17d7df778eb380cbd33ce5e361176e974ccf7cdedb"
        );
    }

    #[test]
    fn test_filter_by_pcr() {
        let data = include_bytes!("../samples/tpm_eventlog.bin");
        let event_log = TpmEventLog::decode(&mut data.as_slice()).unwrap();

        let pcr0_events = event_log.filter_by_pcr(0);
        assert!(!pcr0_events.is_empty());

        let pcr2_events = event_log.filter_by_pcr(2);
        assert_eq!(pcr2_events.len(), 4);

        let pcr99_events = event_log.filter_by_pcr(99);
        assert_eq!(pcr99_events.len(), 0);
    }

    #[test]
    fn test_pcr2_uki_hash_extraction() {
        let data = include_bytes!("../samples/tpm_eventlog.bin");
        let event_log = TpmEventLog::decode(&mut data.as_slice()).unwrap();

        let pcr2_events = event_log.pcr2_events();
        assert!(pcr2_events.len() >= 3);

        let uki_hash = &pcr2_events[2].digest;
        let expected_uki_hash =
            hex::decode("9ab14a46f858662a89adc102d2a57a13f52f75c1769d65a4c34edbbfc8855f0f")
                .unwrap();

        assert_eq!(uki_hash, &expected_uki_hash);
    }
}
