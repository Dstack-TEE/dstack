// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use cc_eventlog::{RuntimeEvent, TdxEvent};
use serde::{Deserialize, Serialize};

pub const ATTESTATION_VERSION: u64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum PlatformEvidence {
    #[serde(rename = "tdx")]
    Tdx {
        quote: Vec<u8>,
        event_log: Vec<TdxEvent>,
    },
    #[serde(rename = "gcp-tdx")]
    GcpTdx,
    #[serde(rename = "nitro-enclave")]
    NitroEnclave,
}

impl PlatformEvidence {
    pub fn tdx_quote(&self) -> Option<&[u8]> {
        match self {
            Self::Tdx { quote, .. } => Some(quote.as_slice()),
            _ => None,
        }
    }

    pub fn tdx_event_log(&self) -> Option<&[TdxEvent]> {
        match self {
            Self::Tdx { event_log, .. } => Some(event_log.as_slice()),
            _ => None,
        }
    }

    pub fn into_stripped(self) -> Self {
        match self {
            Self::Tdx { quote, event_log } => Self::Tdx {
                quote,
                event_log: event_log
                    .into_iter()
                    .filter(|event| event.imr == 3)
                    .map(|event| event.stripped())
                    .collect(),
            },
            other => other,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum StackEvidence {
    #[serde(rename = "dstack")]
    Dstack {
        report_data: Vec<u8>,
        runtime_events: Vec<RuntimeEvent>,
        config: String,
    },
    #[serde(rename = "dstack-pod")]
    DstackPod {
        report_data: Vec<u8>,
        runtime_events: Vec<RuntimeEvent>,
        config: String,
        report_data_payload: String,
    },
}

fn decode_report_data(report_data: &[u8]) -> Result<[u8; 64]> {
    report_data
        .try_into()
        .map_err(|_| anyhow!("stack.report_data must be 64 bytes"))
}

impl StackEvidence {
    pub fn report_data(&self) -> Result<[u8; 64]> {
        match self {
            Self::Dstack { report_data, .. } | Self::DstackPod { report_data, .. } => {
                decode_report_data(report_data)
            }
        }
    }

    pub fn runtime_events(&self) -> &[RuntimeEvent] {
        match self {
            Self::Dstack { runtime_events, .. } | Self::DstackPod { runtime_events, .. } => {
                runtime_events.as_slice()
            }
        }
    }

    pub fn config(&self) -> &str {
        match self {
            Self::Dstack { config, .. } | Self::DstackPod { config, .. } => config,
        }
    }

    pub fn report_data_payload(&self) -> Option<&str> {
        match self {
            Self::Dstack { .. } => None,
            Self::DstackPod {
                report_data_payload,
                ..
            } => Some(report_data_payload.as_str()),
        }
    }

    pub fn into_dstack_pod(self, report_data_payload: String) -> Self {
        match self {
            Self::Dstack {
                report_data,
                runtime_events,
                config,
            }
            | Self::DstackPod {
                report_data,
                runtime_events,
                config,
                ..
            } => Self::DstackPod {
                report_data,
                runtime_events,
                config,
                report_data_payload,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub version: u64,
    pub platform: PlatformEvidence,
    pub stack: StackEvidence,
}

impl Attestation {
    pub fn new(platform: PlatformEvidence, stack: StackEvidence) -> Self {
        Self {
            version: ATTESTATION_VERSION,
            platform,
            stack,
        }
    }

    pub fn to_msgpack(&self) -> Result<Vec<u8>> {
        let mut normalized = self.clone();
        normalized.version = ATTESTATION_VERSION;
        rmp_serde::to_vec_named(&normalized).context("failed to encode attestation as msgpack")
    }

    pub fn from_msgpack(bytes: &[u8]) -> Result<Self> {
        let value: Self =
            rmp_serde::from_slice(bytes).context("failed to decode attestation from msgpack")?;
        if value.version != ATTESTATION_VERSION {
            bail!(
                "unsupported attestation version: expected {}, got {}",
                ATTESTATION_VERSION,
                value.version
            );
        }
        Ok(value)
    }

    pub fn report_data(&self) -> Result<[u8; 64]> {
        self.stack.report_data()
    }

    pub fn report_data_payload(&self) -> Option<&str> {
        self.stack.report_data_payload()
    }

    pub fn into_stripped(self) -> Self {
        Self {
            version: self.version,
            platform: self.platform.into_stripped(),
            stack: self.stack,
        }
    }

    pub fn into_dstack_pod(self, report_data_payload: String) -> Self {
        Self {
            version: self.version,
            platform: self.platform,
            stack: self.stack.into_dstack_pod(report_data_payload),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msgpack_roundtrip_preserves_attestation() {
        let attestation = Attestation::new(
            PlatformEvidence::Tdx {
                quote: vec![1u8, 2, 3],
                event_log: vec![TdxEvent {
                    imr: 3,
                    event_type: 0x08000001,
                    digest: vec![0xaa, 0xbb, 0xcc],
                    event: "pod".into(),
                    event_payload: vec![0xde, 0xad, 0xbe, 0xef],
                }],
            },
            StackEvidence::DstackPod {
                report_data: vec![7u8; 64],
                runtime_events: vec![RuntimeEvent {
                    event: "pod".into(),
                    payload: vec![0xca, 0xfe, 0xba, 0xbe],
                }],
                config: "{}".into(),
                report_data_payload: "{\"hello\":\"world\"}".into(),
            },
        );

        let encoded = attestation.to_msgpack().expect("encode msgpack");
        assert!(matches!(encoded.first(), Some(0x80..=0x8f)));
        let decoded = Attestation::from_msgpack(&encoded).expect("decode msgpack");
        assert_eq!(decoded.version, ATTESTATION_VERSION);
        match decoded.platform {
            PlatformEvidence::Tdx { quote, event_log } => {
                assert_eq!(quote, vec![1u8, 2, 3]);
                assert_eq!(event_log.len(), 1);
                assert_eq!(event_log[0].event, "pod");
                assert_eq!(event_log[0].event_payload, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            _ => panic!("expected tdx platform evidence"),
        }
        match decoded.stack {
            StackEvidence::DstackPod {
                report_data,
                runtime_events,
                config,
                report_data_payload,
            } => {
                assert_eq!(report_data, vec![7u8; 64]);
                assert_eq!(runtime_events.len(), 1);
                assert_eq!(runtime_events[0].event, "pod");
                assert_eq!(runtime_events[0].payload, vec![0xca, 0xfe, 0xba, 0xbe]);
                assert_eq!(config, "{}");
                assert_eq!(report_data_payload, "{\"hello\":\"world\"}");
            }
            _ => panic!("expected dstack-pod stack evidence"),
        }
    }
}
