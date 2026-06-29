// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use cc_eventlog::{RuntimeEvent, TdxEvent};
use dstack_types::mr_config::MrConfigV3;
use serde::{Deserialize, Serialize};
use tpm_types::TpmQuote;

pub const ATTESTATION_VERSION: u64 = 1;

const TDX_ACPI_DATA_EVENT_TYPE: u32 = 10;
const TDX_ACPI_DATA_EVENT_PAYLOAD: &[u8] = b"ACPI DATA";

fn is_tdx_acpi_data_event(event: &TdxEvent) -> bool {
    event.imr == 0
        && event.event_type == TDX_ACPI_DATA_EVENT_TYPE
        && event.event_payload == TDX_ACPI_DATA_EVENT_PAYLOAD
}

pub(crate) fn strip_tdx_runtime_event_log(event_log: Vec<TdxEvent>) -> Vec<TdxEvent> {
    event_log
        .into_iter()
        .filter(|event| event.imr == 3)
        .map(|event| event.stripped())
        .collect()
}

fn strip_tdx_lite_acpi_data_event(event: TdxEvent) -> TdxEvent {
    let mut event = event.stripped();
    event.event_payload = TDX_ACPI_DATA_EVENT_PAYLOAD.to_vec();
    event
}

pub(crate) fn strip_tdx_lite_event_log(event_log: Vec<TdxEvent>) -> Vec<TdxEvent> {
    event_log
        .into_iter()
        .filter_map(|event| {
            if is_tdx_acpi_data_event(&event) {
                Some(strip_tdx_lite_acpi_data_event(event))
            } else if event.imr == 3 {
                Some(event.stripped())
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn is_tdx_lite_config(config: &str) -> bool {
    serde_json::from_str::<dstack_types::VmConfig>(config)
        .map(|config| config.tdx_attestation_variant.is_lite())
        .unwrap_or(false)
}

pub(crate) fn strip_tdx_event_log_for_config(
    event_log: Vec<TdxEvent>,
    config: &str,
) -> Vec<TdxEvent> {
    if is_tdx_lite_config(config) {
        strip_tdx_lite_event_log(event_log)
    } else {
        strip_tdx_runtime_event_log(event_log)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum PlatformEvidence {
    #[serde(rename = "tdx")]
    Tdx {
        quote: Vec<u8>,
        event_log: Vec<TdxEvent>,
    },
    #[serde(rename = "gcp-tdx")]
    GcpTdx {
        quote: Vec<u8>,
        event_log: Vec<TdxEvent>,
        tpm_quote: TpmQuote,
    },
    #[serde(rename = "nitro-enclave")]
    NitroEnclave { nsm_quote: Vec<u8> },
    #[serde(rename = "sev-snp")]
    SevSnp {
        report: Vec<u8>,
        cert_chain: Vec<Vec<u8>>,
        mr_config: String,
    },
}

impl PlatformEvidence {
    pub fn tdx_quote(&self) -> Option<&[u8]> {
        match self {
            Self::Tdx { quote, .. } | Self::GcpTdx { quote, .. } => Some(quote.as_slice()),
            _ => None,
        }
    }

    pub fn tdx_event_log(&self) -> Option<&[TdxEvent]> {
        match self {
            Self::Tdx { event_log, .. } | Self::GcpTdx { event_log, .. } => {
                Some(event_log.as_slice())
            }
            _ => None,
        }
    }

    pub fn tpm_quote(&self) -> Option<&TpmQuote> {
        match self {
            Self::GcpTdx { tpm_quote, .. } => Some(tpm_quote),
            _ => None,
        }
    }

    pub fn nsm_quote(&self) -> Option<&[u8]> {
        match self {
            Self::NitroEnclave { nsm_quote } => Some(nsm_quote.as_slice()),
            _ => None,
        }
    }

    pub fn sev_snp_report(&self) -> Option<&[u8]> {
        match self {
            Self::SevSnp { report, .. } => Some(report.as_slice()),
            _ => None,
        }
    }

    pub fn sev_snp_cert_chain(&self) -> Option<&[Vec<u8>]> {
        match self {
            Self::SevSnp { cert_chain, .. } => Some(cert_chain.as_slice()),
            _ => None,
        }
    }

    pub fn sev_snp_mr_config_document(&self) -> Option<&str> {
        match self {
            Self::SevSnp { mr_config, .. } => Some(mr_config.as_str()),
            _ => None,
        }
    }

    pub fn sev_snp_mr_config(&self) -> Option<MrConfigV3> {
        self.sev_snp_mr_config_document()
            .and_then(|document| MrConfigV3::from_document(document).ok())
    }

    pub fn into_stripped(self) -> Self {
        self.into_stripped_for_config("")
    }

    pub fn into_stripped_for_config(self, config: &str) -> Self {
        match self {
            Self::Tdx { quote, event_log } => Self::Tdx {
                quote,
                event_log: strip_tdx_event_log_for_config(event_log, config),
            },
            Self::GcpTdx {
                quote,
                event_log,
                tpm_quote,
            } => Self::GcpTdx {
                quote,
                event_log: strip_tdx_runtime_event_log(event_log),
                tpm_quote,
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
        let config = self.stack.config().to_string();
        Self {
            version: self.version,
            platform: self.platform.into_stripped_for_config(&config),
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

    /// Return a new attestation with the report_data patched in both platform quote and stack.
    pub fn with_report_data(self, report_data: [u8; 64]) -> Self {
        use crate::attestation::{SNP_REPORT_DATA_RANGE, TDX_QUOTE_REPORT_DATA_RANGE};

        let platform = match self.platform {
            PlatformEvidence::Tdx {
                mut quote,
                event_log,
            } => {
                if quote.len() >= TDX_QUOTE_REPORT_DATA_RANGE.end {
                    quote[TDX_QUOTE_REPORT_DATA_RANGE].copy_from_slice(&report_data);
                }
                PlatformEvidence::Tdx { quote, event_log }
            }
            PlatformEvidence::SevSnp {
                mut report,
                cert_chain,
                mr_config,
            } => {
                if report.len() >= SNP_REPORT_DATA_RANGE.end {
                    report[SNP_REPORT_DATA_RANGE].copy_from_slice(&report_data);
                }
                PlatformEvidence::SevSnp {
                    report,
                    cert_chain,
                    mr_config,
                }
            }
            other => other,
        };
        let stack = match self.stack {
            StackEvidence::Dstack {
                runtime_events,
                config,
                ..
            } => StackEvidence::Dstack {
                report_data: report_data.to_vec(),
                runtime_events,
                config,
            },
            StackEvidence::DstackPod {
                runtime_events,
                config,
                report_data_payload,
                ..
            } => StackEvidence::DstackPod {
                report_data: report_data.to_vec(),
                runtime_events,
                config,
                report_data_payload,
            },
        };
        Self {
            version: self.version,
            platform,
            stack,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mr_config_document() -> String {
        MrConfigV3::new(
            vec![0x11; 20],
            vec![0x22; 32],
            dstack_types::KeyProviderKind::None,
            Vec::new(),
            vec![0x33; 20],
        )
        .to_canonical_json()
    }

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

    #[test]
    fn sev_snp_msgpack_roundtrip_preserves_evidence() {
        let attestation = Attestation::new(
            PlatformEvidence::SevSnp {
                report: vec![0x11; 1184],
                cert_chain: vec![vec![0x22, 0x33]],
                mr_config: test_mr_config_document(),
            },
            StackEvidence::Dstack {
                report_data: vec![9u8; 64],
                runtime_events: vec![],
                config: "{}".into(),
            },
        );

        let encoded = attestation.to_msgpack().expect("encode msgpack");
        let decoded = Attestation::from_msgpack(&encoded).expect("decode msgpack");
        assert_eq!(
            decoded.platform.sev_snp_report(),
            Some(vec![0x11; 1184].as_slice())
        );
        assert_eq!(
            decoded.platform.sev_snp_cert_chain(),
            Some(vec![vec![0x22, 0x33]].as_slice())
        );
    }

    fn boot_event(idx: usize) -> TdxEvent {
        TdxEvent {
            imr: 0,
            event_type: idx as u32,
            digest: vec![idx as u8; 48],
            event: String::new(),
            event_payload: vec![0xff; idx + 1],
        }
    }

    fn acpi_data_event(idx: usize) -> TdxEvent {
        TdxEvent {
            imr: 0,
            event_type: TDX_ACPI_DATA_EVENT_TYPE,
            digest: vec![idx as u8; 48],
            event: String::new(),
            event_payload: TDX_ACPI_DATA_EVENT_PAYLOAD.to_vec(),
        }
    }

    fn runtime_event() -> TdxEvent {
        RuntimeEvent {
            event: "app-id".into(),
            payload: vec![0x42],
        }
        .into()
    }

    #[test]
    fn lite_stripping_keeps_only_acpi_data_digests_and_runtime_payloads() {
        let mut event_log = (0..20).map(boot_event).collect::<Vec<_>>();
        event_log[3] = acpi_data_event(3);
        event_log[8] = acpi_data_event(8);
        event_log[15] = acpi_data_event(15);
        event_log.push(runtime_event());

        let stripped = strip_tdx_lite_event_log(event_log);

        assert_eq!(stripped.len(), 4);
        assert_eq!(
            stripped[0..3]
                .iter()
                .map(|event| event.digest.clone())
                .collect::<Vec<_>>(),
            vec![vec![3u8; 48], vec![8u8; 48], vec![15u8; 48]]
        );
        assert!(stripped[0..3]
            .iter()
            .all(|event| event.imr == 0 && event.event_payload == TDX_ACPI_DATA_EVENT_PAYLOAD));
        assert_eq!(stripped[3].imr, 3);
        assert_eq!(stripped[3].event, "app-id");
        assert_eq!(stripped[3].event_payload, vec![0x42]);
    }

    #[test]
    fn sev_snp_with_report_data_patches_report_and_stack() {
        let mut report = vec![0x11; 1184];
        report[crate::attestation::SNP_REPORT_DATA_RANGE].copy_from_slice(&[0x22; 64]);
        let attestation = Attestation::new(
            PlatformEvidence::SevSnp {
                report,
                cert_chain: vec![],
                mr_config: test_mr_config_document(),
            },
            StackEvidence::Dstack {
                report_data: vec![0x22; 64],
                runtime_events: vec![],
                config: "{}".into(),
            },
        );

        let patched = attestation.with_report_data([0x33; 64]);
        assert_eq!(patched.report_data().unwrap(), [0x33; 64]);
        let report = patched.platform.sev_snp_report().unwrap();
        assert_eq!(
            &report[crate::attestation::SNP_REPORT_DATA_RANGE],
            &[0x33; 64]
        );
    }
}
