// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use ra_tls::attestation::AppInfo;
use serde::{Deserialize, Serialize};

use serde_human_bytes as serde_bytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    #[serde(with = "serde_bytes", default)]
    pub quote: Option<Vec<u8>>,
    #[serde(default)]
    pub event_log: Option<String>,
    #[serde(default)]
    pub vm_config: Option<String>,
    #[serde(with = "serde_bytes", default)]
    pub attestation: Option<Vec<u8>>,
    #[serde(default)]
    pub debug: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationResponse {
    pub is_valid: bool,
    pub details: VerificationDetails,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct VerificationDetails {
    pub quote_verified: bool,
    /// Indicates that the event log was verified against the quote.
    ///
    /// For RTMR3 (runtime measurements), both the digest and payload integrity are verified
    /// by replaying the event log and comparing against the quote. For RTMR 0-2 (boot-time
    /// measurements), only the digests are verified through replay comparison with the quote;
    /// the payload content is not validated. dstack does not define semantics for RTMR 0-2
    /// event log payloads.
    pub event_log_verified: bool,
    pub os_image_hash_verified: bool,
    pub report_data: Option<String>,
    pub tcb_status: Option<String>,
    pub advisory_ids: Vec<String>,
    pub app_info: Option<AppInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acpi_tables: Option<AcpiTables>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtmr_debug: Option<Vec<RtmrMismatch>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcpiTables {
    pub tables: String,
    pub rsdp: String,
    pub loader: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RtmrMismatch {
    pub rtmr: String,
    pub expected: String,
    pub actual: String,
    pub events: Vec<RtmrEventEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_expected_digests: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RtmrEventEntry {
    pub index: usize,
    pub event_type: u32,
    pub event_name: String,
    pub actual_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
    pub payload_len: usize,
    pub status: RtmrEventStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RtmrEventStatus {
    Match,
    Mismatch,
    Extra,
    Missing,
}

#[cfg(test)]
mod tests {
    use super::*;

    // the README documents sending either `attestation` or
    // (`quote` + `event_log` + `vm_config`); every field is optional, so any
    // documented subset must deserialize without a "missing field" error.

    #[test]
    fn deserializes_quote_subset_without_attestation() {
        let json = r#"{"quote":"00","event_log":"[]","vm_config":"{}"}"#;
        let req: VerificationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.quote, Some(vec![0u8]));
        assert_eq!(req.event_log.as_deref(), Some("[]"));
        assert_eq!(req.vm_config.as_deref(), Some("{}"));
        assert_eq!(req.attestation, None);
        assert_eq!(req.debug, None);
    }

    #[test]
    fn deserializes_attestation_subset_without_quote() {
        let json = r#"{"attestation":"00"}"#;
        let req: VerificationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.attestation, Some(vec![0u8]));
        assert_eq!(req.quote, None);
        assert_eq!(req.event_log, None);
        assert_eq!(req.vm_config, None);
    }

    #[test]
    fn deserializes_empty_object() {
        let req: VerificationRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(req.quote, None);
        assert_eq!(req.attestation, None);
        assert_eq!(req.debug, None);
    }
}
