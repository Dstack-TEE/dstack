// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use ra_tls::attestation::AppInfo;
use serde::{Deserialize, Serialize};

use serde_human_bytes as serde_bytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    #[serde(with = "serde_bytes")]
    pub quote: Option<Vec<u8>>,
    pub event_log: Option<String>,
    pub vm_config: Option<String>,
    #[serde(with = "serde_bytes")]
    pub attestation: Option<Vec<u8>>,
    pub pccs_url: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}
