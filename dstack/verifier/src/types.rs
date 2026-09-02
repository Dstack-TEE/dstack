// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dstack_types::KeyProviderInfo;
use ra_tls::attestation::{AppInfo, TeeVariant};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyBootInfo {
    pub tee_variant: TeeVariant,
    #[serde(with = "serde_bytes")]
    pub mr_aggregated: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub os_image_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub mr_system: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub app_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub compose_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub instance_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub device_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub key_provider_info: Vec<u8>,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
}

impl PolicyBootInfo {
    pub fn from_app_info(
        tee_variant: TeeVariant,
        app_info: &AppInfo,
        tcb_status: String,
        advisory_ids: Vec<String>,
    ) -> Self {
        Self {
            tee_variant,
            mr_aggregated: app_info.mr_aggregated.to_vec(),
            os_image_hash: app_info.os_image_hash.clone(),
            mr_system: app_info.mr_system.to_vec(),
            app_id: app_info.app_id.clone(),
            compose_hash: app_info.compose_hash.clone(),
            instance_id: app_info.instance_id.clone(),
            device_id: app_info.device_id.clone(),
            key_provider_info: app_info.key_provider_info.clone(),
            tcb_status,
            advisory_ids,
        }
    }
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
    /// Indicates that TDX ACPI table contents were verified.
    ///
    /// Both dstack TDX paths set this. The full-image path recomputes the
    /// tables and checks the resulting RTMRs against the quote. The lite path
    /// recomputes the three RTMR0 ACPI DATA digests from the declared VM shape
    /// and rejects the attestation when they disagree with the ones the guest
    /// reported, then rebuilds RTMR0 from the recomputed digests, so neither
    /// path lets host-reported table content reach the expected value.
    ///
    /// It stays false where the check does not apply: GCP TDX, which measures
    /// through the vTPM instead, and the SEV-SNP and Nitro Enclave paths.
    pub acpi_tables_verified: bool,
    /// dev vs prod OS image, from metadata.json (bound to os_image_hash). None if not exposed.
    pub os_image_is_dev: Option<bool>,
    /// dstack OS version, from the same metadata.json.
    pub os_image_version: Option<String>,
    /// TEE variant that produced the verified quote.
    pub tee_variant: Option<TeeVariant>,
    pub report_data: Option<String>,
    pub tcb_status: Option<String>,
    pub advisory_ids: Vec<String>,
    /// decoded app_info.key_provider_info; name is e.g. "kms" or "local".
    pub key_provider: Option<KeyProviderInfo>,
    pub app_info: Option<AppInfo>,
    /// Canonical auth-policy input matching the KMS bootAuth payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_info: Option<PolicyBootInfo>,
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
    use ra_tls::attestation::TeeVariant;

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

    #[test]
    fn policy_boot_info_serializes_as_auth_payload() {
        let app_info = AppInfo {
            app_id: vec![0x11; 20],
            compose_hash: vec![0x22; 32],
            instance_id: vec![0x33; 20],
            device_id: vec![0x44; 32],
            mr_system: [0x55; 32],
            mr_aggregated: [0x66; 32],
            os_image_hash: vec![0x77; 32],
            key_provider_info: br#"{"name":"tpm","id":"aws-test"}"#.to_vec(),
            init_script_hashes: Some(Vec::new()),
        };

        let boot_info = PolicyBootInfo::from_app_info(
            TeeVariant::DstackAwsNitroTpm,
            &app_info,
            String::new(),
            Vec::new(),
        );
        let encoded = serde_json::to_value(&boot_info).unwrap();

        assert_eq!(encoded["teeVariant"], "dstack-aws-nitro-tpm");
        assert_eq!(encoded["tcbStatus"], "");
        assert_eq!(encoded["advisoryIds"], serde_json::json!([]));
        assert!(encoded.get("mrAggregated").unwrap().is_string());
        assert!(encoded.get("osImageHash").unwrap().is_string());
        assert!(encoded.get("mrSystem").unwrap().is_string());
        assert!(encoded.get("keyProviderInfo").unwrap().is_string());
    }
}
