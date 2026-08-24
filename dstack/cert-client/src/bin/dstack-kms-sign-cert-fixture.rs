// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0
//! Generate a v2 KMS CSR whose key is bound to fresh guest attestation.

use anyhow::{Context, Result};
use dstack_guest_agent_rpc::{dstack_guest_client::DstackGuestClient, AttestArgs};
use http_client::prpc::PrpcClient;
use ra_tls::{
    attestation::{PlatformEvidence, QuoteContentType, VersionedAttestation},
    cert::{CertConfig, CertConfigV2, CertSigningRequestV1, CertSigningRequestV2, Csr},
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};
use serde_json::json;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[tokio::main]
async fn main() -> Result<()> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("failed to generate the case-scoped certificate key")?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let address = dstack_types::dstack_agent_address();
    let client = DstackGuestClient::new(PrpcClient::new(address));
    let response = client
        .attest(AttestArgs {
            report_data: report_data.to_vec(),
            include_gpu_evidence: false,
        })
        .await
        .context("failed to obtain key-bound guest attestation")?;
    let attestation = VersionedAttestation::from_bytes(&response.attestation)
        .context("failed to decode key-bound guest attestation")?;
    let csr = CertSigningRequestV2 {
        confirm: "please sign cert:".to_string(),
        pubkey: pubkey.clone(),
        config: CertConfigV2 {
            org_name: Some("Dstack Test".to_string()),
            subject: "kms-sign-cert.test".to_string(),
            subject_alt_names: vec!["kms-sign-cert.test".to_string()],
            usage_server_auth: true,
            usage_client_auth: true,
            ext_quote: true,
            ext_app_info: true,
            not_before: None,
            not_after: None,
        },
        attestation: attestation.clone(),
    };
    let signature = csr.signed_by(&key).context("failed to sign the v2 CSR")?;
    let (quote, event_log) = match attestation.clone().into_v1().platform {
        PlatformEvidence::Tdx { quote, event_log } => (quote, event_log),
        _ => anyhow::bail!("legacy v1 CSR fixture requires TDX evidence"),
    };
    let csr_v1 = CertSigningRequestV1 {
        confirm: "please sign cert:".to_string(),
        pubkey: pubkey.clone(),
        config: CertConfig {
            org_name: Some("Dstack Test".to_string()),
            subject: "kms-sign-cert.test".to_string(),
            subject_alt_names: vec!["kms-sign-cert.test".to_string()],
            usage_server_auth: true,
            usage_client_auth: true,
            ext_quote: true,
        },
        quote,
        event_log: serde_json::to_vec(&event_log)
            .context("failed to encode the legacy TDX event log")?,
    };
    let signature_v1 = csr_v1
        .signed_by(&key)
        .context("failed to sign the v1 CSR")?;
    println!(
        "{}",
        json!({
            "api_version": 2,
            "csr": hex(&csr.to_vec()),
            "signature": hex(&signature),
            "csr_v1": hex(&csr_v1.data_to_sign()),
            "signature_v1": hex(&signature_v1),
            "public_key": hex(&pubkey),
            "subject": "kms-sign-cert.test",
            "alt_name": "kms-sign-cert.test"
        })
    );
    Ok(())
}
