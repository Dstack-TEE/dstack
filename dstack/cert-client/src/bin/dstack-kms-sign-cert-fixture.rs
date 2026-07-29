// SPDX-License-Identifier: Apache-2.0
//! Generate a v2 KMS CSR whose key is bound to fresh guest attestation.

use anyhow::{Context, Result};
use ra_rpc::Attestation;
use ra_tls::{
    attestation::QuoteContentType,
    cert::{CertConfigV2, CertSigningRequestV2, Csr},
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

fn main() -> Result<()> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("failed to generate the case-scoped certificate key")?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let attestation = Attestation::quote(&report_data)
        .context("failed to obtain key-bound guest attestation")?
        .into_versioned();
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
        attestation,
    };
    let signature = csr.signed_by(&key).context("failed to sign the v2 CSR")?;
    println!(
        "{}",
        json!({
            "api_version": 2,
            "csr": hex(&csr.to_vec()),
            "signature": hex(&signature),
            "public_key": hex(&pubkey),
            "subject": "kms-sign-cert.test",
            "alt_name": "kms-sign-cert.test"
        })
    );
    Ok(())
}
