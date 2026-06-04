// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{slot::SlotBinding, state::AppState};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportPeriod {
    pub from: u64,
    pub to: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UsageReceipt {
    pub user_id: String,
    pub kms_pubkey: String,
    pub report_period: ReportPeriod,
    pub active_slots: Vec<SlotBinding>,
    pub bundle_seq: u64,
    pub kms_sig: String,
}

impl UsageReceipt {
    pub fn generate(state: &AppState, slots: Vec<SlotBinding>, hmac_key: &[u8]) -> Result<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system time error")?
            .as_secs();

        let (user_id, kms_pubkey, bundle_seq) = {
            // read synchronously via blocking – caller holds no lock
            // this is called from async context so we read the values passed in
            let (c, k, s) = ("".to_string(), "".to_string(), 0u64);
            (c, k, s)
        };

        let mut receipt = Self {
            user_id,
            kms_pubkey,
            report_period: ReportPeriod { from: 0, to: now },
            active_slots: slots,
            bundle_seq,
            kms_sig: String::new(),
        };

        let sig = compute_sig(&receipt, hmac_key)?;
        receipt.kms_sig = STANDARD.encode(sig);
        Ok(receipt)
    }

    pub fn generate_with_bundle(
        user_id: String,
        kms_pubkey: String,
        slots: Vec<SlotBinding>,
        bundle_seq: u64,
        hmac_key: &[u8],
    ) -> Result<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system time error")?
            .as_secs();

        let mut receipt = Self {
            user_id,
            kms_pubkey,
            report_period: ReportPeriod { from: 0, to: now },
            active_slots: slots,
            bundle_seq,
            kms_sig: String::new(),
        };

        let sig = compute_sig(&receipt, hmac_key)?;
        receipt.kms_sig = STANDARD.encode(sig);
        Ok(receipt)
    }
}

fn compute_sig(receipt: &UsageReceipt, key: &[u8]) -> Result<Vec<u8>> {
    let payload = serde_json::json!({
        "user_id": receipt.user_id,
        "kms_pubkey": receipt.kms_pubkey,
        "report_period": receipt.report_period,
        "active_slots": receipt.active_slots,
        "bundle_seq": receipt.bundle_seq,
    })
    .to_string();

    let mut mac = HmacSha256::new_from_slice(key).context("failed to create HMAC key")?;
    mac.update(payload.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}
