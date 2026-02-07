// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! NEAR KMS client for requesting root keys via KMS contract
//!
//! This module handles calling the NEAR KMS contract's `request_kms_root_key()` function,
//! which verifies attestation and requests keys from the MPC network.

use anyhow::{Context, Result};
use byte_slice_cast::AsByteSlice;
use fs_err as fs;
use hex;
use near_api::{
    types::{AccountId, Data},
    Contract, NetworkConfig, SecretKey, Signer,
};
use near_crypto::InMemorySigner;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};
use std::str::FromStr;
use std::sync::Arc;

use crate::ckd::CkdResponse;
use crate::config::KmsConfig;

const NEAR_SIGNER_FILE: &str = "near_signer.json";

/// Request KMS root key arguments (matching NEAR KMS contract interface)
#[derive(Debug, Serialize, Deserialize)]
pub struct RequestKmsRootKeyArgs {
    pub quote_hex: String,
    pub collateral: String,
    pub tcb_info: String,
    pub worker_public_key: String, // BLS12-381 G1 public key in NEAR format
}

/// NEAR KMS client for requesting root keys
pub struct NearKmsClient {
    network_config: NetworkConfig,
    mpc_contract: Contract,
    kms_contract: Contract,
    signer_account_id: Option<AccountId>,
    signer: Option<Arc<Signer>>,
}

impl NearKmsClient {
    /// Create a new NEAR KMS client
    pub fn new(
        network_config: NetworkConfig,
        mpc_contract_id: String,
        kms_contract_id: String,
        signer: Option<InMemorySigner>,
    ) -> Result<Self> {
        let mpc_contract_id: AccountId = mpc_contract_id
            .parse()
            .context("Failed to parse MPC contract ID")?;

        let kms_contract_id: AccountId = kms_contract_id
            .parse()
            .context("Failed to parse KMS contract ID")?;

        let (signer_account_id, near_api_signer) = if let Some(in_memory_signer) = signer {
            // Convert near_crypto::InMemorySigner to near-api Signer
            let secret_key_str = in_memory_signer.secret_key.to_string();
            let near_api_secret_key = SecretKey::from_str(&secret_key_str)
                .context("Failed to parse secret key for near-api Signer")?;

            // near-api Signer::from_secret_key takes only the secret key
            let signer = Signer::from_secret_key(near_api_secret_key)
                .context("Failed to create near-api Signer")?;

            let account_id: AccountId = in_memory_signer
                .account_id
                .to_string()
                .parse()
                .context("Failed to parse account ID")?;

            (Some(account_id.clone()), Some(signer))
        } else {
            (None, None)
        };

        let mpc_contract = Contract(mpc_contract_id);
        let kms_contract = Contract(kms_contract_id);

        Ok(Self {
            network_config,
            mpc_contract,
            kms_contract,
            signer_account_id,
            signer: near_api_signer,
        })
    }

    /// Get MPC public key from the contract
    pub async fn get_mpc_public_key(&self, domain_id: u64) -> Result<String> {
        let current_value: Data<String> = self
            .mpc_contract
            .call_function("public_key", serde_json::json!({ "domain_id": domain_id }))
            .read_only()
            .fetch_from(&self.network_config)
            .await?;

        Ok(current_value.data)
    }

    /// Request root key from KMS contract
    ///
    /// This calls the KMS contract's `request_kms_root_key()` which:
    /// 1. Verifies the TDX attestation (quote, collateral, tcb_info)
    /// 2. Calls the MPC contract to derive the key
    /// 3. Returns the MPC response (big_y, big_c)
    pub async fn request_kms_root_key(
        &self,
        quote_hex: &str,
        collateral: &str,
        tcb_info: &str,
        worker_public_key: &str,
    ) -> Result<CkdResponse> {
        let signer = self
            .signer
            .as_ref()
            .context("NEAR signer required for KMS root key requests")?;
        let signer_account_id = self
            .signer_account_id
            .as_ref()
            .context("Signer account ID required for KMS root key requests")?;

        // Create request arguments
        let args = RequestKmsRootKeyArgs {
            quote_hex: quote_hex.to_string(),
            collateral: collateral.to_string(),
            tcb_info: tcb_info.to_string(),
            worker_public_key: worker_public_key.to_string(),
        };

        // Call the contract method using near-api
        let execution_result = self
            .kms_contract
            .call_function("request_kms_root_key", args)
            .transaction()
            .with_signer(signer_account_id.clone(), signer.clone())
            .send_to(&self.network_config)
            .await
            .context("Failed to call KMS contract")?;

        // Assert that the transaction succeeded and get receipt outcomes
        // Note: assert_success() may consume the result, so we need to handle this carefully
        let receipt_outcomes = execution_result.receipt_outcomes().to_vec();
        execution_result.assert_success();

        // Extract the return value from the transaction result
        // The return value comes via Promise callback in the receipt outcomes
        // We need to find the return value in one of the receipt outcomes
        // TODO: Implement proper extraction based on the actual near-api API
        // The return value from Promise callbacks needs to be extracted from the appropriate receipt outcome
        // This may require checking the receipt IDs and following the Promise chain, or using
        // a helper method if the API provides one

        // For now, return an error indicating this needs implementation
        // The actual implementation will depend on how the near-api library exposes
        // the return values from Promise callbacks in receipt outcomes
        anyhow::bail!(
            "MPC response extraction needs proper implementation. \
            The response comes via Promise callback in receipt outcomes. \
            Please check the near-api documentation for the correct way to extract return values from ExecutionFinalResult. \
            Receipt outcomes count: {}",
            receipt_outcomes.len()
        )
    }

    /// Parse MPC response from transaction receipt value
    fn parse_ckd_response(&self, value: &[u8]) -> Result<CkdResponse> {
        let ckd_response: CkdResponse =
            serde_json::from_slice(value).context("Failed to parse MPC response")?;

        Ok(CkdResponse {
            big_y: ckd_response.big_y,
            big_c: ckd_response.big_c,
        })
    }
}

/// Generate a random NEAR implicit account signer
/// The account ID is derived from the Ed25519 public key (64 hex characters)
pub fn generate_near_implicit_signer() -> Result<InMemorySigner> {
    // Generate random Ed25519 keypair
    let secret_key = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);

    // Derive implicit account ID from public key (hex encode the 32-byte public key)
    let public_key = secret_key.public_key();
    use byte_slice_cast::AsByteSlice;
    let account_id = match public_key {
        near_crypto::PublicKey::ED25519(pk) => {
            // Implicit account ID is the hex-encoded public key (64 characters)
            hex::encode(pk.as_byte_slice())
        }
        _ => anyhow::bail!("Unexpected key type for NEAR implicit account"),
    };

    let account_id: AccountId = account_id
        .parse()
        .context("Failed to parse generated account ID")?;

    let public_key = secret_key.public_key();
    Ok(InMemorySigner {
        account_id,
        secret_key,
        public_key,
    })
}

/// Load or generate NEAR signer (stored persistently)
///
/// This function checks if a signer already exists in the cert_dir, and if not,
/// generates a new random NEAR implicit account signer and saves it.
pub fn load_or_generate_near_signer(config: &KmsConfig) -> Result<Option<InMemorySigner>> {
    // Only generate if using NEAR auth
    if !matches!(&config.auth_api, crate::config::AuthApi::Near { .. }) {
        return Ok(None);
    }

    let signer_path = config.cert_dir.join(NEAR_SIGNER_FILE);

    if signer_path.exists() {
        // Load existing signer
        let signer_data: serde_json::Value = serde_json::from_slice(
            &fs::read(&signer_path).context("Failed to read NEAR signer file")?,
        )
        .context("Failed to parse NEAR signer file")?;

        let account_id_str = signer_data["account_id"]
            .as_str()
            .context("Missing account_id in signer file")?;
        let secret_key_str = signer_data["secret_key"]
            .as_str()
            .context("Missing secret_key in signer file")?;

        let account_id_parsed: AccountId = account_id_str
            .parse()
            .context("Failed to parse account ID from signer file")?;
        let secret_key = near_crypto::SecretKey::from_str(secret_key_str)
            .context("Failed to parse secret key from signer file")?;

        tracing::info!("Loaded existing NEAR signer: {}", account_id_str);
        let public_key = secret_key.public_key();
        let signer = InMemorySigner {
            account_id: account_id_parsed,
            secret_key,
            public_key,
        };
        Ok(Some(signer))
    } else {
        // Generate new signer
        let signer = generate_near_implicit_signer()?;
        let account_id = signer.account_id.to_string();
        let secret_key_str = signer.secret_key.to_string();

        // Save to file
        let signer_data = serde_json::json!({
            "account_id": account_id,
            "secret_key": secret_key_str,
        });
        fs::write(&signer_path, serde_json::to_string_pretty(&signer_data)?)
            .context("Failed to write NEAR signer file")?;

        tracing::info!("Generated new NEAR implicit account signer: {}", account_id);
        Ok(Some(signer))
    }
}

/// Converts a NEAR public key to the report_data format required by the NEAR KMS contract.
///
/// The format matches `ReportData::new()` in the contract:
/// `[version(2 bytes big endian) || SHA3-384(public_key_bytes[1..]) || zero padding]`
///
/// # Arguments
/// * `public_key` - The NEAR account public key (must be ED25519)
///
/// # Returns
/// A 64-byte array containing the report_data in the format expected by the KMS contract
///
/// # Errors
/// Returns an error if the public key is not ED25519 (only ED25519 keys are supported for NEAR implicit accounts)
pub fn near_public_key_to_report_data(
    public_key: &near_crypto::PublicKey,
) -> Result<[u8; 64]> {
    const REPORT_DATA_SIZE: usize = 64;
    const BINARY_VERSION_SIZE: usize = 2;
    const PUBLIC_KEYS_HASH_SIZE: usize = 48;
    const PUBLIC_KEYS_OFFSET: usize = BINARY_VERSION_SIZE;

    let mut report_data = [0u8; REPORT_DATA_SIZE];

    // Version: 1 (2 bytes, big endian)
    report_data[0..BINARY_VERSION_SIZE].copy_from_slice(&1u16.to_be_bytes());

    // Get public key bytes (skip first byte which is curve type identifier)
    let public_key_bytes = match public_key {
        near_crypto::PublicKey::ED25519(pk) => pk.as_byte_slice(),
        _ => anyhow::bail!("Only ED25519 keys are supported for NEAR implicit accounts"),
    };

    // Hash public key bytes (skip first byte) with SHA3-384
    let mut hasher = Sha3_384::new();
    hasher.update(&public_key_bytes[1..]); // Skip first byte (curve type)
    let hash: [u8; PUBLIC_KEYS_HASH_SIZE] = hasher.finalize().into();

    // Copy hash to report_data (offset 2, length 48)
    report_data[PUBLIC_KEYS_OFFSET..PUBLIC_KEYS_OFFSET + PUBLIC_KEYS_HASH_SIZE]
        .copy_from_slice(&hash);
    // Remaining bytes (50..64) are already zero-padded

    Ok(report_data)
}
