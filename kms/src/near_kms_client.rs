// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! NEAR KMS client for requesting root keys via KMS contract
//!
//! This module handles calling the NEAR KMS contract's `request_kms_root_key()` function,
//! which verifies attestation and requests keys from the MPC network.

use anyhow::{Context, Result};
use fs_err as fs;
use hex;
use near_api::{signer::SecretKey, types::AccountId, Account, Chain, NearToken, Signer};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::ckd::MpcResponse;
use crate::config::KmsConfig;

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
    chain: Chain,
    kms_contract_id: AccountId,
    account: Option<Account>,
}

impl NearKmsClient {
    /// Create a new NEAR KMS client
    pub fn new(
        rpc_url: &str,
        kms_contract_id: String,
        signer: Option<near_crypto::InMemorySigner>,
    ) -> Result<Self> {
        let chain =
            Chain::from_rpc_url(rpc_url).context("Failed to create NEAR chain from RPC URL")?;

        let kms_contract_id: AccountId = kms_contract_id
            .parse()
            .context("Failed to parse KMS contract ID")?;

        let account = if let Some(in_memory_signer) = signer {
            // Convert near_crypto::InMemorySigner to near-api Signer
            // near_crypto::SecretKey implements Display, so we can get the string representation
            let secret_key_str = in_memory_signer.secret_key().to_string();
            let near_api_secret_key = SecretKey::from_str(&secret_key_str)
                .context("Failed to parse secret key for near-api Signer")?;

            // near-api Signer::from_secret_key takes only the secret key
            let signer = Signer::from_secret_key(near_api_secret_key)
                .context("Failed to create near-api Signer")?;

            Some(Account::new(
                in_memory_signer.account_id.clone(),
                signer,
                chain.clone(),
            ))
        } else {
            None
        };

        Ok(Self {
            chain,
            kms_contract_id,
            account,
        })
    }

    /// Request root key from KMS contract
    ///
    /// This calls the KMS contract's `request_kms_root_key()` which:
    /// 1. Verifies the TDX attestation (quote, collateral, tcb_info)
    /// 2. Calls the MPC contract to derive the key
    /// 3. Returns a Promise that resolves with the MPC response
    ///
    /// Note: The MPC response comes back via a Promise callback. We need to wait
    /// for the transaction to complete and then extract the result from the receipt.
    pub async fn request_kms_root_key(
        &self,
        quote_hex: &str,
        collateral: &str,
        tcb_info: &str,
        worker_public_key: &str,
    ) -> Result<MpcResponse> {
        let account = self
            .account
            .as_ref()
            .context("NEAR signer required for KMS root key requests")?;

        // Create request arguments
        let args = RequestKmsRootKeyArgs {
            quote_hex: quote_hex.to_string(),
            collateral: collateral.to_string(),
            tcb_info: tcb_info.to_string(),
            worker_public_key: worker_public_key.to_string(),
        };

        // Call the contract method using near-api
        // The contract returns a Promise that resolves with the MPC response
        let result = account
            .contract(self.kms_contract_id.clone())
            .call("request_kms_root_key")
            .args_json(args)
            .gas(300_000_000_000_000u64) // 300 TGas
            .deposit(NearToken::from_yoctonear(1)) // 1 yoctoNEAR (required by KMS contract)
            .transact()
            .await
            .context("Failed to call KMS contract")?;

        // Extract the MPC response from the transaction result
        // The response comes via Promise callback, so we need to check the receipt outcomes
        self.extract_mpc_response_from_result(&result)
    }

    /// Extract MPC response from transaction result
    ///
    /// The MPC response comes back via a Promise callback in the receipt outcomes.
    /// We need to search through the receipts to find the CKDResponse.
    fn extract_mpc_response_from_result(
        &self,
        result: &near_api::types::FinalExecutionOutcomeView,
    ) -> Result<MpcResponse> {
        // Check transaction status
        match &result.status {
            near_api::types::FinalExecutionStatus::SuccessValue(_) => {
                // Look for the MPC response in the receipt outcomes
                // The callback from MPC contract should contain the CKDResponse
                for receipt_outcome in &result.receipts_outcome {
                    if let near_api::types::ExecutionStatusView::SuccessValue(value) =
                        &receipt_outcome.outcome.status
                    {
                        // Try to parse as MPC response
                        if let Ok(mpc_response) = self.parse_mpc_response(value) {
                            return Ok(mpc_response);
                        }
                    }
                }

                // If not found immediately, the Promise callback might be in a nested receipt
                // For now, return an error - in production you might want to implement polling
                anyhow::bail!(
                    "MPC response not found in transaction receipt. The response comes via Promise callback from MPC contract. \
                    The KMS contract calls the MPC contract, which calls back with the response. \
                    You may need to implement polling or check the transaction receipt after the Promise resolves."
                )
            }
            near_api::types::FinalExecutionStatus::Failure(err) => {
                Err(anyhow::anyhow!("KMS transaction failed: {:?}", err))
            }
            other => Err(anyhow::anyhow!(
                "Unexpected transaction status: {:?}",
                other
            )),
        }
    }

    /// Parse MPC response from transaction receipt value
    fn parse_mpc_response(&self, value: &[u8]) -> Result<MpcResponse> {
        // The MPC contract returns CKDResponse which has Bls12381G1PublicKey wrappers
        #[derive(Deserialize)]
        struct Bls12381G1PublicKey(String);

        #[derive(Deserialize)]
        struct CkdResponse {
            big_y: Bls12381G1PublicKey,
            big_c: Bls12381G1PublicKey,
        }

        let ckd_response: CkdResponse =
            serde_json::from_slice(value).context("Failed to parse MPC response")?;

        Ok(MpcResponse {
            big_y: ckd_response.big_y.0,
            big_c: ckd_response.big_c.0,
        })
    }
}

/// Generate a random NEAR implicit account signer
/// The account ID is derived from the Ed25519 public key (64 hex characters)
pub fn generate_near_implicit_signer() -> Result<near_crypto::InMemorySigner> {
    use near_crypto::{InMemorySigner, SecretKey};

    // Generate random Ed25519 keypair
    let secret_key = SecretKey::from_random(near_crypto::KeyType::ED25519);

    // Derive implicit account ID from public key (hex encode the 32-byte public key)
    let public_key = secret_key.public_key();
    let account_id = match public_key {
        near_crypto::PublicKey::ED25519(pk) => {
            // Implicit account ID is the hex-encoded public key (64 characters)
            hex::encode(pk.as_bytes())
        }
        _ => anyhow::bail!("Unexpected key type for NEAR implicit account"),
    };

    let account_id: near_primitives::types::AccountId = account_id
        .parse()
        .context("Failed to parse generated account ID")?;

    Ok(InMemorySigner::from_secret_key(account_id, secret_key))
}

/// Load or generate NEAR signer (stored persistently)
///
/// This function checks if a signer already exists in the cert_dir, and if not,
/// generates a new random NEAR implicit account signer and saves it.
pub fn load_or_generate_near_signer(
    config: &KmsConfig,
) -> Result<Option<near_crypto::InMemorySigner>> {
    // Only generate if using NEAR auth
    if !matches!(&config.auth_api, crate::config::AuthApi::Near { .. }) {
        return Ok(None);
    }

    let signer_path = config.cert_dir.join("near_signer.json");

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

        use near_crypto::{InMemorySigner, SecretKey};

        let account_id: near_primitives::types::AccountId = account_id_str
            .parse()
            .context("Failed to parse account ID from signer file")?;
        let secret_key = SecretKey::from_str(secret_key_str)
            .context("Failed to parse secret key from signer file")?;

        tracing::info!("Loaded existing NEAR signer: {}", account_id);
        Ok(Some(InMemorySigner::from_secret_key(
            account_id, secret_key,
        )))
    } else {
        // Generate new signer
        let signer = generate_near_implicit_signer()?;
        let account_id = signer.account_id.to_string();
        let secret_key_str = signer.secret_key().to_string();

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
