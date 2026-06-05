// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use dstack_guest_agent_rpc::{dstack_guest_client::DstackGuestClient, RawQuoteArgs};
use http_client::prpc::PrpcClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::{crypto, errors::AppError, license, state::AppState};

#[derive(Deserialize)]
pub struct InitRequest {
    pub nonce: String,
}

#[derive(Serialize)]
pub struct InitResponse {
    pub transport_pub: String,
    pub kms_ts: i64,
    /// hex-encoded dstack VersionedAttestation ("" if guest agent unreachable).
    /// On GCP this bundles BOTH the TDX quote AND the vTPM quote — `Attest`
    /// (not `GetQuote`, which omits the TPM quote) — plus the event log.
    pub attestation: String,
    /// hardware/VM config (from Info) — the verifier needs it for os_image_hash.
    pub vm_config: String,
}

/// report_data = SHA-512(nonce || transport_pub || kms_ts_le_i64).
/// Must match the authority's `compute_report_data` so the quote is bound to
/// this courier session's transport key. IDENTICAL to on-prem key-broker.
fn courier_report_data(nonce: &str, transport_pub: &[u8; 32], kms_ts: i64) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(nonce.as_bytes());
    h.update(transport_pub);
    h.update(kms_ts.to_le_bytes());
    h.finalize().into()
}

fn dstack_client() -> DstackGuestClient<PrpcClient> {
    let address = dstack_types::dstack_agent_address();
    DstackGuestClient::new(PrpcClient::new(address))
}

/// Best-effort read of this launcher's own measured app_id / compose_hash from
/// the guest agent's Info() (AppInfo extension). Returns (app_id, compose_hash)
/// as lowercase hex; None when the guest agent is unreachable.
pub async fn self_identity() -> Option<(String, String)> {
    let client = dstack_client();
    match client.info().await {
        Ok(info) => {
            let app_id = hex::encode(&info.app_id);
            let compose_hash = hex::encode(&info.compose_hash);
            if app_id.is_empty() && compose_hash.is_empty() {
                None
            } else {
                Some((app_id, compose_hash))
            }
        }
        Err(e) => {
            tracing::warn!("self_identity: Info() failed ({e}); cannot determine measured identity");
            None
        }
    }
}

pub async fn init(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InitRequest>,
) -> Result<Json<InitResponse>, AppError> {
    let (secret, pub_bytes) = crypto::generate_transport_keypair();

    *state.transport_secret.write().await = Some(secret);
    *state.transport_pub.write().await = Some(pub_bytes);

    let kms_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system time error: {}", e))?
        .as_secs() as i64;

    // Bind the attestation to (nonce, transport_pub, kms_ts) via report_data,
    // then ask the local dstack guest agent for a full attestation (TDX + vTPM
    // on GCP) plus the vm_config the verifier needs for os_image_hash.
    let report_data = courier_report_data(&req.nonce, &pub_bytes, kms_ts);
    let client = dstack_client();
    let (attestation, vm_config) = match client
        .attest(RawQuoteArgs { report_data: report_data.to_vec() })
        .await
    {
        Ok(resp) => {
            let vm_config = match client.info().await {
                Ok(info) => info.vm_config,
                Err(e) => {
                    tracing::warn!("courier init: Info() failed ({e}); empty vm_config");
                    String::new()
                }
            };
            tracing::info!(
                "courier init: got attestation ({} bytes) + vm_config",
                resp.attestation.len()
            );
            (resp.attestation, vm_config)
        }
        Err(e) => {
            // dev / no guest agent: leave attestation empty; authority decides via
            // its own policy whether to allow an unattested provision.
            tracing::warn!("courier init: attestation unavailable ({e}); returning empty");
            (vec![], String::new())
        }
    };

    Ok(Json(InitResponse {
        transport_pub: STANDARD.encode(pub_bytes),
        kms_ts,
        attestation: hex::encode(&attestation),
        vm_config,
    }))
}

#[derive(Deserialize)]
pub struct InstallRequest {
    /// base64( enc(32) || ciphertext ) HPKE-sealed to this session's transport
    /// pub. Carries the image private key PEM (the CEK). Optional: a renewal that
    /// only extends the license (no new image) may omit it.
    #[serde(default)]
    pub sealed_cek: Option<String>,
    /// The signed License (see license::License).
    pub license: serde_json::Value,
}

#[derive(Serialize)]
pub struct InstallResponse {
    pub ok: bool,
}

pub async fn install(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InstallRequest>,
) -> Result<Json<InstallResponse>, AppError> {
    license::install(&state, req.sealed_cek, req.license).await?;
    Ok(Json(InstallResponse { ok: true }))
}
