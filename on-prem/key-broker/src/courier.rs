// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use std::sync::Arc;

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use dstack_guest_agent_rpc::{dstack_guest_client::DstackGuestClient, RawQuoteArgs};
use http_client::prpc::PrpcClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::{crypto, errors::AppError, state::AppState};

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
/// this courier session's transport key.
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
            // REQUIRE_ATTESTATION whether to allow an unattested provision.
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
    pub sealed_root: Option<String>,
    pub auth_bundle: serde_json::Value,
    /// Optional operator override for the KMS rpc cert SAN/domain (e.g. when the
    /// KMS sits behind a load balancer or a real DNS name). When unset, the
    /// key-broker auto-detects the CVM's own internal IP; the authority's sealed
    /// `domain` is only a last-resort fallback.
    #[serde(default)]
    pub kms_domain: Option<String>,
}

/// Best-effort detection of this CVM's primary internal IP. Used as the KMS rpc
/// cert SAN so it always matches the address clients actually dial (their
/// `kms_urls`). "Connecting" a UDP socket only selects the default-route source
/// address — no packet is sent; `169.254.169.254` (the GCP metadata server) is
/// always routable in-VPC, so this resolves to the primary NIC's address.
fn detect_local_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("169.254.169.254:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

#[derive(Serialize)]
pub struct InstallResponse {
    pub ok: bool,
}

pub async fn install(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InstallRequest>,
) -> Result<Json<InstallResponse>, AppError> {
    crypto::verify_auth_bundle(&req.auth_bundle, &state.config.authority_pubkey)?;

    // check bundle_seq monotonically increasing
    {
        let existing = state.auth_bundle.read().await;
        if let Some(existing) = existing.as_ref() {
            let old_seq = existing["bundle_seq"].as_u64().unwrap_or(0);
            let new_seq = req.auth_bundle["bundle_seq"].as_u64().unwrap_or(0);
            if new_seq <= old_seq {
                return Err(AppError::from(anyhow::anyhow!(
                    "bundle_seq not monotonically increasing: {} <= {}",
                    new_seq,
                    old_seq
                )));
            }
        }
    }

    if let Some(sealed_root) = &req.sealed_root {
        let transport_guard = state.transport_secret.read().await;
        let secret = transport_guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no transport keypair, call /courier/init first"))?;

        let root_bytes = crypto::unseal_root(sealed_root, secret)?;

        let kms_vol = &state.config.kms_volume;
        std::fs::create_dir_all(kms_vol)
            .map_err(|e| anyhow::anyhow!("failed to create kms volume dir: {}", e))?;

        // Materialise the full dstack-kms key set the KMS core loads on boot
        // (root-ca / tmp-ca / rpc / k256), so it skips onboarding and serves.
        let mut material = crate::keyset::parse_root_material(&root_bytes)?;
        // KMS rpc cert SAN/domain precedence:
        //   operator override (request) > auto-detected CVM internal IP > authority fallback.
        // The SAN is NOT a trust anchor (that's the root CA) — it only has to match the
        // address clients dial (their kms_urls), which is the operator's deployment topology,
        // not vendor policy. So the vendor authority need not know it.
        let effective_domain = req
            .kms_domain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(detect_local_ip)
            .unwrap_or_else(|| material.domain.clone());
        tracing::info!("courier install: KMS rpc cert domain/SAN = {effective_domain}");
        material.domain = effective_domain;
        let cert_dir = kms_vol.join("certs");
        crate::keyset::install_kms_keyset(&cert_dir, &material)?;

        std::fs::write(kms_vol.join("_ready"), b"1")
            .map_err(|e| anyhow::anyhow!("failed to write _ready marker: {}", e))?;

        *state.root_ready.write().await = true;
        tracing::info!("courier install: key set materialised, key-broker is ready");
    }

    let bundle_path = state.config.kms_volume.join("auth_bundle.json");
    std::fs::write(
        &bundle_path,
        serde_json::to_string_pretty(&req.auth_bundle)?,
    )
    .map_err(|e| anyhow::anyhow!("failed to write auth_bundle.json: {}", e))?;

    *state.auth_bundle.write().await = Some(req.auth_bundle);

    tracing::info!("courier install: auth bundle persisted");

    // load root-ca.crt if it exists (may be written by authority as part of bundle)
    let ca_cert_path = state.config.kms_volume.join("root-ca.crt");
    if ca_cert_path.exists() {
        match std::fs::read_to_string(&ca_cert_path) {
            Ok(pem) => {
                *state.kms_ca_cert.write().await = Some(pem);
                tracing::info!("courier install: loaded root-ca.crt");
            }
            Err(e) => {
                tracing::warn!("courier install: failed to read root-ca.crt: {}", e);
            }
        }
    }

    Ok(Json(InstallResponse { ok: true }))
}
