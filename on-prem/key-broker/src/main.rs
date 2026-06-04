// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use tokio::sync::RwLock;

mod auth;
mod cek;
mod config;
mod courier;
mod crypto;
mod errors;
mod keyset;
mod lease;
mod receipt;
mod slot;
mod state;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ignore error if already installed
    tracing_subscriber::fmt::init();

    let config = config::Config::from_env()?;
    let port = config.port;

    let existing_bundle = load_existing_bundle(&config.kms_volume);
    let root_ready = config.kms_volume.join("_ready").exists();

    if root_ready {
        tracing::info!("root key already present, key-broker starting in ready state");
    } else {
        tracing::info!("waiting for courier install to provide root key");
    }

    let kms_ca_cert = load_kms_ca_cert(&config.kms_volume);
    let slots = slot::SlotStore::new(&config.kms_volume);

    let state = Arc::new(state::AppState {
        transport_secret: RwLock::new(None),
        transport_pub: RwLock::new(None),
        auth_bundle: RwLock::new(existing_bundle),
        root_ready: RwLock::new(root_ready),
        slots,
        kms_ca_cert: RwLock::new(kms_ca_cert),
        config,
    });

    // spawn mTLS server on port_mtls
    let mtls_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(e) = cek::spawn_mtls_server(mtls_state).await {
            tracing::error!("mtls server error: {}", e);
        }
    });

    let app = Router::new()
        .route("/", get(auth::info_handler))
        .route("/courier/init", post(courier::init))
        .route("/courier/install", post(courier::install))
        .route("/bootAuth/app", post(auth::app_boot_auth))
        .route("/bootAuth/kms", post(auth::kms_boot_auth))
        .route("/healthz", get(healthz))
        .route("/version", get(version_handler))
        .route("/usage-receipt", get(usage_receipt_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("key-broker listening on port {}", port);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz(
    State(state): State<Arc<state::AppState>>,
) -> impl IntoResponse {
    if *state.root_ready.read().await {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "waiting for root key")
    }
}

async fn version_handler(
    State(state): State<Arc<state::AppState>>,
    Query(q): Query<cek::VersionQuery>,
) -> Result<Json<cek::VersionResponse>, errors::AppError> {
    cek::version_handler(State(state), Query(q)).await
}

async fn usage_receipt_handler(
    State(state): State<Arc<state::AppState>>,
) -> Result<Json<receipt::UsageReceipt>, errors::AppError> {
    let slots = state.slots.all().await;

    let hmac_key = lease::load_hmac_key(&state.config.kms_volume)?;

    let (user_id, kms_pubkey, bundle_seq) = {
        let bundle_guard = state.auth_bundle.read().await;
        match bundle_guard.as_ref() {
            Some(b) => {
                let cid = b["user_id"].as_str().unwrap_or("").to_string();
                let kpk = b["kms_identity"]["k256_pubkey"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                let seq = b["bundle_seq"].as_u64().unwrap_or(0);
                (cid, kpk, seq)
            }
            None => ("".to_string(), "".to_string(), 0u64),
        }
    };

    let r = receipt::UsageReceipt::generate_with_bundle(
        user_id,
        kms_pubkey,
        slots,
        bundle_seq,
        &hmac_key,
    )?;
    Ok(Json(r))
}

fn load_existing_bundle(kms_volume: &std::path::Path) -> Option<serde_json::Value> {
    let path = kms_volume.join("auth_bundle.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

fn load_kms_ca_cert(kms_volume: &std::path::Path) -> Option<String> {
    let path = kms_volume.join("root-ca.crt");
    std::fs::read_to_string(&path).ok()
}
