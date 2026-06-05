// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0
//! dstack-lite-launcher — the KMS-less "on-prem-lite" launcher.
//!
//! Runs inside the workload CVM (TDX+vTPM). On boot it has NO license; it serves
//! a plain-HTTP courier API on LITE_PORT (default 9000), reachable through the
//! operator's IAP tunnel, and waits. The operator's CLI drives:
//!   challenge(authority) → courier/init(launcher) → license(authority) →
//!   courier/install(launcher).
//! On install the launcher verifies the License (Ed25519, seq, validity,
//! self-identity), HPKE-opens the CEK, decrypts + runs the workload, and arms an
//! expiry watchdog. Renewal/update = the same courier run again.

use std::sync::Arc;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use tokio::sync::{Mutex, RwLock};

mod cloud;
mod config;
mod courier;
mod crypto;
mod errors;
mod license;
mod runner;
mod state;

use state::{AppState, Phase};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 needs an explicit crypto provider for the guest-agent prpc client.
    rustls::crypto::ring::default_provider().install_default().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("dstack_lite_launcher=info".parse().unwrap()),
        )
        .init();

    let config = config::Config::from_env()?;
    let port = config.port;
    if config.authority_pubkey.is_empty() {
        // serve anyway (so the operator can observe /healthz), but every install
        // will fail-closed at G8 until a pubkey is pinned.
        tracing::warn!("LITE_AUTHORITY_PUBKEY is empty; installs will be refused (fail-closed)");
    }

    let state = Arc::new(AppState {
        transport_secret: RwLock::new(None),
        transport_pub: RwLock::new(None),
        config,
        phase: RwLock::new(Phase::Booting),
        installed: RwLock::new(None),
        last_error: RwLock::new(None),
        generation: Mutex::new(0),
    });

    // resume a persisted valid license (re-arm watchdog / mark Running) or move
    // to Waiting for the operator's courier install.
    license::resume(&state).await;

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/courier/init", post(courier::init))
        .route("/courier/install", post(courier::install))
        .route("/status", get(status))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("dstack-lite-launcher listening on port {} (plain http; iap tunnel is the channel)", port);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz(State(state): State<Arc<AppState>>) -> &'static str {
    state.phase.read().await.as_str()
}

#[derive(Serialize)]
struct StatusResp {
    app_id: String,
    compose_hash: String,
    workload_image: String,
    running_digest: String,
    license_seq: u64,
    expires_at: i64,
    workload_running: bool,
    last_error: Option<String>,
}

/// Read-only operational state — never returns the CEK, certs, keys, env, or
/// container logs. There is no introspection / file-read / exec endpoint here by
/// design.
async fn status(State(state): State<Arc<AppState>>) -> Json<StatusResp> {
    let installed = state.installed.read().await.clone();
    let last_error = state.last_error.read().await.clone();
    let workload_running = tokio::task::spawn_blocking(runner::is_workload_running)
        .await
        .unwrap_or(false);

    let (app_id, compose_hash, workload_image, running_digest, license_seq, expires_at) =
        match installed {
            Some(l) => (
                l.app_id,
                l.compose_hash,
                l.workload.image,
                l.workload.digest,
                l.seq,
                l.expires_at,
            ),
            None => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                0,
                0,
            ),
        };

    Json(StatusResp {
        app_id,
        compose_hash,
        workload_image,
        running_digest,
        license_seq,
        expires_at,
        workload_running,
        last_error,
    })
}
