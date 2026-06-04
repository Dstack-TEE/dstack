// Minimal read-only status HTTP server — the SSH-free way to observe a workload
// CVM. It exposes ONLY non-sensitive operational state (image digest, lease
// active?, bundle_seq, workload running?, last-error category). It never returns
// the CEK, certs, keys, env, or container logs — there is no introspection,
// file-read, or exec endpoint here by design.
use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;
use std::sync::{Arc, Mutex};

use crate::runner;

#[derive(Clone)]
pub struct StatusState {
    pub app_id: String,
    pub workload_image: String,
    pub running_digest: Arc<Mutex<String>>,
    pub lease_id: Arc<Mutex<String>>,
    pub bundle_seq: Arc<Mutex<u64>>,
    pub last_error: Arc<Mutex<Option<String>>>,
}

#[derive(Serialize)]
struct StatusResp {
    app_id: String,
    workload_image: String,
    running_digest: String,
    lease_active: bool,
    bundle_seq: u64,
    workload_running: bool,
    last_error: Option<String>,
}

async fn status(State(s): State<StatusState>) -> Json<StatusResp> {
    let running_digest = s.running_digest.lock().unwrap().clone();
    let lease_active = !s.lease_id.lock().unwrap().is_empty();
    let bundle_seq = *s.bundle_seq.lock().unwrap();
    let last_error = s.last_error.lock().unwrap().clone();
    // is_workload_running shells out to `docker compose ps`; cheap enough for a
    // status poll, run on the blocking pool to keep the async runtime free.
    let workload_running = tokio::task::spawn_blocking(runner::is_workload_running)
        .await
        .unwrap_or(false);
    Json(StatusResp {
        app_id: s.app_id.clone(),
        workload_image: s.workload_image.clone(),
        running_digest,
        lease_active,
        bundle_seq,
        workload_running,
        last_error,
    })
}

async fn healthz() -> &'static str {
    "ok"
}

/// Serve `/status` + `/healthz` on `0.0.0.0:<port>` until the process exits.
pub async fn serve(state: StatusState, port: u16) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/status", get(status))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("status server listening on :{port} (/status, /healthz)");
    axum::serve(listener, app).await?;
    Ok(())
}
