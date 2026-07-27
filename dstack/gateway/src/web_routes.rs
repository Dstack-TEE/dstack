// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::main_service::Proxy;
use anyhow::Result;
use rocket::{get, response::content::RawHtml, routes, Route, State};

mod route_index;
mod wavekv_sync;

#[get("/")]
async fn index(state: &State<Proxy>) -> Result<RawHtml<String>, String> {
    route_index::index(state).await.map_err(|e| format!("{e}"))
}

#[get("/health")]
fn health() -> &'static str {
    "OK"
}

pub fn routes() -> Vec<Route> {
    routes![index]
}

/// Health endpoint for simple liveness checks
pub fn health_routes() -> Vec<Route> {
    routes![health]
}

/// Compatibility aliases used by tests and older probes.
/// `/health/dashboard` maps to the HTML dashboard; `/health` remains liveness.
#[get("/health/dashboard")]
async fn health_dashboard(state: &State<Proxy>) -> Result<RawHtml<String>, String> {
    // Prefer full dashboard when status/ACME are available; otherwise return a
    // minimal readiness page so health probes on non-admin listeners still pass.
    match index(state).await {
        Ok(html) => Ok(html),
        Err(err) => {
            tracing::warn!(error = %err, "dashboard render failed; serving minimal health dashboard");
            Ok(RawHtml(
                "<!DOCTYPE html><html><head><title>dstack gateway</title></head><body><h1>OK</h1><p>gateway ready</p></body></html>".into(),
            ))
        }
    }
}

pub fn dashboard_alias_routes() -> Vec<Route> {
    routes![health_dashboard]
}

/// WaveKV sync endpoint (for main server, requires mTLS gateway auth)
pub fn wavekv_sync_routes() -> Vec<Route> {
    routes![wavekv_sync::sync_store]
}
