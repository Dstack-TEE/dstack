// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::main_service::Proxy;
use anyhow::Result;
use rocket::{get, response::content::RawHtml, response::content::RawText, routes, Route, State};

mod metrics;
mod route_index;
mod wavekv_sync;

#[get("/")]
async fn index(state: &State<Proxy>) -> Result<RawHtml<String>, String> {
    route_index::index(state).await.map_err(|e| format!("{e}"))
}

/// Prometheus scrape endpoint.
///
/// Mounted on the admin listener only: the series below name domains, node ids
/// and instance counts, which is topology no unauthenticated caller should be
/// able to read.
#[get("/metrics")]
fn scrape(state: &State<Proxy>) -> RawText<String> {
    RawText(metrics::render(state))
}

#[get("/health")]
fn health() -> &'static str {
    "OK"
}

pub fn routes() -> Vec<Route> {
    routes![index, scrape]
}

/// Health endpoint for simple liveness checks
pub fn health_routes() -> Vec<Route> {
    routes![health]
}

/// WaveKV sync endpoint (for main server, requires mTLS gateway auth)
pub fn wavekv_sync_routes() -> Vec<Route> {
    routes![wavekv_sync::sync_store]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scrape output names domains, node ids and instance counts, so `/metrics`
    /// must be part of the authenticated admin route set (`routes()`) and must not
    /// be included in the route sets intended for non-admin listeners.
    ///
    /// This test checks the route-set membership only; it does not inspect Rocket
    /// listener wiring in `main.rs`.
    #[test]
    fn metrics_is_mounted_on_the_admin_listener_only() {
        let mounted = |set: Vec<Route>| set.iter().any(|route| route.uri.path() == "/metrics");
        assert!(mounted(routes()));
        assert!(!mounted(health_routes()));
        assert!(!mounted(wavekv_sync_routes()));
    }
}
