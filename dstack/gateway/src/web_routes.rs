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

/// WaveKV sync endpoint (for main server, requires mTLS gateway auth)
pub fn wavekv_sync_routes() -> Vec<Route> {
    routes![
        wavekv_sync::sync_store,
        wavekv_sync::sync_store_v2,
        wavekv_sync::push_store
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The v1/v2 negotiation is driven entirely by whether a peer answers 404 on the v2
    /// route. A typo in any of these paths would therefore not fail — every peer would
    /// simply 404 forever and the whole cluster would stay silently on v1.
    #[test]
    fn the_sync_routes_are_mounted_where_peers_look_for_them() {
        let mounted: Vec<String> = wavekv_sync_routes()
            .iter()
            .map(|route| route.uri.to_string())
            .collect();

        for expected in [
            "/wavekv/sync/<store>",
            "/wavekv/sync2/<store>",
            "/wavekv/push/<store>",
        ] {
            assert!(
                mounted.iter().any(|uri| uri == expected),
                "{expected} is not mounted; peers would 404 and never negotiate v2. \
                 mounted: {mounted:?}"
            );
        }
    }
}
