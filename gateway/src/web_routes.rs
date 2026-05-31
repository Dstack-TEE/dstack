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
    routes![wavekv_sync::sync_store]
}
