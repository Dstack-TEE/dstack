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

pub fn routes() -> Vec<Route> {
    routes![index]
}

pub fn wavekv_routes() -> Vec<Route> {
    routes![
        wavekv_sync::sync_persistent,
        wavekv_sync::sync_ephemeral,
        wavekv_sync::status
    ]
}
