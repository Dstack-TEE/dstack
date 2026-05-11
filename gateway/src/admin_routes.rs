// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use ra_rpc::rocket_helper::deps::{Data, PrpcHandler, RpcRequest, RpcResponse, State};
use rocket::{get, post, routes, Route};

use crate::{admin_auth::AdminAuthorized, admin_service::AdminRpcHandler, main_service::Proxy};

fn next_req_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_REQ_ID: AtomicU64 = AtomicU64::new(0);
    NEXT_REQ_ID.fetch_add(1, Ordering::Relaxed)
}

#[post("/<method>", data = "<data>")]
#[tracing::instrument(level = "INFO", skip_all, fields(id = next_req_id(), method = %method))]
async fn admin_prpc_post<'a: 'd, 'd>(
    _auth: AdminAuthorized,
    state: &'a State<Proxy>,
    method: &'a str,
    rpc_request: RpcRequest<'a>,
    data: Data<'d>,
) -> RpcResponse {
    PrpcHandler::builder()
        .state(&**state)
        .request(rpc_request)
        .method(method)
        .data(data)
        .method_trim_prefix("Admin.")
        .build()
        .handle::<AdminRpcHandler>()
        .await
}

#[get("/<method>")]
#[tracing::instrument(level = "INFO", skip_all, fields(id = next_req_id(), method = %method))]
async fn admin_prpc_get(
    _auth: AdminAuthorized,
    state: &State<Proxy>,
    method: &str,
    rpc_request: RpcRequest<'_>,
) -> RpcResponse {
    PrpcHandler::builder()
        .state(&**state)
        .request(rpc_request)
        .method(method)
        .method_trim_prefix("Admin.")
        .build()
        .handle::<AdminRpcHandler>()
        .await
}

pub fn routes() -> Vec<Route> {
    routes![admin_prpc_post, admin_prpc_get]
}
