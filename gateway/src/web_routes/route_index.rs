// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    admin_service::AdminRpcHandler,
    main_service::{Proxy, RpcHandler},
    models::Dashboard,
};
use anyhow::Context;
use dstack_gateway_rpc::gateway_server::GatewayRpc;
use ra_rpc::{CallContext, RpcCall};
use rinja::Template as _;
use rocket::{response::content::RawHtml as Html, State};

pub async fn index(state: &State<Proxy>) -> anyhow::Result<Html<String>> {
    let context = CallContext::builder().state(&**state).build();
    let rpc_handler =
        AdminRpcHandler::construct(context.clone()).context("Failed to construct RpcHandler")?;
    let status = rpc_handler.status().await.context("Failed to get status")?;
    let rpc_handler = RpcHandler::construct(context).context("Failed to construct RpcHandler")?;
    let acme_info = rpc_handler
        .acme_info()
        .await
        .context("Failed to get ACME info")?;
    let model = Dashboard { status, acme_info };
    let html = model.render().context("Failed to render template")?;
    Ok(Html(html))
}
