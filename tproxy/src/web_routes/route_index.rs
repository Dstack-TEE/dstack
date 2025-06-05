use crate::{
    admin_service::AdminRpcHandler,
    main_service::{Proxy, RpcHandler},
    models::CvmList,
};
use anyhow::Context;
use ra_rpc::{CallContext, RpcCall};
use rinja::Template as _;
use rocket::{response::content::RawHtml as Html, State};
use tproxy_rpc::tproxy_server::TproxyRpc;

pub async fn index(state: &State<Proxy>) -> anyhow::Result<Html<String>> {
    let context = CallContext::builder().state(&**state).build();
    let rpc_handler =
        AdminRpcHandler::construct(context.clone()).context("Failed to construct RpcHandler")?;
    let response = rpc_handler.list().await.context("Failed to list hosts")?;
    let rpc_handler = RpcHandler::construct(context).context("Failed to construct RpcHandler")?;
    let acme_info = rpc_handler
        .acme_info()
        .await
        .context("Failed to get ACME info")?;
    let model = CvmList {
        hosts: &response.hosts,
        acme_info: &acme_info,
    };
    let html = model.render().context("Failed to render template")?;
    Ok(Html(html))
}
