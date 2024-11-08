use crate::main_service::{AppState, RpcHandler};
use anyhow::Result;
use ra_rpc::rocket_helper::{handle_prpc, QuoteVerifier};
use rocket::{
    data::{Data, Limits},
    get,
    http::ContentType,
    mtls::Certificate,
    post,
    response::{content::RawHtml, status::Custom},
    routes, Route, State,
};

mod route_index;

#[get("/")]
async fn index(state: &State<AppState>) -> Result<RawHtml<String>, String> {
    route_index::index(state).await.map_err(|e| format!("{e}"))
}

#[post("/prpc/<method>?<json>", data = "<data>")]
async fn prpc_post(
    state: &State<AppState>,
    cert: Option<Certificate<'_>>,
    quote_verifier: Option<&State<QuoteVerifier>>,
    method: &str,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, RpcHandler>(
        &*state,
        cert,
        quote_verifier.map(|v| &**v),
        method,
        Some(data),
        limits,
        content_type,
        json,
    )
    .await
    .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

#[get("/prpc/<method>")]
async fn prpc_get(
    state: &State<AppState>,
    cert: Option<Certificate<'_>>,
    quote_verifier: Option<&State<QuoteVerifier>>,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, RpcHandler>(
        &*state,
        cert,
        quote_verifier.map(|v| &**v),
        method,
        None,
        limits,
        content_type,
        true,
    )
    .await
    .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

pub fn routes() -> Vec<Route> {
    routes![index, prpc_post, prpc_get]
}
