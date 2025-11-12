// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;

#[cfg(all(feature = "rocket", feature = "openapi"))]
use crate::openapi::{OpenApiDoc, RenderedDoc};
#[cfg(all(feature = "rocket", feature = "openapi"))]
use rocket::response::content::{RawHtml, RawJson};
#[cfg(all(feature = "rocket", feature = "openapi"))]
use std::{borrow::Cow, sync::Arc};

use anyhow::{Context, Result};
use ra_tls::{attestation::Attestation, traits::CertExt};
use rocket::{
    data::{ByteUnit, Data, Limits, ToByteUnit},
    http::{uri::Origin, ContentType, Method, Status},
    listener::Endpoint,
    mtls::Certificate,
    request::{FromRequest, Outcome},
    response::{status::Custom, Responder},
    Request,
};
use rocket_vsock_listener::VsockEndpoint;
use tracing::warn;

use crate::{encode_error, CallContext, RemoteEndpoint, RpcCall};

pub struct RpcResponse {
    is_json: bool,
    status: Status,
    body: Vec<u8>,
}

impl<'r> Responder<'r, 'static> for RpcResponse {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        use rocket::http::ContentType;
        let content_type = if self.is_json {
            ContentType::JSON
        } else {
            ContentType::Binary
        };
        let response = Custom(self.status, self.body).respond_to(request)?;
        rocket::Response::build_from(response)
            .header(content_type)
            .ok()
    }
}

#[derive(Debug, Clone)]
pub struct QuoteVerifier {
    pccs_url: Option<String>,
}

pub mod deps {
    pub use super::{PrpcHandler, RpcRequest, RpcResponse};
    pub use rocket::{Data, State};
}

fn query_field_get_raw<'r>(req: &'r Request<'_>, field_name: &str) -> Option<&'r str> {
    for field in req.query_fields() {
        let key = field.name.key_lossy().as_str();
        if key == field_name {
            return Some(field.value);
        }
    }
    None
}

fn query_field_get_bool(req: &Request<'_>, field_name: &str) -> bool {
    matches!(
        query_field_get_raw(req, field_name),
        Some("true" | "1" | "")
    )
}

#[macro_export]
macro_rules! prpc_routes {
    ($state:ty, $handler:ty) => {{
        $crate::prpc_routes!($state, $handler, trim: "")
    }};
    ($state:ty, $handler:ty, trim: $trim_prefix:literal) => {{
        $crate::declare_prpc_routes!(prpc_post, prpc_get, $state, $handler, trim: $trim_prefix);
        rocket::routes![prpc_post, prpc_get]
    }};
}

#[macro_export]
macro_rules! declare_prpc_routes {
    ($post:ident, $get:ident, $state:ty, $handler:ty, trim: $trim_prefix:literal) => {
        $crate::declare_prpc_routes!(path: "/<method>", $post, $get, $state, $handler, trim: $trim_prefix);
    };
    (path: $path: literal, $post:ident, $get:ident, $state:ty, $handler:ty, trim: $trim_prefix:literal) => {
        fn next_req_id() -> u64 {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT_REQ_ID: AtomicU64 = AtomicU64::new(0);
            NEXT_REQ_ID.fetch_add(1, Ordering::Relaxed)
        }

        #[rocket::post($path, data = "<data>")]
        #[tracing::instrument(level = "INFO", skip_all, fields(id = next_req_id(), method = %method))]
        async fn $post<'a: 'd, 'd>(
            state: &'a $crate::rocket_helper::deps::State<$state>,
            method: &'a str,
            rpc_request: $crate::rocket_helper::deps::RpcRequest<'a>,
            data: $crate::rocket_helper::deps::Data<'d>,
        ) -> $crate::rocket_helper::deps::RpcResponse {
            $crate::rocket_helper::deps::PrpcHandler::builder()
                .state(&**state)
                .request(rpc_request)
                .method(method)
                .data(data)
                .method_trim_prefix($trim_prefix)
                .build()
                .handle::<$handler>()
                .await
        }

        #[rocket::get($path)]
        #[tracing::instrument(level = "INFO", skip_all, fields(id = next_req_id(), method = %method))]
        async fn $get(
            state: &$crate::rocket_helper::deps::State<$state>,
            method: &str,
            rpc_request: $crate::rocket_helper::deps::RpcRequest<'_>,
        ) -> $crate::rocket_helper::deps::RpcResponse {
            $crate::rocket_helper::deps::PrpcHandler::builder()
                .state(&**state)
                .request(rpc_request)
                .method(method)
                .method_trim_prefix($trim_prefix)
                .build()
                .handle::<$handler>()
                .await
        }
    };
}

#[macro_export]
macro_rules! prpc_alias {
    (get: $name:ident, $alias:literal -> $prpc:ident($method:literal, $state:ty)) => {
        #[rocket::get($alias)]
        async fn $name(
            state: &$crate::rocket_helper::deps::State<$state>,
            rpc_request: $crate::rocket_helper::deps::RpcRequest<'_>,
        ) -> $crate::rocket_helper::deps::RpcResponse {
            $prpc(state, $method, rpc_request).await
        }
    };
    (post: $name:ident, $alias:literal -> $prpc:ident($method:literal, $state:ty)) => {
        #[rocket::post($alias, data = "<data>")]
        async fn $name<'a: 'd, 'd>(
            state: &'a $crate::rocket_helper::deps::State<$state>,
            rpc_request: $crate::rocket_helper::deps::RpcRequest<'a>,
            data: $crate::rocket_helper::deps::Data<'d>,
        ) -> $crate::rocket_helper::deps::RpcResponse {
            $prpc(state, $method, rpc_request, data).await
        }
    };
}

macro_rules! from_request {
    ($request:expr) => {
        match FromRequest::from_request($request).await {
            Outcome::Success(v) => v,
            Outcome::Error(e) => return Outcome::Error(e),
            Outcome::Forward(f) => return Outcome::Forward(f),
        }
    };
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for &'r QuoteVerifier {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(state) = rocket::State::<QuoteVerifier>::get(request.rocket()) else {
            return Outcome::Error((Status::InternalServerError, ()));
        };
        Outcome::Success(state)
    }
}

impl QuoteVerifier {
    pub fn new(pccs_url: Option<String>) -> Self {
        Self { pccs_url }
    }
}

async fn read_data(data: Data<'_>, limit: ByteUnit) -> Result<Vec<u8>> {
    let stream = data.open(limit);
    let data = stream.into_bytes().await.context("failed to read data")?;
    if !data.is_complete() {
        anyhow::bail!("payload too large");
    }
    Ok(data.into_inner())
}

fn limit_for_method(method: &str, limits: &Limits) -> ByteUnit {
    if let Some(v) = limits.get(method) {
        return v;
    }
    10.mebibytes()
}

#[derive(bon::Builder)]
pub struct PrpcHandler<'s, 'r, S> {
    state: &'s S,
    request: RpcRequest<'r>,
    method: &'r str,
    method_trim_prefix: Option<&'r str>,
    data: Option<Data<'r>>,
}

pub struct RpcRequest<'r> {
    remote_addr: Option<&'r Endpoint>,
    certificate: Option<Certificate<'r>>,
    quote_verifier: Option<&'r QuoteVerifier>,
    origin: &'r Origin<'r>,
    limits: &'r Limits,
    content_type: Option<&'r ContentType>,
    json: bool,
    is_get: bool,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RpcRequest<'r> {
    type Error = Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Self {
            remote_addr: from_request!(request),
            certificate: from_request!(request),
            quote_verifier: from_request!(request),
            origin: from_request!(request),
            limits: from_request!(request),
            content_type: from_request!(request),
            json: request.method() == Method::Get || query_field_get_bool(request, "json"),
            is_get: request.method() == Method::Get,
        })
    }
}

impl<S> PrpcHandler<'_, '_, S> {
    pub async fn handle<Call: RpcCall<S>>(self) -> RpcResponse {
        let json = self.request.json;
        let result = handle_prpc_impl::<S, Call>(self).await;
        match result {
            Ok(output) => output,
            Err(e) => {
                let estr = format!("{e:?}");
                warn!("error handling prpc: {estr}");
                let body = encode_error(json, estr);
                RpcResponse {
                    is_json: json,
                    status: Status::BadRequest,
                    body,
                }
            }
        }
    }
}

impl From<Endpoint> for RemoteEndpoint {
    fn from(endpoint: Endpoint) -> Self {
        match endpoint {
            Endpoint::Tcp(addr) => RemoteEndpoint::Tcp(addr),
            Endpoint::Quic(addr) => RemoteEndpoint::Quic(addr),
            Endpoint::Unix(path) => RemoteEndpoint::Unix(path),
            _ => {
                let address = endpoint.to_string();
                match address.parse::<VsockEndpoint>() {
                    Ok(addr) => RemoteEndpoint::Vsock {
                        cid: addr.cid,
                        port: addr.port,
                    },
                    Err(_) => RemoteEndpoint::Other(address),
                }
            }
        }
    }
}

pub async fn handle_prpc_impl<S, Call: RpcCall<S>>(
    args: PrpcHandler<'_, '_, S>,
) -> Result<RpcResponse> {
    let PrpcHandler {
        state,
        request,
        method,
        method_trim_prefix,
        data,
    } = args;
    let method = method.trim_start_matches(method_trim_prefix.unwrap_or_default());
    let remote_app_id = request
        .certificate
        .as_ref()
        .map(|cert| RocketCertificate(cert).get_app_id())
        .transpose()?
        .flatten();
    let attestation = request
        .certificate
        .as_ref()
        .map(|cert| Attestation::from_der(cert.as_bytes()))
        .transpose()?
        .flatten();
    let attestation = match (request.quote_verifier, attestation) {
        (Some(quote_verifier), Some(attestation)) => {
            let pubkey = request
                .certificate
                .expect("certificate is missing")
                .public_key()
                .raw
                .to_vec();
            let verified = attestation
                .verify_with_ra_pubkey(&pubkey, quote_verifier.pccs_url.as_deref())
                .await
                .context("invalid quote")?;
            Some(verified)
        }
        _ => None,
    };
    let payload = match data {
        Some(data) => {
            let limit = limit_for_method(method, request.limits);
            read_data(data, limit)
                .await
                .context("failed to read data")?
        }
        None => request
            .origin
            .query()
            .map_or(vec![], |q| q.as_bytes().to_vec()),
    };
    let is_json = request.json || request.content_type.map(|t| t.is_json()).unwrap_or(false);
    let context = CallContext {
        state,
        attestation,
        remote_endpoint: request.remote_addr.cloned().map(RemoteEndpoint::from),
        remote_app_id,
    };
    let call = Call::construct(context).context("failed to construct call")?;
    let (status_code, output) = call
        .call(method.to_string(), payload, is_json, request.is_get)
        .await;
    Ok(RpcResponse {
        is_json,
        status: Status::new(status_code),
        body: output,
    })
}

struct RocketCertificate<'a>(&'a rocket::mtls::Certificate<'a>);

impl CertExt for RocketCertificate<'_> {
    fn get_extension_der(&self, oid: &[u64]) -> Result<Option<Vec<u8>>> {
        let oid = x509_parser::der_parser::Oid::from(oid)
            .ok()
            .context("invalid oid")?;
        let Some(ext) = self.0.extensions().iter().find(|ext| ext.oid == oid) else {
            return Ok(None);
        };
        Ok(Some(ext.value.to_vec()))
    }
}

#[cfg(all(feature = "rocket", feature = "openapi"))]
#[derive(Clone)]
struct OpenApiState {
    spec_json: Arc<String>,
    ui_html: Arc<String>,
}

#[cfg(all(feature = "rocket", feature = "openapi"))]
impl From<RenderedDoc> for OpenApiState {
    fn from(doc: RenderedDoc) -> Self {
        Self {
            spec_json: doc.spec.clone(),
            ui_html: Arc::new(doc.ui_html),
        }
    }
}

#[cfg(all(feature = "rocket", feature = "openapi"))]
#[rocket::get("/openapi.json")]
fn openapi_spec(state: &rocket::State<OpenApiState>) -> RawJson<String> {
    RawJson((*state.spec_json).clone())
}

#[cfg(all(feature = "rocket", feature = "openapi"))]
#[rocket::get("/docs")]
fn openapi_docs(state: &rocket::State<OpenApiState>) -> RawHtml<String> {
    RawHtml((*state.ui_html).clone())
}

#[cfg(all(feature = "rocket", feature = "openapi"))]
pub fn mount_openapi_docs(
    rocket: rocket::Rocket<rocket::Build>,
    doc: OpenApiDoc,
    mount_path: impl Into<Cow<'static, str>>,
) -> rocket::Rocket<rocket::Build> {
    let base = normalize_openapi_mount(mount_path.into());
    let spec_url = join_mount_path(base.as_ref(), "openapi.json");
    let rendered = doc.render(&spec_url);
    let state = OpenApiState::from(rendered);
    let mount_point = base.clone().into_owned();
    rocket
        .manage(state)
        .mount(mount_point, rocket::routes![openapi_spec, openapi_docs])
}

#[cfg(all(feature = "rocket", feature = "openapi"))]
fn normalize_openapi_mount(path: Cow<'static, str>) -> Cow<'static, str> {
    let mut owned = path.into_owned();
    if owned.is_empty() {
        owned.push('/');
    }
    if !owned.starts_with('/') {
        owned.insert(0, '/');
    }
    if owned.len() > 1 && owned.ends_with('/') {
        owned.pop();
    }
    Cow::Owned(if owned.is_empty() { "/".into() } else { owned })
}

#[cfg(all(feature = "rocket", feature = "openapi"))]
fn join_mount_path(base: &str, segment: &str) -> String {
    if base == "/" {
        format!("/{}", segment.trim_start_matches('/'))
    } else {
        format!(
            "{}/{}",
            base.trim_end_matches('/'),
            segment.trim_start_matches('/')
        )
    }
}
