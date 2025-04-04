use std::convert::Infallible;

use anyhow::{Context, Result};
use ra_tls::{attestation::Attestation, traits::CertExt};
use rocket::{
    data::{ByteUnit, Data, Limits, ToByteUnit},
    http::{uri::Origin, ContentType, Method, Status},
    listener::Endpoint,
    mtls::Certificate,
    request::{FromRequest, Outcome},
    response::status::Custom,
    Request,
};
use rocket_vsock_listener::VsockEndpoint;
use tracing::warn;

use crate::{encode_error, CallContext, RemoteEndpoint, RpcCall};

#[derive(Debug, Clone)]
pub struct QuoteVerifier {
    pccs_url: Option<String>,
}

pub mod deps {
    pub use super::{PrpcHandler, RpcRequest};
    pub use rocket::response::status::Custom;
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
        ra_rpc::declare_prpc_routes!(prpc_post, prpc_get, $state, $handler);
        rocket::routes![prpc_post, prpc_get]
    }};
}

#[macro_export]
macro_rules! declare_prpc_routes {
    ($post:ident, $get:ident, $state:ty, $handler:ty) => {
        $crate::declare_prpc_routes!(path: "/<method>", $post, $get, $state, $handler);
    };
    (path: $path: literal, $post:ident, $get:ident, $state:ty, $handler:ty) => {
        #[rocket::post($path, data = "<data>")]
        async fn $post<'a: 'd, 'd>(
            state: &'a $crate::rocket_helper::deps::State<$state>,
            method: &'a str,
            rpc_request: $crate::rocket_helper::deps::RpcRequest<'a>,
            data: $crate::rocket_helper::deps::Data<'d>,
        ) -> $crate::rocket_helper::deps::Custom<Vec<u8>> {
            $crate::rocket_helper::deps::PrpcHandler::builder()
                .state(&**state)
                .request(rpc_request)
                .method(method)
                .data(data)
                .build()
                .handle::<$handler>()
                .await
        }

        #[rocket::get($path)]
        async fn $get(
            state: &$crate::rocket_helper::deps::State<$state>,
            method: &str,
            rpc_request: $crate::rocket_helper::deps::RpcRequest<'_>,
        ) -> $crate::rocket_helper::deps::Custom<Vec<u8>> {
            $crate::rocket_helper::deps::PrpcHandler::builder()
                .state(&**state)
                .request(rpc_request)
                .method(method)
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
        ) -> $crate::rocket_helper::deps::Custom<Vec<u8>> {
            $prpc(state, $method, rpc_request).await
        }
    };
    (post: $name:ident, $alias:literal -> $prpc:ident($method:literal, $state:ty)) => {
        #[rocket::post($alias, data = "<data>")]
        async fn $name<'a: 'd, 'd>(
            state: &'a $crate::rocket_helper::deps::State<$state>,
            rpc_request: $crate::rocket_helper::deps::RpcRequest<'a>,
            data: $crate::rocket_helper::deps::Data<'d>,
        ) -> $crate::rocket_helper::deps::Custom<Vec<u8>> {
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
        })
    }
}

impl<S> PrpcHandler<'_, '_, S> {
    pub async fn handle<Call: RpcCall<S>>(self) -> Custom<Vec<u8>> {
        let json = self.request.json;
        let result = handle_prpc_impl::<S, Call>(self).await;
        match result {
            Ok(output) => output,
            Err(e) => {
                let estr = format!("{e:?}");
                warn!("error handling prpc: {estr}");
                let body = encode_error(json, estr);
                Custom(Status::BadRequest, body)
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
) -> Result<Custom<Vec<u8>>> {
    let PrpcHandler {
        state,
        request,
        method,
        data,
    } = args;
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
    let is_get = data.is_none();
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
    let json = request.json || request.content_type.map(|t| t.is_json()).unwrap_or(false);
    let context = CallContext {
        state,
        attestation,
        remote_endpoint: request.remote_addr.cloned().map(RemoteEndpoint::from),
        remote_app_id,
    };
    let call = Call::construct(context).context("failed to construct call")?;
    let (status_code, output) = call.call(method.to_string(), payload, json, is_get).await;
    Ok(Custom(Status::new(status_code), output))
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
