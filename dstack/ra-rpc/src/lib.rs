#![allow(async_fn_in_trait)]

// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{fmt::Display, net::SocketAddr, path::PathBuf};

use anyhow::Result;
use prpc::{codec::encode_message_to_vec, server::Service as PrpcService};
use ra_tls::attestation::AppInfo;
use tracing::{error, info};

pub use ra_tls::attestation::{Attestation, VerifiedAttestation};

#[cfg(feature = "rocket")]
pub mod rocket_helper;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "openapi")]
pub mod openapi;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixPeerCred {
    /// Peer process ID (platform-independent representation)
    pub pid: u64,
    /// Peer user ID
    pub uid: u64,
    /// Peer group ID
    pub gid: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEndpoint {
    Tcp(SocketAddr),
    Quic(SocketAddr),
    /// Unix domain socket endpoint.
    ///
    /// When available, `peer` can carry SO_PEERCRED (pid/uid/gid) of the caller.
    Unix {
        path: PathBuf,
        peer: Option<UnixPeerCred>,
    },
    Vsock {
        cid: u32,
        port: u32,
    },
    Other(String),
}

#[derive(Clone, bon::Builder)]
pub struct CallContext<'a, State> {
    pub state: &'a State,
    pub attestation: Option<VerifiedAttestation>,
    pub remote_endpoint: Option<RemoteEndpoint>,
    pub remote_app_id: Option<Vec<u8>>,
    pub remote_app_info: Option<AppInfo>,
}

/// An RPC error carrying a status code, so a failure can be reported as
/// something more specific than a generic bad request.
///
/// `Display` and `source` delegate to the inner error, so attaching a code
/// leaves the rendered error message byte-for-byte unchanged.
#[derive(Debug)]
pub struct CodedError {
    code: u16,
    inner: anyhow::Error,
}

impl CodedError {
    pub fn code(&self) -> u16 {
        self.code
    }
}

impl Display for CodedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl std::error::Error for CodedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

/// Attach a status code to an error.
pub trait ErrorExt {
    fn with_code(self, code: u16) -> anyhow::Error;
}

impl<E: Into<anyhow::Error>> ErrorExt for E {
    fn with_code(self, code: u16) -> anyhow::Error {
        anyhow::Error::new(CodedError {
            code,
            inner: self.into(),
        })
    }
}

/// Attach a status code to the error of a `Result`.
pub trait ResultExt<T> {
    fn with_code(self, code: u16) -> Result<T>;
}

impl<T, E: Into<anyhow::Error>> ResultExt<T> for std::result::Result<T, E> {
    fn with_code(self, code: u16) -> Result<T> {
        self.map_err(|e| ErrorExt::with_code(e, code))
    }
}

/// Extract the status code attached to `err`, if any.
///
/// Walks the whole error chain and returns the outermost code, so a code
/// survives `.context(..)` layers and foreign error types wrapped around it.
/// `anyhow::Error::downcast_ref` alone is not enough: it only follows anyhow's
/// own context chain and stops at the first foreign error type, which would
/// silently drop a code buried under, say, a `thiserror` wrapper.
///
/// The outermost code wins: the layer closest to the caller has the most
/// context about how the failure should be reported.
pub fn code_of(err: &anyhow::Error) -> Option<u16> {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<CodedError>())
        .map(CodedError::code)
        .next()
}

/// Whether `method` is one the service actually implements.
///
/// `prpc-build` generates the method table and the dispatcher's match arms from
/// the same list, so this answers exactly what the dispatcher would accept.
fn is_known_method<S: PrpcService>(method: &str) -> bool {
    S::methods().as_ref().contains(&method)
}

/// Status code reported for an error that carries no code of its own.
pub const CODE_BAD_REQUEST: u16 = 400;
/// Status code reported when a requested method does not exist.
pub const CODE_NOT_FOUND: u16 = 404;
/// Status code reported when the request body exceeds the configured limit.
pub const CODE_PAYLOAD_TOO_LARGE: u16 = 413;

pub trait RpcCall<State>: Sized {
    type PrpcService: PrpcService + From<Self> + Send + 'static;

    fn construct(context: CallContext<'_, State>) -> Result<Self>;

    async fn call(
        self,
        method: String,
        payload: Vec<u8>,
        is_json: bool,
        is_query: bool,
    ) -> (u16, Vec<u8>) {
        let (code, body) = dispatch_prpc(
            &method,
            payload,
            is_json,
            is_query,
            <Self::PrpcService as From<Self>>::from(self),
        )
        .await;
        // The dispatcher reports an unknown method as an ordinary error, so it
        // arrives here as a generic bad request. Only that case needs refining,
        // so the method table is consulted lazily: a successful call, or a
        // failure the service chose a code for, never pays for the lookup. The
        // dispatcher's own message is reused verbatim rather than rebuilt here.
        if code == CODE_BAD_REQUEST && !is_known_method::<Self::PrpcService>(&method) {
            return (CODE_NOT_FOUND, body);
        }
        (code, body)
    }
}

async fn dispatch_prpc(
    path: &str,
    data: Vec<u8>,
    json: bool,
    query: bool,
    server: impl PrpcService + Send + 'static,
) -> (u16, Vec<u8>) {
    info!("dispatching request: {path}");
    let result = server.dispatch_request(path, data, json, query).await;
    let (code, data) = match result {
        Ok(data) => (200, data),
        Err(err) => {
            error!("rpc error: {err:?}");
            // Services can attach a status code to their error; anything that
            // does not is reported as a generic bad request, as before.
            let code = code_of(&err).unwrap_or(CODE_BAD_REQUEST);
            (code, encode_error(json, &err))
        }
    };
    (code, data)
}

pub fn encode_error(json: bool, error: &impl Display) -> Vec<u8> {
    let error = format!("{error:#}");
    if json {
        serde_json::to_string_pretty(&serde_json::json!({ "error": error }))
            .unwrap_or_else(|_| r#"{"error": "failed to encode the error"}"#.to_string())
            .into_bytes()
    } else {
        encode_message_to_vec(&::prpc::server::ProtoError::new(error))
    }
}

#[cfg(test)]
mod coded_error_tests {
    use super::{code_of, ErrorExt, ResultExt};
    use anyhow::{anyhow, Context, Error};

    /// A foreign error type that keeps its source in the chain, like `thiserror`.
    #[derive(Debug)]
    struct Wrapper(Error);

    impl std::fmt::Display for Wrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "wrapper")
        }
    }

    impl std::error::Error for Wrapper {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    #[test]
    fn attaching_a_code_leaves_the_message_unchanged() {
        let plain = anyhow!("something went wrong");
        let coded = anyhow!("something went wrong").with_code(403);
        assert_eq!(format!("{plain}"), format!("{coded}"));
        assert_eq!(format!("{plain:#}"), format!("{coded:#}"));
    }

    #[test]
    fn an_error_without_a_code_reports_none() {
        assert_eq!(code_of(&anyhow!("boom")), None);
    }

    #[test]
    fn a_code_can_be_attached_to_a_result() {
        let err = Err::<(), _>(anyhow!("bad body"))
            .with_code(400)
            .unwrap_err();
        assert_eq!(code_of(&err), Some(400));
    }

    #[test]
    fn a_code_is_found_through_many_context_layers() {
        let err = Err::<(), _>(anyhow!("db down").with_code(503))
            .context("a")
            .context("b")
            .context("c")
            .unwrap_err();
        assert_eq!(code_of(&err), Some(503));
        assert_eq!(format!("{err:#}"), "c: b: a: db down");
    }

    #[test]
    fn a_code_is_found_under_a_foreign_error_type() {
        // This is the case a bare `downcast_ref::<CodedError>()` misses, because
        // anyhow stops walking at the first foreign error type.
        let err = Error::new(Wrapper(anyhow!("db down").with_code(503)));
        assert_eq!(code_of(&err), Some(503));
    }

    #[test]
    fn a_code_is_found_under_a_foreign_error_type_plus_context() {
        let err = Err::<(), _>(Error::new(Wrapper(anyhow!("db down").with_code(503))))
            .context("outer")
            .unwrap_err();
        assert_eq!(code_of(&err), Some(503));
    }

    #[test]
    fn the_outermost_code_wins() {
        assert_eq!(
            code_of(&anyhow!("db down").with_code(503).with_code(404)),
            Some(404)
        );
        let err = Err::<(), _>(anyhow!("db down").with_code(503))
            .context("mid")
            .unwrap_err()
            .with_code(404);
        assert_eq!(code_of(&err), Some(404));
    }

    #[test]
    fn a_code_survives_a_question_mark_boundary() {
        fn inner() -> anyhow::Result<()> {
            Err(anyhow!("db down").with_code(503))
        }
        fn outer() -> anyhow::Result<()> {
            inner().context("outer failed")?;
            Ok(())
        }
        let err = outer().unwrap_err();
        assert_eq!(code_of(&err), Some(503));
        assert_eq!(format!("{err:#}"), "outer failed: db down");
    }
}
