// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! End-to-end coverage for the status code an RPC failure is reported with.
//!
//! The service is hand-written rather than generated so the test needs no
//! `.proto` and no build script. It mirrors what `prpc-build` emits: a
//! `methods()` table, and a `dispatch_request` whose fallback arm reports an
//! unknown method as an ordinary error.

use anyhow::{anyhow, Context, Result};
use ra_rpc::{CallContext, ErrorExt, RpcCall};
use rocket::local::asynchronous::Client;

/// A foreign error type that keeps its source in the chain, like `thiserror`.
#[derive(Debug)]
struct ForeignError(anyhow::Error);

impl std::fmt::Display for ForeignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "storage layer failed")
    }
}

impl std::error::Error for ForeignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[derive(Clone, Default)]
struct AppState;

struct DemoHandler;

struct DemoServer(#[allow(dead_code)] DemoHandler);

impl From<DemoHandler> for DemoServer {
    fn from(handler: DemoHandler) -> Self {
        Self(handler)
    }
}

impl prpc::server::Service for DemoServer {
    type Methods = &'static [&'static str];

    fn methods() -> Self::Methods {
        &[
            "Echo",
            "PlainFail",
            "Forbidden",
            "Unavailable",
            "DeeplyBuried",
        ]
    }

    async fn dispatch_request(
        self,
        path: &str,
        data: impl AsRef<[u8]>,
        _json: bool,
        _query: bool,
    ) -> Result<Vec<u8>, prpc::server::Error> {
        match path {
            "Echo" => {
                // Decoding the payload is what turns a malformed body into a
                // generic bad request, exactly as the generated code does.
                let value: serde_json::Value = serde_json::from_slice(data.as_ref())?;
                Ok(serde_json::to_vec(&value)?)
            }
            "PlainFail" => Err(anyhow!("something went wrong")),
            "Forbidden" => Err(anyhow!("caller is not authorized").with_code(403)),
            // The code is attached at the bottom and wrapped in context on the
            // way out; it still has to reach the transport.
            "Unavailable" => Err(anyhow!("db down").with_code(503)).context("load app"),
            // The worst case: a code buried under a foreign error type and
            // three context layers.
            "DeeplyBuried" => Err(anyhow::Error::new(ForeignError(
                anyhow!("no such app").with_code(404),
            )))
            .context("lookup app")
            .context("handle request")
            .context("serve"),
            _ => anyhow::bail!("Service not found: {path}"),
        }
    }
}

impl RpcCall<AppState> for DemoHandler {
    type PrpcService = DemoServer;

    fn construct(_context: CallContext<'_, AppState>) -> Result<Self> {
        Ok(DemoHandler)
    }
}

async fn client() -> Client {
    let rocket = rocket::build().manage(AppState).mount(
        "/",
        ra_rpc::prpc_routes!(AppState, DemoHandler, trim: "Demo."),
    );
    Client::tracked(rocket)
        .await
        .expect("failed to build the test client")
}

async fn post(client: &Client, path: &str, body: &str) -> (u16, String) {
    let response = client
        .post(format!("/{path}?json"))
        .body(body.to_string())
        .dispatch()
        .await;
    let status = response.status().code;
    let text = response.into_string().await.unwrap_or_default();
    (status, text)
}

#[tokio::test]
async fn a_successful_call_is_reported_as_ok() {
    let client = client().await;
    let (status, body) = post(&client, "Demo.Echo", r#"{"text":"hello"}"#).await;
    assert_eq!(status, 200);
    assert_eq!(body, r#"{"text":"hello"}"#);
}

#[tokio::test]
async fn an_unknown_method_is_reported_as_not_found() {
    let client = client().await;
    let (status, body) = post(&client, "Demo.NoSuchMethod", "{}").await;
    assert_eq!(status, 404);
    // The dispatcher's own message is reused rather than rebuilt.
    assert!(body.contains("Service not found: NoSuchMethod"), "{body}");
}

#[tokio::test]
async fn a_malformed_body_is_reported_as_a_bad_request() {
    let client = client().await;
    let (status, _) = post(&client, "Demo.Echo", "{not json").await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn an_error_without_a_code_is_reported_as_a_bad_request() {
    let client = client().await;
    let (status, body) = post(&client, "Demo.PlainFail", "{}").await;
    assert_eq!(status, 400);
    assert!(body.contains("something went wrong"), "{body}");
}

#[tokio::test]
async fn a_service_can_choose_the_status_code() {
    let client = client().await;
    let (status, body) = post(&client, "Demo.Forbidden", "{}").await;
    assert_eq!(status, 403);
    assert!(body.contains("caller is not authorized"), "{body}");
}

#[tokio::test]
async fn a_code_survives_a_context_layer() {
    let client = client().await;
    let (status, body) = post(&client, "Demo.Unavailable", "{}").await;
    assert_eq!(status, 503);
    // The message reads as if no code had been attached at all.
    assert!(body.contains("load app: db down"), "{body}");
    assert!(!body.contains("503"), "{body}");
}

#[tokio::test]
async fn a_code_survives_a_foreign_error_type_and_several_context_layers() {
    let client = client().await;
    let (status, body) = post(&client, "Demo.DeeplyBuried", "{}").await;
    assert_eq!(status, 404);
    assert!(
        body.contains("serve: handle request: lookup app: storage layer failed: no such app"),
        "{body}"
    );
}

#[tokio::test]
async fn a_body_over_the_limit_is_reported_as_payload_too_large() {
    // `limit_for_method` looks the limit up by method name.
    let figment = rocket::Config::figment().merge((
        "limits",
        rocket::data::Limits::default().limit("Echo", rocket::data::ToByteUnit::bytes(8u64)),
    ));
    let rocket = rocket::custom(figment).manage(AppState).mount(
        "/",
        ra_rpc::prpc_routes!(AppState, DemoHandler, trim: "Demo."),
    );
    let client = Client::tracked(rocket)
        .await
        .expect("failed to build the test client");

    let oversized = format!(r#"{{"text":"{}"}}"#, "x".repeat(64));
    let (status, body) = post(&client, "Demo.Echo", &oversized).await;
    assert_eq!(status, 413, "{body}");
    assert!(body.contains("payload too large"), "{body}");

    // A body within the limit still succeeds.
    let (status, _) = post(&client, "Demo.Echo", "{}").await;
    assert_eq!(status, 200);
}
