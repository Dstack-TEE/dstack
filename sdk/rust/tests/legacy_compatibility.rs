// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Compatibility with legacy agents that ignore unknown request fields.
#![allow(deprecated)]

use std::sync::mpsc::{channel, Receiver};

use axum::{body::Bytes, routing::post, Router};
use dstack_sdk::dstack_client_v0::{DstackClientV0, TlsKeyConfig};
use dstack_sdk::tappd_client::TappdClient;
use http::{StatusCode, Uri};
use serde_json::{json, Value};
use tokio::net::TcpListener;

async fn agent(
    reply: impl Fn(&str) -> (StatusCode, Value) + Clone + Send + Sync + 'static,
) -> (String, Receiver<(String, Value)>) {
    let (tx, requests) = channel();
    let routes = Router::new().fallback(post(move |uri: Uri, body: Bytes| {
        let path = uri.path();
        tx.send((path.to_owned(), serde_json::from_slice(&body).unwrap()))
            .unwrap();
        let (status, payload) = reply(path);
        async move { (status, payload.to_string()) }
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
    (endpoint, requests)
}

fn key_agent(path: &str) -> (StatusCode, Value) {
    match path {
        "/GetKey" => (StatusCode::OK, json!({"key":"ab", "signature_chain":[]})),
        "/GetTlsKey" => (StatusCode::OK, json!({"key":"pem", "certificate_chain":[]})),
        _ => (StatusCode::NOT_FOUND, json!({"error":"unknown method"})),
    }
}

#[tokio::test]
async fn default_v0_requests_work_without_version() {
    let (endpoint, requests) = agent(key_agent).await;
    let client = DstackClientV0::new(Some(&endpoint));
    assert_eq!(client.get_key(None, None).await.unwrap().key, "ab");
    for alias in ["", "k256", "secp256k1"] {
        assert_eq!(
            client
                .get_key_with_algorithm(None, None, alias)
                .await
                .unwrap()
                .key,
            "ab"
        );
    }
    assert_eq!(
        client
            .get_tls_key(TlsKeyConfig::builder().build())
            .await
            .unwrap()
            .key,
        "pem"
    );
    let paths: Vec<_> = requests.try_iter().map(|(path, _)| path).collect();
    assert_eq!(
        paths,
        ["/GetKey", "/GetKey", "/GetKey", "/GetKey", "/GetTlsKey"]
    );
}

#[tokio::test]
async fn available_version_allows_nondefault_fields_even_with_an_opaque_version_string() {
    let (endpoint, requests) = agent(|path| match path {
        "/Version" => (StatusCode::OK, json!({"version":"unknown", "rev":"dev"})),
        _ => key_agent(path),
    })
    .await;
    let client = DstackClientV0::new(Some(&endpoint));
    assert_eq!(
        client
            .get_key_with_algorithm(None, None, "ed25519")
            .await
            .unwrap()
            .key,
        "ab"
    );
    let config = TlsKeyConfig::builder()
        .not_before(10)
        .not_after(20)
        .with_app_info(true)
        .build();
    assert_eq!(client.get_tls_key(config).await.unwrap().key, "pem");
    let calls: Vec<_> = requests.try_iter().collect();
    let paths: Vec<_> = calls.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(paths, ["/Version", "/GetKey", "/Version", "/GetTlsKey"]);
    assert_eq!(calls[1].1["algorithm"], "ed25519");
    assert_eq!(calls[3].1["not_before"], 10);
    assert_eq!(calls[3].1["not_after"], 20);
    assert_eq!(calls[3].1["with_app_info"], true);
}

#[tokio::test]
async fn malformed_version_does_not_authorize_key_derivation() {
    let (endpoint, requests) = agent(|path| match path {
        "/Version" => (StatusCode::OK, json!({"error":"not a version response"})),
        _ => key_agent(path),
    })
    .await;
    let err = DstackClientV0::new(Some(&endpoint))
        .get_key_with_algorithm(None, None, "ed25519")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Version RPC"), "{err:#}");
    assert!(
        format!("{err:#}").contains("missing field `version`"),
        "{err:#}"
    );
    assert_eq!(
        requests.try_iter().collect::<Vec<_>>(),
        [("/Version".into(), json!({}))]
    );
}

#[tokio::test]
async fn tappd_info_accepts_null_tdx_registers() {
    let (endpoint, requests) = agent(|_| {
        let tcb = json!({"mrtd":null, "rtmr0":null, "rtmr1":null, "rtmr2":null, "rtmr3":null,
                         "event_log":[], "app_compose":"{}"});
        (StatusCode::OK, json!({"app_id":"app", "instance_id":"id", "app_cert":"", "app_name":"example", "tcb_info":tcb.to_string()}))
    }).await;
    let info = TappdClient::new(Some(&endpoint)).info().await.unwrap();
    assert_eq!(info.app_id, "app");
    assert_eq!(info.tcb_info.mrtd, None);
    assert_eq!(info.tcb_info.rtmr0, None);
    assert_eq!(info.tcb_info.rtmr1, None);
    assert_eq!(info.tcb_info.rtmr2, None);
    assert_eq!(info.tcb_info.rtmr3, None);
    assert_eq!(
        requests.try_iter().collect::<Vec<_>>(),
        [("/prpc/Tappd.Info".into(), json!({}))]
    );
}

#[tokio::test]
async fn legacy_agent_cannot_silently_ignore_tls_options() {
    let (endpoint, requests) = agent(key_agent).await;
    let client = DstackClientV0::new(Some(&endpoint));
    for (option, config) in [
        ("not_before", TlsKeyConfig::builder().not_before(0).build()),
        ("not_after", TlsKeyConfig::builder().not_after(0).build()),
        (
            "with_app_info",
            TlsKeyConfig::builder().with_app_info(true).build(),
        ),
    ] {
        let err = client.get_tls_key(config).await.unwrap_err();
        assert!(err.to_string().contains(option), "{err:#}");
        assert!(
            format!("{err:#}").contains("HTTP 404: unknown method"),
            "{err:#}"
        );
        assert_eq!(
            requests.try_iter().collect::<Vec<_>>(),
            [("/Version".into(), json!({}))]
        );
    }
}

#[tokio::test]
async fn ed25519_does_not_fall_back_to_a_legacy_key() {
    let (endpoint, requests) = agent(key_agent).await;
    let client = DstackClientV0::new(Some(&endpoint));
    let err = client
        .get_key_with_algorithm(None, None, "ed25519")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("ed25519"), "{err:#}");
    assert!(
        format!("{err:#}").contains("HTTP 404: unknown method"),
        "{err:#}"
    );
    assert_eq!(
        requests.try_iter().collect::<Vec<_>>(),
        [("/Version".into(), json!({}))]
    );
}
