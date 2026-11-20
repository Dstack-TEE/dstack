// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

#![allow(deprecated)]

use axum::{routing::post, Router};
use dstack_sdk::dstack_client_v0::{DstackClientV0, GetKeyConfig, TlsKeyConfig};
use dstack_sdk::tappd_client::TappdClient;
use serde_json::json;
use tokio::net::TcpListener;

async fn endpoint(routes: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
    endpoint
}

#[tokio::test]
async fn legacy_keys_still_work_but_cannot_silently_ignore_new_options() {
    // An agent without Version can return its default key or certificate even
    // if the caller requested an explicit expiry.
    let routes = Router::new()
        .route(
            "/GetKey",
            post(|| async { r#"{"key":"ab","signature_chain":[]}"# }),
        )
        .route(
            "/GetTlsKey",
            post(|| async { r#"{"key":"pem","certificate_chain":[]}"# }),
        );
    let client = DstackClientV0::new(Some(&endpoint(routes).await));

    assert_eq!(
        client
            .get_key(GetKeyConfig::builder().build())
            .await
            .unwrap()
            .key,
        "ab"
    );
    assert!(client
        .get_key(GetKeyConfig::builder().algorithm("ed25519").build())
        .await
        .is_err());

    assert_eq!(
        client
            .get_tls_key(TlsKeyConfig::builder().build())
            .await
            .unwrap()
            .key,
        "pem"
    );
    assert!(client
        .get_tls_key(TlsKeyConfig::builder().not_after(0).build())
        .await
        .is_err());
}

#[tokio::test]
async fn tappd_info_accepts_null_tdx_registers() {
    let routes = Router::new().route(
        "/prpc/Tappd.Info",
        post(|| async {
            let tcb = json!({
                "mrtd":null, "rtmr0":null, "rtmr1":null, "rtmr2":null, "rtmr3":null,
                "event_log":[], "app_compose":"{}"
            });
            json!({"app_id":"app", "instance_id":"id", "app_cert":"", "app_name":"example",
               "tcb_info":tcb.to_string()})
            .to_string()
        }),
    );
    let info = TappdClient::new(Some(&endpoint(routes).await))
        .info()
        .await
        .unwrap();
    assert_eq!(info.tcb_info.mrtd, None);
}
