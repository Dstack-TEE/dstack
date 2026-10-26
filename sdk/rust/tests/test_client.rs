// SPDX-FileCopyrightText: © 2025 Created-for-a-purpose <rachitchahar@gmail.com>
// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-FileCopyrightText: © 2025 tuddman <tuddman@users.noreply.github.com>
//
// SPDX-License-Identifier: Apache-2.0

// This file exercises the deprecated v0 surface; that is its purpose.
#![allow(deprecated)]

use dcap_qvl::quote::Quote;
use dstack_sdk::dstack_client_v0::DstackClientV0 as AsyncDstackClient;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn test_async_client_get_key() {
    let client = AsyncDstackClient::new(None);
    let result = client.get_key(None, None).await.unwrap();
    assert!(!result.key.is_empty());
    assert_eq!(result.decode_key().unwrap().len(), 32);
}

#[tokio::test]
async fn test_async_client_get_quote() {
    let client = AsyncDstackClient::new(None);
    let result = client.get_quote("test".into()).await.unwrap();
    assert!(!result.quote.is_empty());
}

#[tokio::test]
async fn test_async_client_get_tls_key() {
    let client = AsyncDstackClient::new(None);
    let key_config = dstack_sdk_types::dstack_v0::TlsKeyConfig::builder().build();
    let result = client.get_tls_key(key_config).await.unwrap();
    assert!(result.key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(!result.certificate_chain.is_empty());
}

#[tokio::test]
async fn test_tls_key_uniqueness() {
    let client = AsyncDstackClient::new(None);
    let key_config_1 = dstack_sdk_types::dstack_v0::TlsKeyConfig::builder().build();
    let key_config_2 = dstack_sdk_types::dstack_v0::TlsKeyConfig::builder().build();
    let result1 = client.get_tls_key(key_config_1).await.unwrap();
    let result2 = client.get_tls_key(key_config_2).await.unwrap();
    assert_ne!(result1.key, result2.key);
}

#[tokio::test]
async fn test_report_data() {
    let report_data = "test";
    let client = AsyncDstackClient::new(None);
    let result = client.get_quote(report_data.into()).await.unwrap();
    let quote = result.decode_quote().unwrap();

    let tdx_quote = Quote::parse(&quote).unwrap();
    let quote_report = tdx_quote.report.as_td10().unwrap();
    let expected = {
        let mut padded = report_data.as_bytes().to_vec();
        padded.resize(64, 0);
        padded
    };
    assert_eq!(&quote_report.report_data[..], &expected[..]);
}

#[tokio::test]
async fn test_info() {
    let client = AsyncDstackClient::new(None);
    let info = client.info().await.unwrap();
    assert!(!info.app_id.is_empty());
    assert!(!info.instance_id.is_empty());
    assert!(!info.app_cert.is_empty());
    assert!(!info.tcb_info.mrtd.is_empty());
    assert!(!info.tcb_info.rtmr0.is_empty());
    assert!(!info.tcb_info.rtmr1.is_empty());
    assert!(!info.tcb_info.rtmr2.is_empty());
    assert!(!info.tcb_info.rtmr3.is_empty());
    assert!(!info.tcb_info.compose_hash.is_empty());
    assert!(!info.tcb_info.device_id.is_empty());
    assert!(!info.tcb_info.app_compose.is_empty());
    assert!(!info.tcb_info.event_log.is_empty());
    assert!(!info.app_name.is_empty());
    assert!(!info.device_id.is_empty());
    assert!(!info.key_provider_info.is_empty());
    assert!(!info.compose_hash.is_empty());
}

#[tokio::test]
async fn test_async_client_version() {
    let client = AsyncDstackClient::new(None);
    let result = client.version().await.unwrap();
    assert!(!result.version.is_empty());
}

#[tokio::test]
async fn test_async_client_get_key_k256_alias() {
    let client = AsyncDstackClient::new(None);
    // k256 should work as an alias for secp256k1
    let result = client
        .get_key(Some("test".to_string()), None)
        .await
        .unwrap();
    assert!(!result.key.is_empty());
    assert_eq!(result.decode_key().unwrap().len(), 32);
}

#[tokio::test]
async fn test_async_client_sign_k256_alias() {
    let client = AsyncDstackClient::new(None);
    let data = b"test message".to_vec();

    // Sign with k256 alias
    let resp_k256 = client.sign("k256", data.clone()).await.unwrap();
    assert!(!resp_k256.signature.is_empty());
    assert!(!resp_k256.public_key.is_empty());

    // Sign with secp256k1 should produce the same public key
    let resp_secp = client.sign("secp256k1", data.clone()).await.unwrap();
    assert_eq!(resp_k256.public_key, resp_secp.public_key);
}

// Sign and Verify are both v0 RPCs, so the round trip stays entirely on the
// frozen surface. v1 has neither: an app there signs locally with the key
// `get_key` returns, and a relying party verifies per `docs/guest-api-v1.md`.

#[tokio::test]
async fn test_sign_then_verify_ed25519() {
    let client = AsyncDstackClient::new(None);
    let data = b"test message for ed25519".to_vec();
    let resp = client.sign("ed25519", data.clone()).await.unwrap();
    let signature = resp.decode_signature().unwrap();
    let public_key = resp.decode_public_key().unwrap();

    assert_eq!(resp.signature_chain.len(), 3);
    assert!(
        client
            .verify("ed25519", data, signature.clone(), public_key.clone())
            .await
            .unwrap()
            .valid
    );
    assert!(
        !client
            .verify("ed25519", b"wrong message".to_vec(), signature, public_key)
            .await
            .unwrap()
            .valid
    );
}

#[tokio::test]
async fn test_sign_then_verify_secp256k1() {
    let client = AsyncDstackClient::new(None);
    let data = b"test message for secp256k1".to_vec();
    let resp = client.sign("secp256k1", data.clone()).await.unwrap();
    let signature = resp.decode_signature().unwrap();
    let public_key = resp.decode_public_key().unwrap();

    assert_eq!(resp.signature_chain.len(), 3);
    assert!(
        client
            .verify("secp256k1", data, signature.clone(), public_key.clone())
            .await
            .unwrap()
            .valid
    );
    assert!(
        !client
            .verify(
                "secp256k1",
                b"wrong message".to_vec(),
                signature,
                public_key
            )
            .await
            .unwrap()
            .valid
    );
}

#[tokio::test]
async fn test_sign_then_verify_secp256k1_prehashed() {
    let client = AsyncDstackClient::new(None);
    let digest = Sha256::digest(b"test message for prehashed").to_vec();
    let resp = client
        .sign("secp256k1_prehashed", digest.clone())
        .await
        .unwrap();
    let signature = resp.decode_signature().unwrap();
    let public_key = resp.decode_public_key().unwrap();

    assert_eq!(resp.signature_chain.len(), 3);
    assert!(
        client
            .verify("secp256k1_prehashed", digest, signature, public_key)
            .await
            .unwrap()
            .valid
    );
}

/// A refused prpc call answers 4xx with `{"error": "..."}`, and that message is
/// the whole value of the response -- `EmitEvent` exists in 0.6 only to explain
/// its own removal. Both the status and the agent's text have to reach the
/// caller, which `error_for_status()` and the unix client's default error both
/// used to throw away.
#[tokio::test]
async fn a_refused_call_reports_the_status_and_the_agent_message() {
    let client = AsyncDstackClient::new(None);
    let err = client
        .emit_event("test-event".to_string(), b"payload".to_vec())
        .await
        .unwrap_err();

    let message = format!("{err:#}");
    assert!(
        message.contains("HTTP 400"),
        "expected the status in: {message}"
    );
    assert!(
        message.contains("EmitEvent was removed in dstack 0.6.0"),
        "expected the agent's own explanation in: {message}"
    );
}
