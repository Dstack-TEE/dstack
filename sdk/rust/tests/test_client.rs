// SPDX-FileCopyrightText: © 2025 Created-for-a-purpose <rachitchahar@gmail.com>
// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-FileCopyrightText: © 2025 tuddman <tuddman@users.noreply.github.com>
//
// SPDX-License-Identifier: Apache-2.0

use dcap_qvl::quote::Quote;
use dstack_sdk::dstack_client::DstackClient as AsyncDstackClient;
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
    let key_config = dstack_sdk_types::dstack::TlsKeyConfig::builder().build();
    let result = client.get_tls_key(key_config).await.unwrap();
    assert!(result.key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(!result.certificate_chain.is_empty());
}

#[tokio::test]
async fn test_tls_key_uniqueness() {
    let client = AsyncDstackClient::new(None);
    let key_config_1 = dstack_sdk_types::dstack::TlsKeyConfig::builder().build();
    let key_config_2 = dstack_sdk_types::dstack::TlsKeyConfig::builder().build();
    let result1 = client.get_tls_key(key_config_1).await.unwrap();
    let result2 = client.get_tls_key(key_config_2).await.unwrap();
    assert_ne!(result1.key, result2.key);
}

#[tokio::test]
async fn test_replay_rtmr() {
    let client = AsyncDstackClient::new(None);
    let result = client.get_quote("test".into()).await.unwrap();
    let rtmrs = result.replay_rtmrs().unwrap();
    let quote = result.decode_quote().unwrap();

    let tdx_quote = Quote::parse(&quote).unwrap();
    let quote_report = tdx_quote.report.as_td10().unwrap();
    assert_eq!(rtmrs[&0], hex::encode(quote_report.rt_mr0));
    assert_eq!(rtmrs[&1], hex::encode(quote_report.rt_mr1));
    assert_eq!(rtmrs[&2], hex::encode(quote_report.rt_mr2));
    assert_eq!(rtmrs[&3], hex::encode(quote_report.rt_mr3));
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
async fn test_async_client_sign_and_verify_ed25519() {
    let client = AsyncDstackClient::new(None);
    let data_to_sign = b"test message for ed25519".to_vec();
    let algorithm = "ed25519";

    let sign_resp = client.sign(algorithm, data_to_sign.clone()).await.unwrap();
    assert!(!sign_resp.signature.is_empty());
    assert!(!sign_resp.public_key.is_empty());
    assert_eq!(sign_resp.signature_chain.len(), 3);

    let sig = sign_resp.decode_signature().unwrap();
    let pub_key = sign_resp.decode_public_key().unwrap();

    let verify_resp = client
        .verify(
            algorithm,
            data_to_sign.clone(),
            sig.clone(),
            pub_key.clone(),
        )
        .await
        .unwrap();
    assert!(verify_resp.valid);

    let bad_data = b"wrong message".to_vec();
    let verify_resp_bad = client
        .verify(algorithm, bad_data, sig, pub_key)
        .await
        .unwrap();
    assert!(!verify_resp_bad.valid);
}

#[tokio::test]
async fn test_async_client_sign_and_verify_secp256k1() {
    let client = AsyncDstackClient::new(None);
    let data_to_sign = b"test message for secp256k1".to_vec();
    let algorithm = "secp256k1";

    let sign_resp = client.sign(algorithm, data_to_sign.clone()).await.unwrap();
    let sig = sign_resp.decode_signature().unwrap();
    let pub_key = sign_resp.decode_public_key().unwrap();

    let verify_resp = client
        .verify(algorithm, data_to_sign, sig, pub_key)
        .await
        .unwrap();
    assert!(verify_resp.valid);
}

#[tokio::test]
async fn test_async_client_sign_and_verify_secp256k1_prehashed() {
    let client = AsyncDstackClient::new(None);
    let data_to_sign = b"test message for secp256k1 prehashed";
    let digest = Sha256::digest(data_to_sign).to_vec();
    let algorithm = "secp256k1_prehashed";

    let sign_resp = client.sign(algorithm, digest.clone()).await.unwrap();
    let sig = sign_resp.decode_signature().unwrap();
    let pub_key = sign_resp.decode_public_key().unwrap();

    let verify_resp = client
        .verify(algorithm, digest.clone(), sig, pub_key)
        .await
        .unwrap();
    assert!(verify_resp.valid);
}
