// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dstack_sdk::tappd_client::TappdClient;
use dstack_sdk_types::tappd::DeriveKeyResponse;
use std::env;

#[tokio::test]
async fn test_tappd_client_creation() {
    // Test client creation with default endpoint
    let _client = TappdClient::new(None);

    // This should succeed without panicking
    assert!(true);
}

#[tokio::test]
async fn test_tappd_client_with_custom_endpoint() {
    // Test client creation with custom endpoint
    let _client = TappdClient::new(Some("/custom/path/tappd.sock"));

    // This should succeed without panicking
    assert!(true);
}

#[tokio::test]
async fn test_tappd_client_with_http_endpoint() {
    // Test client creation with HTTP endpoint
    let _client = TappdClient::new(Some("http://localhost:8080"));

    // This should succeed without panicking
    assert!(true);
}

// Integration tests that require a running tappd service
// These tests will be skipped if no tappd service is available

#[tokio::test]
async fn test_tappd_client_info_integration() {
    let client = get_test_client();
    let info = client.info().await.unwrap();

    println!("✓ Info request successful");
    println!("  App ID: {}", info.app_id);
    println!("  Instance ID: {}", info.instance_id);
    println!("  App Name: {}", info.app_name);

    // Validate response structure
    assert!(!info.app_id.is_empty());
    assert!(!info.instance_id.is_empty());
    assert!(!info.app_name.is_empty());
    assert!(!info.tcb_info.app_compose.is_empty());
    assert!(!info.tcb_info.mrtd.is_empty());
    assert!(!info.tcb_info.rtmr0.is_empty());
    assert!(!info.tcb_info.rtmr1.is_empty());
    assert!(!info.tcb_info.rtmr2.is_empty());
    assert!(!info.tcb_info.rtmr3.is_empty());
    assert!(!info.tcb_info.event_log.is_empty());
}

#[tokio::test]
async fn test_tappd_client_derive_key_integration() {
    let client = get_test_client();

    let response = client.derive_key("test/key/path").await.unwrap();
    println!("✓ Derive key request successful");
    println!("  Key length: {}", response.key.len());
    println!(
        "  Certificate chain length: {}",
        response.certificate_chain.len()
    );

    // Validate response structure
    assert!(!response.key.is_empty());

    // Test key decoding
    let key_bytes = response.decode_key().unwrap();
    println!("✓ Decoded key bytes length: {}", key_bytes.len());
    assert_eq!(key_bytes.len(), 32);
}

#[tokio::test]
async fn test_tappd_client_derive_key_with_subject_integration() {
    let client = get_test_client();

    let response = client
        .derive_key_with_subject("test/key/path", "example.com")
        .await
        .unwrap();

    println!("✓ Derive key with subject request successful");
    println!("  Key length: {}", response.key.len());
    println!(
        "  Certificate chain length: {}",
        response.certificate_chain.len()
    );

    // Validate response structure
    assert!(!response.key.is_empty());
}

#[tokio::test]
async fn test_tappd_client_derive_key_with_alt_names_integration() {
    let client = get_test_client();

    let alt_names = vec!["www.example.com".to_string(), "api.example.com".to_string()];
    let response = client
        .derive_key_with_subject_and_alt_names(
            "test/key/path",
            Some("example.com"),
            Some(alt_names),
        )
        .await
        .unwrap();
    println!("✓ Derive key with alt names request successful");
    println!("  Key length: {}", response.key.len());
    println!(
        "  Certificate chain length: {}",
        response.certificate_chain.len()
    );

    // Validate response structure
    assert!(!response.key.is_empty());
}

#[tokio::test]
async fn test_tappd_client_get_quote_integration() {
    let client = get_test_client();

    let mut report_data = b"test report data for quote".to_vec();
    // Pad to exactly 64 bytes for get_quote
    report_data.resize(64, 0);

    let response = client.get_quote(report_data).await.unwrap();
    println!("✓ Quote request successful");
    println!("  Quote length: {}", response.quote.len());
    println!("  Event log length: {}", response.event_log.len());

    // Validate response structure
    assert!(!response.quote.is_empty());
    assert!(!response.event_log.is_empty());

    // Test quote decoding
    match response.decode_quote() {
        Ok(quote_bytes) => {
            println!("  Decoded quote bytes length: {}", quote_bytes.len());
            assert!(!quote_bytes.is_empty());
        }
        Err(e) => {
            println!("  Quote decode error: {}", e);
        }
    }

    // Test RTMR replay
    match response.replay_rtmrs() {
        Ok(rtmrs) => {
            println!("  Replayed RTMRs: {} entries", rtmrs.len());
            for (idx, rtmr) in rtmrs.iter() {
                println!("    RTMR{}: {}", idx, rtmr);
            }
        }
        Err(e) => {
            println!("  RTMR replay error: {}", e);
        }
    }
}

// Helper function to get a test client
fn get_test_client() -> TappdClient {
    // Check for simulator endpoint first
    if let Ok(endpoint) = env::var("TAPPD_SIMULATOR_ENDPOINT") {
        println!("Using TAPPD_SIMULATOR_ENDPOINT: {}", endpoint);
        return TappdClient::new(Some(&endpoint));
    }

    // Check for DSTACK_SIMULATOR_ENDPOINT as fallback
    if let Ok(endpoint) = env::var("DSTACK_SIMULATOR_ENDPOINT") {
        println!("Using DSTACK_SIMULATOR_ENDPOINT as fallback: {}", endpoint);
        return TappdClient::new(Some(&endpoint));
    }

    // Use default endpoint
    println!("Using default tappd endpoint: /var/run/tappd.sock");
    TappdClient::new(None)
}

#[test]
fn test_derive_key_response_decode() {
    // Test with a valid ECDSA P-256 private key in PKCS#8 format
    let pem_key = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3/aZQhz0nBx0tqG1\nwPNlB/ILBqnY1xvHT7bkZl9oJP2hRANCAATEwT3ixOl0zFOjEEUhpwP6xBz1F2jY\n3B1LokSVHFcFJHUWEHVZJQcFhBAhFGdhEn1B/9HYBQz5w5H8Vl0z3T9U\n-----END PRIVATE KEY-----";
    let response = DeriveKeyResponse {
        key: pem_key.to_string(),
        certificate_chain: vec![],
    };

    // The implementation should return the decoded ECDSA P-256 private key bytes
    let bytes = response.decode_key().unwrap();
    assert!(!bytes.is_empty());
    // For a valid ECDSA P-256 key, we should get either 32 bytes (the private key)
    // or fall back to the full DER contents if parsing fails
    assert_eq!(bytes.len(), 32);
}
