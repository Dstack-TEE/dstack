// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dstack_sdk::tappd_client::TappdClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a TappdClient with default endpoint (/var/run/tappd.sock)
    let client = TappdClient::new(None);

    // Or create with a custom endpoint
    // let client = TappdClient::new(Some("/custom/path/tappd.sock"));

    // Or create with HTTP endpoint for simulator
    // let client = TappdClient::new(Some("http://localhost:8080"));

    println!("TappdClient created successfully!");

    // Example usage (these will fail without a running tappd service):

    // 1. Derive a key
    let response = client.derive_key("my/key/path").await?;
    println!("Key derived successfully!");
    println!(
        "Certificate chain length: {}",
        response.certificate_chain.len()
    );
    let ecdsa_p256_key = response.decode_key().unwrap();
    println!("ECDSA P-256 key length: {}", ecdsa_p256_key.len());

    // 2. Get a quote with 64 bytes of report data
    let mut report_data = b"Hello, world!".to_vec();
    // Pad to exactly 64 bytes for get_quote
    report_data.resize(64, 0);
    let response = client.get_quote(report_data).await?;
    println!("Quote generated successfully!");
    println!("Quote length: {}", response.quote.len());

    // 3. Get instance info
    let response = client.info().await?;
    println!("Instance info retrieved successfully!");
    println!("App ID: {}", response.app_id);
    println!("Instance ID: {}", response.instance_id);
    println!("App Name: {}", response.app_name);

    Ok(())
}
