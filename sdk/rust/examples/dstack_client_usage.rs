// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dstack_sdk::dstack_client::DstackClient;
use dstack_sdk_types::dstack::TlsKeyConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a DstackClient with default endpoint (/var/run/dstack.sock)
    let client = DstackClient::new(None);

    // Or create with a custom endpoint
    // let client = DstackClient::new(Some("/custom/path/dstack.sock"));

    // Or create with HTTP endpoint for simulator
    // let client = DstackClient::new(Some("http://localhost:8000"));

    println!("DstackClient created successfully!");

    // Example usage (these will fail without a running dstack service):

    // 1. Get system info
    let info = client.info().await?;
    println!("System info retrieved successfully!");
    println!("  App ID: {}", info.app_id);
    println!("  Instance ID: {}", info.instance_id);
    println!("  App Name: {}", info.app_name);
    println!("  Device ID: {}", info.device_id);
    println!("  Compose Hash: {}", info.compose_hash);
    println!("  TCB Info - MRTD: {}", info.tcb_info.mrtd);
    println!("  TCB Info - RTMR0: {}", info.tcb_info.rtmr0);

    // 2. Derive a key
    let response = client
        .get_key(Some("my-app".to_string()), Some("encryption".to_string()))
        .await?;
    println!("Key derived successfully!");
    println!("  Key length: {}", response.key.len());
    println!(
        "  Signature chain length: {}",
        response.signature_chain.len()
    );

    // Decode the key
    let key_bytes = response.decode_key()?;
    println!("  Decoded key bytes length: {}", key_bytes.len());

    // 3. Generate TDX quote
    let report_data = b"Hello, dstack world!".to_vec();
    let response = client.get_quote(report_data).await?;
    println!("TDX quote generated successfully!");
    println!("  Quote length: {}", response.quote.len());
    println!("  Event log length: {}", response.event_log.len());

    // Decode the quote
    let quote_bytes = response.decode_quote()?;
    println!("  Decoded quote bytes length: {}", quote_bytes.len());

    // Replay RTMRs from event log
    let rtmrs = response.replay_rtmrs()?;
    println!("  Replayed RTMRs: {} entries", rtmrs.len());
    for (idx, rtmr) in rtmrs.iter() {
        println!("    RTMR{}: {}", idx, rtmr);
    }

    // 4. Emit an event
    let event_payload = b"Application started successfully".to_vec();
    client
        .emit_event("AppStart".to_string(), event_payload)
        .await?;
    println!("Event emitted successfully!");

    // 5. Get TLS key for server authentication
    let tls_config = TlsKeyConfig::builder()
        .subject("my-app.example.com")
        .alt_names(vec![
            "www.my-app.com".to_string(),
            "api.my-app.com".to_string(),
        ])
        .usage_server_auth(true)
        .usage_client_auth(false)
        .usage_ra_tls(true)
        .build();

    let response = client.get_tls_key(tls_config).await?;
    println!("TLS key generated successfully!");
    println!("  Key length: {}", response.key.len());
    println!(
        "  Certificate chain length: {}",
        response.certificate_chain.len()
    );

    // 6. Get a simple key without purpose
    let response = client.get_key(Some("simple-key".to_string()), None).await?;
    println!("Simple key derived successfully!");
    println!("  Key: {}", response.key);

    // 7. Generate quote with minimal report data
    let minimal_data = vec![0x01, 0x02, 0x03, 0x04];
    let response = client.get_quote(minimal_data).await?;
    println!("Minimal quote generated successfully!");
    println!("  Quote length: {}", response.quote.len());
    println!("  Event log length: {}", response.event_log.len());

    // Parse and display event log
    let events = response.decode_event_log()?;
    println!("  Event log contains {} events", events.len());
    for (i, event) in events.iter().enumerate().take(3) {
        // Show first 3 events
        println!(
            "    Event {}: IMR={}, Type={}, Event='{}'",
            i, event.imr, event.event_type, event.event
        );
    }

    let data_to_sign = b"my secret message".to_vec();
    let algorithm = "secp256k1";
    println!("Signing data with algorithm '{}'...", algorithm);
    let sign_resp = client.sign(algorithm, data_to_sign.clone()).await?;
    println!("  Signature: {}", sign_resp.signature);
    println!("  Public Key: {}", sign_resp.public_key);

    let sig_bytes = sign_resp.decode_signature()?;
    let pub_key_bytes = sign_resp.decode_public_key()?;

    let verify_resp = client
        .verify(
            algorithm,
            data_to_sign.clone(),
            sig_bytes.clone(),
            pub_key_bytes.clone(),
        )
        .await?;
    println!("  Verification successful: {}", verify_resp.valid);
    Ok(())
}
