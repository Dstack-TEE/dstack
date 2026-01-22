// Run with: cargo run --bin gen_debug_key -- <simulator_url>
// Example: cargo run --bin gen_debug_key -- https://daee134c3b9f66aa2401c3b5ea64f1d34038f45d-3000.tdxlab.dstack.org:12004

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use dstack_guest_agent_rpc::{dstack_guest_client::DstackGuestClient, RawQuoteArgs};
use http_client::prpc::PrpcClient;
use ra_tls::attestation::QuoteContentType;
use ra_tls::rcgen::KeyPair;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugKeyData {
    /// Private key in PEM format
    key_pem: String,
    /// TDX quote in base64 format
    quote_base64: String,
    /// Event log in JSON string format
    event_log: String,
    /// VM config in JSON string format
    vm_config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <simulator_url>", args[0]);
        eprintln!("Example: {} https://daee134c3b9f66aa2401c3b5ea64f1d34038f45d-3000.tdxlab.dstack.org:12004", args[0]);
        std::process::exit(1);
    }
    let simulator_url = &args[1];

    // Generate key pair
    let key = KeyPair::generate().context("Failed to generate key")?;
    let pubkey = key.public_key_der();
    let key_pem = key.serialize_pem();

    // Calculate report_data
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);

    // Get quote from simulator
    println!("Getting quote from simulator: {simulator_url}");
    let simulator_client = PrpcClient::new(simulator_url.to_string());
    let simulator_client = DstackGuestClient::new(simulator_client);
    let quote_response = simulator_client
        .get_quote(RawQuoteArgs {
            report_data: report_data.to_vec(),
        })
        .await
        .context("Failed to get quote from simulator")?;

    // Create debug key data structure
    let debug_data = DebugKeyData {
        key_pem,
        quote_base64: STANDARD.encode(&quote_response.quote),
        event_log: quote_response.event_log,
        vm_config: quote_response.vm_config,
    };

    // Write to single JSON file
    let json_content =
        serde_json::to_string_pretty(&debug_data).context("Failed to serialize debug key data")?;
    let output_file = "debug_key.json";
    fs_err::write(output_file, json_content).context("Failed to write debug key file")?;

    println!("✓ Successfully generated debug key data:");
    println!("  - {output_file}");
    println!("\nYou can now configure this path in your gateway config:");
    println!("[core.debug]");
    println!("insecure_skip_attestation = true");
    println!(
        "key_file = \"{}\"",
        fs_err::canonicalize(&output_file)
            .unwrap_or_default()
            .display()
    );

    Ok(())
}
