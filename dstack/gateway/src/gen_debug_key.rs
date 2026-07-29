// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Run with: cargo run --bin gen_debug_key -- <simulator_url>
// Example: cargo run --bin gen_debug_key -- https://daee134c3b9f66aa2401c3b5ea64f1d34038f45d-3000.tdxlab.dstack.org:12004

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use dstack_guest_agent_rpc::{RawQuoteArgs, dstack_guest_client::DstackGuestClient};
use http_client::prpc::PrpcClient;
use ra_tls::attestation::QuoteContentType;
use ra_tls::rcgen::KeyPair;
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Write as _, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugKeyData {
    /// This artifact is accepted only by the explicit insecure debug path.
    debug_only: bool,
    /// Private key in PEM format
    key_pem: String,
    /// TDX quote in base64 format
    quote_base64: String,
    /// Event log in JSON string format
    event_log: String,
    /// VM config in JSON string format
    vm_config: String,
}

fn write_new_debug_key(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs_err::create_dir_all(parent).context("Failed to create debug key directory")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Debug key output path has no UTF-8 file name")?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));

    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let result = (|| -> Result<()> {
        let mut output = options
            .open(&temporary)
            .context("Failed to create private debug key temporary file")?;
        output
            .write_all(content)
            .context("Failed to write private debug key temporary file")?;
        output
            .sync_all()
            .context("Failed to sync private debug key temporary file")?;
        drop(output);
        fs_err::hard_link(&temporary, path)
            .context("Refusing to overwrite existing debug key file")?;
        Ok(())
    })();
    let _ = fs_err::remove_file(&temporary);
    result
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <simulator_url>", args[0]);
        eprintln!(
            "Example: {} https://daee134c3b9f66aa2401c3b5ea64f1d34038f45d-3000.tdxlab.dstack.org:12004",
            args[0]
        );
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
        debug_only: true,
        key_pem,
        quote_base64: STANDARD.encode(&quote_response.quote),
        event_log: quote_response.event_log,
        vm_config: quote_response.vm_config,
    };

    // Write to single JSON file
    let json_content =
        serde_json::to_string_pretty(&debug_data).context("Failed to serialize debug key data")?;
    let output_file = "debug_key.json";
    write_new_debug_key(Path::new(output_file), json_content.as_bytes())
        .context("Failed to publish debug key file")?;

    println!("✓ Successfully generated debug key data:");
    println!("  - {output_file}");
    println!("\nYou can now configure this path in your gateway config:");
    println!("[core.debug]");
    println!("insecure_skip_attestation = true");
    println!(
        "key_file = \"{}\"",
        fs_err::canonicalize(output_file)
            .unwrap_or_default()
            .display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::write_new_debug_key;
    use std::{
        fs,
        sync::{Arc, Barrier},
    };

    #[test]
    fn debug_key_artifact_safety_matrix() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("debug_key.json");
        write_new_debug_key(&output, br#"{"debug_only":true}"#).unwrap();
        assert_eq!(fs::read(&output).unwrap(), br#"{"debug_only":true}"#);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(write_new_debug_key(&output, b"replacement").is_err());
        assert_eq!(fs::read(&output).unwrap(), br#"{"debug_only":true}"#);

        let concurrent = directory.path().join("concurrent.json");
        let barrier = Arc::new(Barrier::new(9));
        let workers: Vec<_> = (0..8)
            .map(|index| {
                let barrier = barrier.clone();
                let concurrent = concurrent.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    write_new_debug_key(&concurrent, format!("row-{index}").as_bytes()).is_ok()
                })
            })
            .collect();
        barrier.wait();
        let successes = workers
            .into_iter()
            .filter(|worker| worker.join().unwrap())
            .count();
        assert_eq!(successes, 1);
        assert!(fs::read_to_string(&concurrent).unwrap().starts_with("row-"));
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }
}
