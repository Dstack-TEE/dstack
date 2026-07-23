// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Generate development-only mock attestation assets")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate PKI roots and a manifest for every supported platform.
    Generate {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8088")]
        collateral_base_url: String,
    },
    /// Serve mock PCCS, AMD KDS and certificate collateral endpoints.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8088")]
        listen: std::net::SocketAddr,
        /// Write the roots matching this server instance into this directory.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Read the seed and collateral URL from a simulator config JSON file.
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Generate {
            output,
            collateral_base_url,
        } => {
            mock_attestation::generate_assets_from_seed(
                &output,
                mock_attestation::random_seed(),
                &collateral_base_url,
            )?;
        }
        Command::Serve {
            listen,
            output,
            config,
        } => {
            let state = if let Some(path) = config {
                let config: dstack_types::TeeSimulatorConfig =
                    serde_json::from_slice(&fs_err::read(path)?)?;
                let seed = mock_attestation::parse_seed(
                    config
                        .mock_attestation_seed
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("mock_attestation_seed missing"))?,
                )?;
                let url = config
                    .collateral_base_url
                    .as_deref()
                    .unwrap_or("http://127.0.0.1:8088");
                std::sync::Arc::new(mock_attestation::server::MockCollateralState::from_seed(
                    seed, url,
                )?)
            } else {
                std::sync::Arc::new(mock_attestation::server::MockCollateralState::new()?)
            };
            if let Some(output) = output {
                state.write_roots(&output)?;
            }
            mock_attestation::server::serve(listen, state).await?;
        }
    }
    Ok(())
}
