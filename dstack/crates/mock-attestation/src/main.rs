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
    },
    /// Serve mock PCCS, AMD KDS and certificate collateral endpoints.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8088")]
        listen: std::net::SocketAddr,
        /// Write the roots matching this server instance into this directory.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Generate { output } => {
            mock_attestation::generate_assets(&output)?;
        }
        Command::Serve { listen, output } => {
            let state = std::sync::Arc::new(mock_attestation::server::MockCollateralState::new()?);
            if let Some(output) = output {
                state.write_roots(&output)?;
            }
            mock_attestation::server::serve(listen, state).await?;
        }
    }
    Ok(())
}
