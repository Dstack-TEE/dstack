// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Forward UDS connections to a remote QUIC endpoint (null crypto — no encryption).
//!
//! Maintains a single QUIC connection. Each incoming UDS connection is mapped
//! to a QUIC bidirectional stream.

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tokio::net::UnixListener;
use tracing::{error, info};

#[derive(Parser)]
#[command(about = "Forward UDS connections to a QUIC endpoint")]
struct Args {
    /// Path to the Unix domain socket to listen on
    #[arg(long)]
    uds: String,

    /// QUIC server address (host:port)
    #[arg(long)]
    quic_addr: String,
}

async fn connect_quic(addr: &str) -> Result<quinn::Connection> {
    let client_config =
        quinn::ClientConfig::new(Arc::new(quinn::crypto::null::NullClientConfig));

    let endpoint_config = quinn::EndpointConfig::new(Arc::new(quinn::crypto::null::NullHmacKey));
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let runtime = Arc::new(quinn::TokioRuntime);
    let endpoint = quinn::Endpoint::new(endpoint_config, None, socket, runtime)?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(addr.parse().context("invalid QUIC address")?, "localhost")
        .context("failed to start QUIC connect")?
        .await
        .context("failed to establish QUIC connection")?;

    Ok(connection)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Remove existing socket file if present
    let _ = std::fs::remove_file(&args.uds);

    let listener = UnixListener::bind(&args.uds)
        .with_context(|| format!("failed to bind UDS at {}", args.uds))?;

    let connection = connect_quic(&args.quic_addr)
        .await
        .context("failed to connect QUIC")?;
    let connection = Arc::new(connection);

    info!(
        "listening on {}, forwarding to QUIC {}",
        args.uds, args.quic_addr
    );

    loop {
        let (uds_stream, _) = listener
            .accept()
            .await
            .context("failed to accept UDS connection")?;

        let connection = connection.clone();
        tokio::spawn(async move {
            let (send, recv) = match connection.open_bi().await {
                Ok(s) => s,
                Err(e) => {
                    error!("failed to open QUIC stream: {e}");
                    return;
                }
            };

            // Bridge UDS ↔ QUIC stream
            let (mut ur, mut uw) = tokio::io::split(uds_stream);
            let mut send = send;
            let mut recv = recv;

            let r = tokio::select! {
                r = tokio::io::copy(&mut ur, &mut send) => r,
                r = tokio::io::copy(&mut recv, &mut uw) => r,
            };
            if let Err(e) = r {
                error!("bridge error: {e}");
            }
        });
    }
}
