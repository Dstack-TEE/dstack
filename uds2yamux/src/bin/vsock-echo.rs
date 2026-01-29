// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Echo server for testing TCP and yamux connectivity.
//!
//! Usage:
//!   vsock-echo --tcp-port 8080                 # TCP echo server
//!   vsock-echo --yamux-port 9090               # yamux-over-TCP echo server
//!   vsock-echo --tcp-port 8080 --yamux-port 9090 # both

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::TcpListener;
use tracing::{error, info};

#[derive(Parser)]
#[command(about = "TCP/yamux echo server for testing")]
struct Args {
    /// TCP port to listen on for TCP connections
    #[arg(long)]
    tcp_port: Option<u16>,

    /// TCP port to listen on for yamux-over-TCP connections
    #[arg(long)]
    yamux_port: Option<u16>,
}

static ACTIVE: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);

async fn run_tcp_echo(port: u16) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .with_context(|| format!("failed to bind TCP port {port}"))?;
    info!("TCP echo server listening on port {port}");

    loop {
        let (stream, addr) = listener.accept().await?;
        let id = TOTAL.fetch_add(1, Ordering::Relaxed);
        let active = ACTIVE.fetch_add(1, Ordering::Relaxed) + 1;
        if id.is_multiple_of(100) {
            info!("tcp #{id} from {addr}, active={active}");
        }
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(stream);
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let remaining = ACTIVE.fetch_sub(1, Ordering::Relaxed) - 1;
            if id.is_multiple_of(100) {
                info!("tcp #{id} closed, active={remaining}");
            }
        });
    }
}

async fn run_yamux_echo(port: u16) -> Result<()> {
    use tokio_util::compat::TokioAsyncReadCompatExt;

    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .with_context(|| format!("failed to bind yamux TCP port {port}"))?;
    info!("yamux echo server listening on TCP port {port}");

    loop {
        let (tcp_stream, addr) = listener.accept().await?;
        info!("yamux: new TCP connection from {addr}");
        tokio::spawn(async move {
            let cfg = yamux::Config::default();
            let mut conn = yamux::Connection::new(tcp_stream.compat(), cfg, yamux::Mode::Server);

            loop {
                match std::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await {
                    Some(Ok(stream)) => {
                        let id = TOTAL.fetch_add(1, Ordering::Relaxed);
                        let active = ACTIVE.fetch_add(1, Ordering::Relaxed) + 1;
                        if id.is_multiple_of(100) {
                            info!("yamux #{id}, active={active}");
                        }
                        tokio::spawn(async move {
                            let (mut r, mut w) = futures::io::AsyncReadExt::split(stream);
                            let _ = futures::io::copy(&mut r, &mut w).await;
                            let remaining = ACTIVE.fetch_sub(1, Ordering::Relaxed) - 1;
                            if id.is_multiple_of(100) {
                                info!("yamux #{id} closed, active={remaining}");
                            }
                        });
                    }
                    None => {
                        info!("yamux connection from {addr} closed");
                        break;
                    }
                    Some(Err(e)) => {
                        error!("yamux accept error from {addr}: {e}");
                        break;
                    }
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if args.tcp_port.is_none() && args.yamux_port.is_none() {
        anyhow::bail!("specify at least one of --tcp-port or --yamux-port");
    }

    let mut tasks = Vec::new();

    if let Some(port) = args.tcp_port {
        tasks.push(tokio::spawn(async move {
            if let Err(e) = run_tcp_echo(port).await {
                error!("TCP echo error: {e}");
            }
        }));
    }

    if let Some(port) = args.yamux_port {
        tasks.push(tokio::spawn(async move {
            if let Err(e) = run_yamux_echo(port).await {
                error!("yamux echo error: {e}");
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }

    Ok(())
}
