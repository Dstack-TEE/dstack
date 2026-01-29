// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Forward UDS connections to a remote yamux endpoint over TCP.
//!
//! Maintains a single TCP connection and multiplexes each incoming UDS
//! connection onto a yamux stream.

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::{TcpStream, UnixListener};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{error, info};

#[derive(Parser)]
#[command(about = "Forward UDS connections to a yamux endpoint")]
struct Args {
    /// Path to the Unix domain socket to listen on
    #[arg(long)]
    uds: String,

    /// Yamux server address (host:port)
    #[arg(long)]
    yamux_addr: String,
}

async fn connect_yamux(
    addr: &str,
) -> Result<yamux::Connection<tokio_util::compat::Compat<TcpStream>>> {
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("failed to connect TCP {addr}"))?;
    stream
        .set_nodelay(true)
        .context("failed to set TCP_NODELAY")?;

    let cfg = yamux::Config::default();
    Ok(yamux::Connection::new(
        stream.compat(),
        cfg,
        yamux::Mode::Client,
    ))
}

async fn drive_yamux(
    mut conn: yamux::Connection<tokio_util::compat::Compat<TcpStream>>,
    mut requests: mpsc::Receiver<oneshot::Sender<anyhow::Result<yamux::Stream>>>,
) {
    loop {
        tokio::select! {
            inbound = std::future::poll_fn(|cx| conn.poll_next_inbound(cx)) => {
                match inbound {
                    Some(Ok(stream)) => {
                        info!("yamux: inbound stream {stream}");
                    }
                    Some(Err(e)) => {
                        error!("yamux: inbound error: {e}");
                        break;
                    }
                    None => {
                        info!("yamux: connection closed by peer");
                        break;
                    }
                }
            }
            request = requests.recv() => {
                let Some(reply) = request else {
                    break;
                };
                let result = std::future::poll_fn(|cx| conn.poll_new_outbound(cx))
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to open yamux stream: {e}"));
                let _ = reply.send(result);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let _ = std::fs::remove_file(&args.uds);

    let listener = UnixListener::bind(&args.uds)
        .with_context(|| format!("failed to bind UDS at {}", args.uds))?;

    let connection = connect_yamux(&args.yamux_addr)
        .await
        .context("failed to connect yamux")?;

    let (request_tx, request_rx) = mpsc::channel(128);
    tokio::spawn(drive_yamux(connection, request_rx));

    info!(
        "listening on {}, forwarding to yamux {}",
        args.uds, args.yamux_addr
    );

    loop {
        let (uds_stream, _) = listener
            .accept()
            .await
            .context("failed to accept UDS connection")?;

        let request_tx = request_tx.clone();
        tokio::spawn(async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            if request_tx.send(reply_tx).await.is_err() {
                error!("yamux driver closed");
                return;
            }

            let stream = match reply_rx.await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    error!("failed to open yamux stream: {e}");
                    return;
                }
                Err(_) => {
                    error!("yamux driver dropped response channel");
                    return;
                }
            };

            let stream = stream.compat();
            let (mut sr, mut sw) = tokio::io::split(stream);
            let (mut ur, mut uw) = tokio::io::split(uds_stream);

            let r = tokio::select! {
                r = tokio::io::copy(&mut ur, &mut sw) => r,
                r = tokio::io::copy(&mut sr, &mut uw) => r,
            };
            if let Err(e) = r {
                error!("bridge error: {e}");
            }
        });
    }
}
