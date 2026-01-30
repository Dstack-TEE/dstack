// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Forward UDS connections to a remote yamux endpoint over TCP.
//!
//! Maintains a pool of TCP connections and multiplexes each incoming UDS
//! connection onto a yamux stream.

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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

    /// Number of TCP connections in the yamux pool
    #[arg(long, default_value = "1")]
    yamux_conns: usize,
}

type YamuxRequest = oneshot::Sender<anyhow::Result<yamux::Stream>>;

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

async fn drive_yamux(addr: String, mut requests: mpsc::Receiver<YamuxRequest>) {
    use futures::FutureExt;

    let mut pending: Vec<YamuxRequest> = Vec::new();
    let mut backoff = std::time::Duration::from_secs(1);
    let max_backoff = std::time::Duration::from_secs(60);

    loop {
        let mut conn = loop {
            match connect_yamux(&addr).await {
                Ok(conn) => {
                    backoff = std::time::Duration::from_secs(1);
                    info!("yamux: connected to {addr}");
                    break conn;
                }
                Err(e) => {
                    error!("yamux: connect error: {e}");
                    let delay = tokio::time::sleep(backoff);
                    tokio::pin!(delay);
                    tokio::select! {
                        _ = &mut delay => {
                            backoff = std::cmp::min(backoff * 2, max_backoff);
                        }
                        request = requests.recv() => {
                            match request {
                                Some(reply) => pending.push(reply),
                                None => return,
                            }
                        }
                    }
                }
            }
        };

        loop {
            let request_fut = if let Some(reply) = pending.pop() {
                futures::future::ready(Some(reply)).boxed()
            } else {
                requests.recv().boxed()
            };

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
                request = request_fut => {
                    let Some(reply) = request else {
                        return;
                    };
                    let result = std::future::poll_fn(|cx| conn.poll_new_outbound(cx))
                        .await
                        .map_err(|e| anyhow::anyhow!("failed to open yamux stream: {e}"));
                    let _ = reply.send(result);
                }
            }
        }
    }
}

async fn spawn_yamux_driver(addr: &str) -> Result<mpsc::Sender<YamuxRequest>> {
    let (request_tx, request_rx) = mpsc::channel(128);
    tokio::spawn(drive_yamux(addr.to_string(), request_rx));
    Ok(request_tx)
}

struct YamuxPool {
    senders: Vec<mpsc::Sender<YamuxRequest>>,
    next: AtomicUsize,
}

impl YamuxPool {
    async fn new(addr: &str, num_conns: usize) -> Result<Self> {
        let mut senders = Vec::with_capacity(num_conns);
        for _ in 0..num_conns {
            senders.push(spawn_yamux_driver(addr).await?);
        }
        Ok(Self {
            senders,
            next: AtomicUsize::new(0),
        })
    }

    async fn open_stream(&self) -> Result<yamux::Stream> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.senders[idx]
            .send(reply_tx)
            .await
            .map_err(|_| anyhow::anyhow!("yamux driver closed"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("yamux driver dropped response channel"))?
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.yamux_conns == 0 {
        anyhow::bail!("yamux_conns must be >= 1");
    }

    let _ = std::fs::remove_file(&args.uds);

    let listener = UnixListener::bind(&args.uds)
        .with_context(|| format!("failed to bind UDS at {}", args.uds))?;

    let pool = Arc::new(
        YamuxPool::new(&args.yamux_addr, args.yamux_conns)
            .await
            .context("failed to connect yamux")?,
    );

    info!(
        "listening on {}, forwarding to yamux {} (pool size {})",
        args.uds, args.yamux_addr, args.yamux_conns
    );

    loop {
        let (uds_stream, _) = listener
            .accept()
            .await
            .context("failed to accept UDS connection")?;

        let pool = pool.clone();
        tokio::spawn(async move {
            let stream = match pool.open_stream().await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("failed to open yamux stream: {e}");
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
