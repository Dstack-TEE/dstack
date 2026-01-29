// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Echo server for testing QUIC connectivity (null crypto — no encryption).
//!
//! Listens for QUIC connections over UDP, accepts bidirectional streams,
//! and echoes back any data received.
//!
//! Usage:
//!   vsock-echo --udp-port 4433                 # QUIC echo server
//!   vsock-echo --tcp-port 8080                 # TCP echo server
//!   vsock-echo --yamux-port 9090               # yamux-over-TCP echo server
//!   vsock-echo --udp-port 4433 --tcp-port 8080 # both

use anyhow::{Context, Result};
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

#[derive(Parser)]
#[command(about = "QUIC/TCP/yamux echo server for testing")]
struct Args {
    /// UDP port to listen on for QUIC connections
    #[arg(long)]
    udp_port: Option<u16>,

    /// TCP port to listen on for TCP connections
    #[arg(long)]
    tcp_port: Option<u16>,

    /// TCP port to listen on for yamux-over-TCP connections
    #[arg(long)]
    yamux_port: Option<u16>,

    /// Number of UDP SO_REUSEPORT workers (each gets its own quinn endpoint)
    #[arg(long, default_value = "1")]
    udp_workers: usize,
}

static ACTIVE: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);

fn spawn_echo(stream: (quinn::SendStream, quinn::RecvStream)) {
    let id = TOTAL.fetch_add(1, Ordering::Relaxed);
    let active = ACTIVE.fetch_add(1, Ordering::Relaxed) + 1;
    if id.is_multiple_of(100) {
        info!("conn #{id}, active={active}");
    }

    let (mut send, mut recv) = stream;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok(Some(n)) = recv.read(&mut buf).await {
            if send.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
        let remaining = ACTIVE.fetch_sub(1, Ordering::Relaxed) - 1;
        if id.is_multiple_of(100) {
            info!("conn #{id} closed, active={remaining}");
        }
    });
}

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

fn make_reuseport_udp_socket(port: u16) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create socket")?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    let addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse()?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

async fn run_quic_echo_worker(port: u16, worker_id: usize, reuseport: bool) -> Result<()> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(100_000u32.into());
    let mut server_config =
        quinn::ServerConfig::new(
            Arc::new(quinn::crypto::null::NullServerConfig),
            Arc::new(quinn::crypto::null::NullHandshakeTokenKey),
        );
    server_config.transport_config(Arc::new(transport));

    let endpoint_config = quinn::EndpointConfig::new(Arc::new(quinn::crypto::null::NullHmacKey));
    let socket = if reuseport {
        make_reuseport_udp_socket(port)?
    } else {
        std::net::UdpSocket::bind(format!("0.0.0.0:{port}"))?
    };
    let runtime = Arc::new(quinn::TokioRuntime);
    let endpoint = quinn::Endpoint::new(endpoint_config, Some(server_config), socket, runtime)
        .context("failed to bind QUIC endpoint")?;

    info!("QUIC echo worker {worker_id} listening on UDP port {port} (null crypto)");

    while let Some(incoming) = endpoint.accept().await {
        let conn = match incoming.await {
            Ok(conn) => conn,
            Err(e) => {
                error!("worker {worker_id}: failed to accept QUIC connection: {e}");
                continue;
            }
        };
        info!("worker {worker_id}: new QUIC connection from {}", conn.remote_address());
        tokio::spawn(async move {
            loop {
                match conn.accept_bi().await {
                    Ok(stream) => spawn_echo(stream),
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        info!("QUIC connection closed");
                        break;
                    }
                    Err(e) => {
                        error!("QUIC accept_bi error: {e}");
                        break;
                    }
                }
            }
        });
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if args.udp_port.is_none() && args.tcp_port.is_none() && args.yamux_port.is_none() {
        anyhow::bail!("specify at least one of --udp-port, --tcp-port, or --yamux-port");
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

    if let Some(port) = args.udp_port {
        let workers = args.udp_workers;
        let reuseport = workers > 1;
        for i in 0..workers {
            tasks.push(tokio::spawn(async move {
                if let Err(e) = run_quic_echo_worker(port, i, reuseport).await {
                    error!("QUIC echo worker {i} error: {e}");
                }
            }));
        }
    }

    for t in tasks {
        let _ = t.await;
    }

    Ok(())
}
