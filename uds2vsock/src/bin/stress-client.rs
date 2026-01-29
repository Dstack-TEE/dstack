// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Stress test client for UDS, TCP, or QUIC connections.
//!
//! Opens N concurrent connections, sends a payload, reads echo, then holds.
//! Reports peak concurrent connections and statistics.
//!
//! Usage:
//!   # Direct TCP test
//!   stress-client --tcp localhost:8080 --concurrency 1000 --total 10000
//!
//!   # QUIC multiplexed test (single connection, unlimited streams)
//!   stress-client --quic localhost:4433 --concurrency 100000 --total 100000

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::Semaphore;

#[derive(Parser)]
#[command(about = "Stress test client for connection throughput and concurrency limits")]
struct Args {
    /// UDS path to connect to
    #[arg(long)]
    uds: Option<String>,

    /// TCP address to connect to (host:port)
    #[arg(long)]
    tcp: Option<String>,

    /// QUIC address to connect to (host:port) — uses UDP, streams are multiplexed
    #[arg(long)]
    quic: Option<String>,

    /// yamux-over-TCP address (host:port) — streams multiplexed over TCP connection(s)
    #[arg(long)]
    yamux: Option<String>,

    /// Number of TCP connections in yamux pool (default 1)
    #[arg(long, default_value = "1")]
    yamux_conns: usize,

    /// Maximum concurrent connections/streams
    #[arg(long, default_value = "1000")]
    concurrency: usize,

    /// Total number of connections/streams to make
    #[arg(long, default_value = "10000")]
    total: u64,

    /// Payload size in bytes
    #[arg(long, default_value = "128")]
    payload_size: usize,

    /// Hold connection open for this many ms (0 = close immediately after echo)
    #[arg(long, default_value = "0")]
    hold_ms: u64,

    /// Max new connections per second (0 = unlimited)
    #[arg(long, default_value = "0")]
    ramp_rate: u64,

    /// Print a status line every N seconds while connections are held (0 = no periodic status)
    #[arg(long, default_value = "2")]
    status_interval: u64,
}

#[derive(Clone, Debug)]
enum Target {
    Uds(String),
    Tcp(String),
    Quic(String),
    Yamux(String),
}

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

async fn connect(target: &Target) -> Result<Box<dyn AsyncStream>> {
    match target {
        Target::Uds(path) => {
            let stream = UnixStream::connect(path)
                .await
                .with_context(|| format!("failed to connect to UDS {path}"))?;
            Ok(Box::new(stream))
        }
        Target::Tcp(addr) => {
            let stream = TcpStream::connect(addr)
                .await
                .with_context(|| format!("failed to connect to TCP {addr}"))?;
            Ok(Box::new(stream))
        }
        Target::Quic(_) | Target::Yamux(_) => {
            bail!("use multiplexed connection, not connect()")
        }
    }
}

/// Wrapper that combines quinn SendStream + RecvStream into a single AsyncRead + AsyncWrite.
struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncRead::poll_read(std::pin::Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}

type YamuxRequest = tokio::sync::oneshot::Sender<Result<yamux::Stream>>;

/// Spawns a single yamux connection driver task.
fn spawn_yamux_driver(
    addr: String,
) -> Result<(
    tokio::sync::mpsc::Sender<YamuxRequest>,
    tokio::task::JoinHandle<()>,
)> {
    let (tx, rx) = tokio::sync::mpsc::channel::<YamuxRequest>(1024);
    let handle = tokio::spawn(async move {
        use tokio_util::compat::TokioAsyncReadCompatExt;

        let tcp = match TcpStream::connect(&addr).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("yamux driver: failed to connect to {addr}: {e}");
                return;
            }
        };
        let cfg = yamux::Config::default();
        let mut conn = yamux::Connection::new(tcp.compat(), cfg, yamux::Mode::Client);
        let mut rx = rx;
        let mut pending: Vec<YamuxRequest> = Vec::new();

        loop {
            use std::task::Poll;

            let result = std::future::poll_fn(|cx| {
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(_))) => {}
                    Poll::Ready(Some(Err(e))) => return Poll::Ready(Err::<(), _>(e)),
                    Poll::Ready(None) => return Poll::Ready(Err(yamux::ConnectionError::Closed)),
                    Poll::Pending => {}
                }

                loop {
                    match rx.poll_recv(cx) {
                        Poll::Ready(Some(sender)) => pending.push(sender),
                        Poll::Ready(None) => {
                            return Poll::Ready(Err(yamux::ConnectionError::Closed))
                        }
                        Poll::Pending => break,
                    }
                }

                while !pending.is_empty() {
                    match conn.poll_new_outbound(cx) {
                        Poll::Ready(result) => {
                            if let Some(sender) = pending.pop() {
                                let _ = sender.send(result.map_err(Into::into));
                            }
                        }
                        Poll::Pending => break,
                    }
                }

                Poll::Pending
            })
            .await;

            if let Err(e) = result {
                if !matches!(e, yamux::ConnectionError::Closed) {
                    eprintln!("yamux connection error: {e}");
                }
                break;
            }
        }
    });
    Ok((tx, handle))
}

/// Pool of yamux connections with round-robin stream opening.
struct YamuxPool {
    senders: Vec<tokio::sync::mpsc::Sender<YamuxRequest>>,
    next: std::sync::atomic::AtomicUsize,
}

impl YamuxPool {
    async fn new(addr: &str, num_conns: usize) -> Result<(Self, Vec<tokio::task::JoinHandle<()>>)> {
        let mut senders = Vec::with_capacity(num_conns);
        let mut handles = Vec::with_capacity(num_conns);
        for _ in 0..num_conns {
            let (tx, handle) = spawn_yamux_driver(addr.to_string())?;
            senders.push(tx);
            handles.push(handle);
        }
        Ok((
            Self {
                senders,
                next: std::sync::atomic::AtomicUsize::new(0),
            },
            handles,
        ))
    }

    async fn open_stream(&self) -> Result<Box<dyn AsyncStream>> {
        use tokio_util::compat::FuturesAsyncReadCompatExt;

        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.senders[idx]
            .send(tx)
            .await
            .map_err(|_| anyhow::anyhow!("yamux driver closed"))?;
        let stream = rx
            .await
            .map_err(|_| anyhow::anyhow!("yamux driver dropped"))??;
        Ok(Box::new(stream.compat()))
    }
}

/// QUIC connection that can open bidirectional streams.
struct QuicConn {
    connection: quinn::Connection,
}

impl QuicConn {
    async fn new(addr: &str) -> Result<Self> {
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(100_000u32.into());
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(quinn::crypto::null::NullClientConfig));
        client_config.transport_config(Arc::new(transport));

        let endpoint_config =
            quinn::EndpointConfig::new(Arc::new(quinn::crypto::null::NullHmacKey));
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let runtime = Arc::new(quinn::TokioRuntime);
        let endpoint = quinn::Endpoint::new(endpoint_config, None, socket, runtime)?;
        endpoint.set_default_client_config(client_config);

        let connection = endpoint
            .connect(addr.parse().context("invalid QUIC address")?, "localhost")
            .context("failed to start QUIC connect")?
            .await
            .context("failed to establish QUIC connection")?;

        Ok(Self { connection })
    }

    async fn open_stream(&self) -> Result<Box<dyn AsyncStream>> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .context("failed to open QUIC bi stream")?;
        Ok(Box::new(QuicBiStream { send, recv }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let target = match (&args.uds, &args.tcp, &args.quic, &args.yamux) {
        (Some(path), None, None, None) => Target::Uds(path.clone()),
        (None, Some(addr), None, None) => Target::Tcp(addr.clone()),
        (None, None, Some(addr), None) => Target::Quic(addr.clone()),
        (None, None, None, Some(addr)) => Target::Yamux(addr.clone()),
        _ => bail!("specify exactly one of --uds, --tcp, --quic, or --yamux"),
    };

    // Set up multiplexed connection if requested
    let quic_conn = if let Target::Quic(ref addr) = target {
        let conn = QuicConn::new(addr).await?;
        eprintln!("QUIC connection established to {addr}");
        Some(Arc::new(conn))
    } else {
        None
    };

    let yamux_conn = if let Target::Yamux(ref addr) = target {
        let n = args.yamux_conns;
        let (pool, _handles) = YamuxPool::new(addr, n).await?;
        eprintln!("yamux pool established to {addr} ({n} TCP connections)");
        Some(Arc::new(pool))
    } else {
        None
    };

    let payload = vec![0x42u8; args.payload_size];
    let payload = Arc::new(payload);
    let semaphore = Arc::new(Semaphore::new(args.concurrency));

    let success = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let connect_err = Arc::new(AtomicU64::new(0));
    let write_err = Arc::new(AtomicU64::new(0));
    let read_err = Arc::new(AtomicU64::new(0));
    let peak_concurrent = Arc::new(AtomicU64::new(0));
    let current_concurrent = Arc::new(AtomicU64::new(0));

    // Periodic status reporter
    if args.status_interval > 0 && args.hold_ms > 0 {
        let current = current_concurrent.clone();
        let peak = peak_concurrent.clone();
        let success = success.clone();
        let failed = failed.clone();
        let interval = args.status_interval;
        tokio::spawn(async move {
            let start = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_secs(interval)).await;
                let c = current.load(Ordering::Relaxed);
                let p = peak.load(Ordering::Relaxed);
                let s = success.load(Ordering::Relaxed);
                let f = failed.load(Ordering::Relaxed);
                eprintln!(
                    "[{:>6.1}s] active={c} peak={p} success={s} failed={f}",
                    start.elapsed().as_secs_f64()
                );
            }
        });
    }

    let mode = if quic_conn.is_some() {
        "quic"
    } else if yamux_conn.is_some() {
        "yamux"
    } else {
        "direct"
    };
    eprintln!(
        "starting: target={target:?} mode={mode} total={} concurrency={} hold={}ms",
        args.total, args.concurrency, args.hold_ms
    );

    let start = Instant::now();
    let mut handles = Vec::with_capacity(args.total as usize);

    let interval_per_conn = if args.ramp_rate > 0 {
        Some(Duration::from_secs_f64(1.0 / args.ramp_rate as f64))
    } else {
        None
    };

    for i in 0..args.total {
        if let Some(interval) = interval_per_conn {
            tokio::time::sleep(interval).await;
        }

        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let target = target.clone();
        let payload = payload.clone();
        let success = success.clone();
        let failed = failed.clone();
        let connect_err = connect_err.clone();
        let write_err = write_err.clone();
        let read_err = read_err.clone();
        let peak = peak_concurrent.clone();
        let current = current_concurrent.clone();
        let hold_ms = args.hold_ms;
        let total = args.total;
        let quic_conn = quic_conn.clone();
        let yamux_conn = yamux_conn.clone();

        handles.push(tokio::spawn(async move {
            let cur = current.fetch_add(1, Ordering::Relaxed) + 1;
            peak.fetch_max(cur, Ordering::Relaxed);

            let result: Result<()> = async {
                let mut stream = if let Some(ref conn) = quic_conn {
                    conn.open_stream().await.inspect_err(|e| {
                        let prev = connect_err.fetch_add(1, Ordering::Relaxed);
                        if prev < 3 {
                            eprintln!("connect error #{}: {e:#}", prev + 1);
                        }
                    })?
                } else if let Some(ref conn) = yamux_conn {
                    conn.open_stream().await.inspect_err(|e| {
                        let prev = connect_err.fetch_add(1, Ordering::Relaxed);
                        if prev < 3 {
                            eprintln!("connect error #{}: {e:#}", prev + 1);
                        }
                    })?
                } else {
                    connect(&target).await.inspect_err(|e| {
                        let prev = connect_err.fetch_add(1, Ordering::Relaxed);
                        if prev < 3 {
                            eprintln!("connect error #{}: {e:#}", prev + 1);
                        }
                    })?
                };
                stream.write_all(&payload).await.map_err(|e| {
                    write_err.fetch_add(1, Ordering::Relaxed);
                    anyhow::anyhow!(e)
                })?;
                let mut buf = vec![0u8; payload.len()];
                tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
                    .await
                    .map_err(|_| {
                        read_err.fetch_add(1, Ordering::Relaxed);
                        anyhow::anyhow!("read timeout")
                    })?
                    .map_err(|e| {
                        read_err.fetch_add(1, Ordering::Relaxed);
                        anyhow::anyhow!(e)
                    })?;
                if hold_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(hold_ms)).await;
                }
                Ok(())
            }
            .await;

            current.fetch_sub(1, Ordering::Relaxed);
            drop(permit);

            match result {
                Ok(()) => {
                    success.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                }
            }

            if (i + 1).is_multiple_of(1000) {
                let s = success.load(Ordering::Relaxed);
                let f = failed.load(Ordering::Relaxed);
                eprintln!("[{:>6}/{:>6}] success={s} failed={f}", i + 1, total);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let elapsed = start.elapsed();
    let s = success.load(Ordering::Relaxed);
    let f = failed.load(Ordering::Relaxed);
    let ce = connect_err.load(Ordering::Relaxed);
    let we = write_err.load(Ordering::Relaxed);
    let re = read_err.load(Ordering::Relaxed);
    let peak = peak_concurrent.load(Ordering::Relaxed);

    eprintln!();
    eprintln!("=== Results ===");
    eprintln!("target:       {target:?}");
    eprintln!("mode:         {mode}");
    eprintln!("total:        {}", args.total);
    eprintln!("concurrency:  {}", args.concurrency);
    eprintln!("success:      {s}");
    eprintln!("failed:       {f}");
    eprintln!("  connect_err:  {ce}");
    eprintln!("  write_err:    {we}");
    eprintln!("  read_err:     {re}");
    eprintln!("peak_conns:   {peak}");
    eprintln!("elapsed:      {elapsed:.2?}");
    if elapsed.as_secs_f64() > 0.0 {
        eprintln!(
            "throughput:   {:.0} conn/s",
            s as f64 / elapsed.as_secs_f64()
        );
    }

    if f > 0 {
        eprintln!("\nWARNING: {f} connections failed!");
        std::process::exit(1);
    }
    Ok(())
}
