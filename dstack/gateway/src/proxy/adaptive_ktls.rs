// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Traffic-triggered kernel TLS offload.
//!
//! Measurements show the two halves of kTLS pull in opposite directions:
//! enabling it costs ~30% of connection setup rate (secret extraction plus
//! kernel ULP setup per connection) but wins ~25% on bulk throughput once
//! combined with splice. Short request/response connections therefore pay the
//! setup cost and never earn it back.
//!
//! This module keeps the connection in userspace rustls after the handshake and
//! only hands it to the kernel once it has proven itself: once the configured
//! [`EngageAfter`] gate fires, the stream is drained at a TLS record boundary
//! and switched to kTLS + splice for the remainder.
//!
//! Handing over mid-stream is sound because the secrets rustls exports carry
//! the current record sequence numbers, and `CorkStream` exists precisely to
//! stop reads at a record boundary so nothing is left half-parsed.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use ktls::CorkStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::debug;

use super::idle::IdleWatchdog;
use super::splice::{splice_bidirectional, CloseKind};
use super::tls_terminate::SocketParts;
use crate::config::{EngageAfter, SpliceConfig};

/// Why the userspace relay phase stopped.
enum Phase {
    /// The connection proved itself worth the offload.
    Gated,
    /// One side closed before the gate fired.
    Eof,
}

/// Relay both directions in userspace until either side closes or `gate` fires.
async fn relay_until<S>(
    tls: &mut S,
    upstream: &mut TcpStream,
    gate: &EngageAfter,
    idle: Option<Duration>,
) -> Result<Phase>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut tr, mut tw) = tokio::io::split(tls);
    let (mut ur, mut uw) = upstream.split();
    let mut down = vec![0u8; 32 * 1024];
    let mut up = vec![0u8; 32 * 1024];
    let mut moved: u64 = 0;
    let start = Instant::now();
    let mut watchdog: Option<IdleWatchdog> = match idle {
        Some(idle) => {
            let mut w = IdleWatchdog::new(idle);
            w.tick().await; // the first tick completes immediately
            Some(w)
        }
        None => None,
    };

    let phase = loop {
        // `write_all` is not cancel-safe, so it cannot sit in a `select!` arm,
        // and awaiting it outside one left nothing polling the watchdog for as
        // long as the write blocked. A peer that stops reading fills the socket
        // buffer and parks the write there, which holds the connection to
        // `timeouts.total` from either end. Single `write` calls are
        // cancel-safe (nothing is written when the other branch wins), so the
        // partial-write loop is ours to drive -- with the watchdog in it.
        macro_rules! write_watched {
            ($w:expr, $buf:expr, $n:expr, $ctx:expr) => {{
                let n = $n;
                let mut written = 0usize;
                while written < n {
                    let count = tokio::select! {
                        () = async { match watchdog.as_mut() {
                            Some(w) => w.tick().await,
                            None => std::future::pending().await,
                        } } => {
                            if watchdog.as_mut().is_some_and(|w| w.stalled(moved)) {
                                bail!("idle timeout");
                            }
                            continue;
                        }
                        r = $w.write(&$buf[written..n]) => r.context($ctx)?,
                    };
                    if count == 0 {
                        bail!("write accepted no bytes");
                    }
                    written += count;
                    // Per partial write, so a peer draining slowly still counts
                    // as progress and is not reaped for being slow.
                    moved += count as u64;
                }
            }};
        }

        // One side closing is not the end of the connection: a client that ends
        // its request with close_notify still expects the response. Propagate
        // the EOF to that direction's peer, then drain the other direction
        // before giving up on the connection.
        macro_rules! finish_one {
            ($closing:expr, $r:expr, $w:expr, $buf:expr) => {{
                $closing.shutdown().await.ok();
                loop {
                    let n = tokio::select! {
                        () = async { match watchdog.as_mut() {
                            Some(w) => w.tick().await,
                            None => std::future::pending().await,
                        } } => {
                            // The drain is watched too: a backend that accepts the
                            // request and then never answers would otherwise hold
                            // the connection until `timeouts.total`.
                            if watchdog.as_mut().is_some_and(|w| w.stalled(moved)) {
                                bail!("idle timeout");
                            }
                            continue;
                        }
                        r = $r.read(&mut $buf) => r.context("read error")?,
                    };
                    if n == 0 {
                        break;
                    }
                    write_watched!($w, $buf, n, "write error");
                }
                $w.shutdown().await.ok();
                break Phase::Eof;
            }};
        }
        tokio::select! {
            () = async { match watchdog.as_mut() {
                Some(w) => w.tick().await,
                // No idle timeout configured: this arm must never win.
                None => std::future::pending().await,
            } } => {
                if watchdog.as_mut().is_some_and(|w| w.stalled(moved)) {
                    bail!("idle timeout");
                }
                continue;
            }
            r = tr.read(&mut down) => {
                let n = r.context("read from client failed")?;
                if n == 0 { finish_one!(uw, ur, tw, up); }
                write_watched!(uw, down, n, "write to app failed");
            }
            r = ur.read(&mut up) => {
                let n = r.context("read from app failed")?;
                if n == 0 { finish_one!(tw, tr, uw, down); }
                write_watched!(tw, up, n, "write to client failed");
            }
        }
        if gate.reached(moved, start) {
            // Flush before handing the socket to the kernel so no plaintext is
            // still sitting in a rustls write buffer.
            tw.flush().await.context("flush before offload failed")?;
            break Phase::Gated;
        }
    };
    Ok(phase)
}

/// Relay a freshly accepted TLS connection, upgrading it to kTLS + splice once
/// the kTLS gate fires. `splice` supplies the relay settings used afterwards.
pub(crate) async fn relay_with_adaptive_offload<IO>(
    mut tls: TlsStream<CorkStream<IO>>,
    mut upstream: TcpStream,
    ktls: &EngageAfter,
    splice: &SpliceConfig,
    idle: Option<Duration>,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + std::os::fd::AsRawFd + ktls::AsyncReadReady,
    IO: SocketParts,
{
    match relay_until(&mut tls, &mut upstream, ktls, idle).await? {
        Phase::Eof => return Ok(()),
        Phase::Gated => {}
    }
    debug!("offloading connection to kTLS after {ktls:?}");

    // config_ktls_server corks the stream, drains rustls to a record boundary
    // and installs the current traffic secrets into the kernel.
    let ktls_stream = super::stats::record_ktls_offload(ktls::config_ktls_server(tls).await)
        .context("failed to switch connection to kernel TLS")?;
    let (drained, io) = ktls_stream.into_raw();
    if let Some(drained) = drained {
        if !drained.is_empty() {
            upstream
                .write_all(&drained)
                .await
                .context("failed to flush drained data to app")?;
        }
    }
    // Same rule as the immediate offload path: the sniff remainder is raw
    // ciphertext, so it can neither be forwarded to the app nor pushed back
    // into a socket the kernel now owns. A completed handshake always consumes
    // it, so this is unreachable -- refuse rather than corrupt a stream if it
    // ever is not.
    let (buffered, tcp) = io.into_socket_parts();
    if !buffered.is_empty() {
        bail!(
            "{} bytes of unconsumed ciphertext at kTLS handover",
            buffered.len()
        );
    }
    // The client side is now a kTLS socket, so its close needs a close_notify.
    splice_bidirectional(
        tcp,
        upstream,
        splice.release_idle_pipes,
        idle,
        CloseKind::KernelTls,
    )
    .await
    .context("splice after kTLS offload failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    /// A gate no test connection reaches, so the relay stays in the userspace
    /// phase for the whole exchange. `relay_until` is generic over the client
    /// stream, so a plain socket stands in for the TLS one and the half-close
    /// handling is exercised without a handshake.
    fn ungated() -> EngageAfter {
        EngageAfter {
            after_bytes: Some(1 << 30),
            after_duration: None,
        }
    }

    /// Shrink both socket buffers so a few KiB of unread data is enough to
    /// park a write, instead of the megabytes loopback autotuning grows to.
    fn throttle(stream: &TcpStream) {
        let sock = socket2::SockRef::from(stream);
        sock.set_recv_buffer_size(4096).unwrap();
        sock.set_send_buffer_size(4096).unwrap();
    }

    /// A peer that stops reading parks the relay in a write, and a write is
    /// the one thing the pre-gate `select!` cannot watch: `write_all` is not
    /// cancel-safe, so it is awaited outside the `select!` and nothing polls
    /// the watchdog for as long as it blocks. The drain below already guards
    /// this; the main loop has to as well, or a client that sends a request
    /// and never reads the answer holds a relay until `timeouts.total`.
    ///
    /// Real timers rather than a paused clock: with time paused the runtime
    /// advances to the next deadline whenever no event is ready at that
    /// instant, which fires the watchdog on a relay that is merely waiting for
    /// loopback data -- so the test would pass without the write ever blocking.
    #[tokio::test]
    async fn a_client_that_stops_reading_is_reaped_by_the_idle_timeout() {
        let (client, mut tls_side) = connected_pair().await;
        let (mut upstream, mut backend) = connected_pair().await;
        for s in [&client, &tls_side, &upstream, &backend] {
            throttle(s);
        }

        // The app answers; the client never reads a byte of it.
        let _app = tokio::spawn(async move {
            backend.write_all(&vec![0u8; 1 << 20]).await.ok();
            backend
        });

        let idle = Duration::from_secs(1);
        let relayed = tokio::time::timeout(
            idle * 10,
            relay_until(&mut tls_side, &mut upstream, &ungated(), Some(idle)),
        )
        .await
        .expect("the relay outlived its idle window");
        let Err(err) = relayed else {
            panic!("the relay finished instead of reaping a stalled write");
        };
        assert!(err.to_string().contains("idle timeout"), "{err:#}");
        drop(client);
    }

    #[tokio::test]
    async fn response_survives_a_client_half_close_before_the_gate() {
        let (mut client, mut tls_side) = connected_pair().await;
        let (mut upstream, mut backend) = connected_pair().await;
        let relay = tokio::spawn(async move {
            relay_until(&mut tls_side, &mut upstream, &ungated(), None).await
        });

        client.write_all(b"ping").await.unwrap();
        client.shutdown().await.unwrap();

        let mut req = vec![0u8; 4];
        backend.read_exact(&mut req).await.unwrap();
        assert_eq!(&req, b"ping");
        let mut trailing = Vec::new();
        backend.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
        backend.write_all(b"pong").await.unwrap();
        drop(backend);

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"pong", "client lost the response after half-closing");
        assert!(matches!(relay.await.unwrap().unwrap(), Phase::Eof));
    }

    #[tokio::test]
    async fn request_survives_an_app_half_close_before_the_gate() {
        let (mut client, mut tls_side) = connected_pair().await;
        let (mut upstream, mut backend) = connected_pair().await;
        let relay = tokio::spawn(async move {
            relay_until(&mut tls_side, &mut upstream, &ungated(), None).await
        });

        backend.write_all(b"early").await.unwrap();
        backend.shutdown().await.unwrap();

        let mut resp = vec![0u8; 5];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"early");

        client.write_all(b"late").await.unwrap();
        drop(client);

        let mut got = Vec::new();
        backend.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"late", "app lost the request after half-closing");
        assert!(matches!(relay.await.unwrap().unwrap(), Phase::Eof));
    }
}
