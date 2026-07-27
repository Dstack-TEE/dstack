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

use std::time::Instant;

use anyhow::{Context, Result};
use ktls::CorkStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::debug;

use super::splice::splice_bidirectional;
use crate::config::{EngageAfter, SpliceConfig};

/// Why the userspace relay phase stopped.
enum Phase {
    /// The connection proved itself worth the offload.
    Gated,
    /// One side closed before the gate fired.
    Eof,
}

/// Relay both directions in userspace until either side closes or `gate` fires.
async fn relay_until<S>(tls: &mut S, upstream: &mut TcpStream, gate: &EngageAfter) -> Result<Phase>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut tr, mut tw) = tokio::io::split(tls);
    let (mut ur, mut uw) = upstream.split();
    let mut down = vec![0u8; 32 * 1024];
    let mut up = vec![0u8; 32 * 1024];
    let mut moved: u64 = 0;
    let start = Instant::now();

    let phase = loop {
        tokio::select! {
            r = tr.read(&mut down) => {
                let n = r.context("read from client failed")?;
                if n == 0 { break Phase::Eof; }
                uw.write_all(&down[..n]).await.context("write to app failed")?;
                moved += n as u64;
            }
            r = ur.read(&mut up) => {
                let n = r.context("read from app failed")?;
                if n == 0 { break Phase::Eof; }
                tw.write_all(&up[..n]).await.context("write to client failed")?;
                moved += n as u64;
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
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + std::os::fd::AsRawFd + ktls::AsyncReadReady,
    IO: Into<TcpStream>,
{
    match relay_until(&mut tls, &mut upstream, ktls).await? {
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
    splice_bidirectional(io.into(), upstream, splice.release_idle_pipes)
        .await
        .context("splice after kTLS offload failed")
}
