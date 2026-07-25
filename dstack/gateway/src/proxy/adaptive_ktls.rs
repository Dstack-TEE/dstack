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
//! only hands it to the kernel once it has proven itself: after
//! `offload_after_bytes` have been relayed, the stream is drained at a TLS
//! record boundary and switched to kTLS + splice for the remainder.
//!
//! Handing over mid-stream is sound because the secrets rustls exports carry
//! the current record sequence numbers, and `CorkStream` exists precisely to
//! stop reads at a record boundary so nothing is left half-parsed.

use anyhow::{Context, Result};
use ktls::CorkStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::debug;

use super::splice::splice_bidirectional;

/// Why the userspace relay phase stopped.
enum Phase {
    /// Enough bytes moved to justify the offload.
    Threshold,
    /// One side closed before the threshold was reached.
    Eof,
}

/// Relay both directions in userspace until either side closes or `threshold`
/// bytes have been transferred in total.
async fn relay_until<S>(tls: &mut S, upstream: &mut TcpStream, threshold: u64) -> Result<Phase>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut tr, mut tw) = tokio::io::split(tls);
    let (mut ur, mut uw) = upstream.split();
    let mut down = vec![0u8; 32 * 1024];
    let mut up = vec![0u8; 32 * 1024];
    let mut moved: u64 = 0;

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
        if moved >= threshold {
            // Flush before handing the socket to the kernel so no plaintext is
            // still sitting in a rustls write buffer.
            tw.flush().await.context("flush before offload failed")?;
            break Phase::Threshold;
        }
    };
    Ok(phase)
}

/// Relay a freshly accepted TLS connection, upgrading it to kTLS + splice once
/// it has moved `threshold` bytes.
pub(crate) async fn relay_with_adaptive_offload<IO>(
    mut tls: TlsStream<CorkStream<IO>>,
    mut upstream: TcpStream,
    threshold: u64,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + std::os::fd::AsRawFd + ktls::AsyncReadReady,
    IO: Into<TcpStream>,
{
    match relay_until(&mut tls, &mut upstream, threshold).await? {
        Phase::Eof => return Ok(()),
        Phase::Threshold => {}
    }
    debug!("offloading connection to kTLS after {threshold} bytes");

    // config_ktls_server corks the stream, drains rustls to a record boundary
    // and installs the current traffic secrets into the kernel.
    let ktls_stream = ktls::config_ktls_server(tls)
        .await
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
    splice_bidirectional(io.into(), upstream)
        .await
        .context("splice after kTLS offload failed")
}
