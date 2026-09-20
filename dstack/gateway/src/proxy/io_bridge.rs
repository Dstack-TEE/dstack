// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use super::idle::IdleWatchdog;
use crate::config::ProxyConfig;
use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

#[derive(Debug)]
enum NextStep {
    Read,
    Write,
    Flush,
    Shutdown,
    Done,
}

struct OneDirection<'a, R, W> {
    dir: &'static str,
    cfg: &'a ProxyConfig,
    buf: BytesMut,
    reader: &'a mut R,
    writer: &'a mut W,
    next_step: NextStep,
    /// Bumped whenever this direction makes progress. The watchdog samples it
    /// instead of the clock, so the hot path costs an integer increment rather
    /// than arming a timer per read/write/flush.
    progress: u64,
}

impl<R, W> OneDirection<'_, R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    async fn step(&mut self) -> Result<bool> {
        match self.next_step {
            NextStep::Read => {
                let n = self
                    .reader
                    .read_buf(&mut self.buf)
                    .await
                    .context("read error")?;
                self.progress += 1;
                trace!(direction = %self.dir, "read: {n} bytes");
                if n == 0 {
                    self.next_step = NextStep::Shutdown;
                } else {
                    self.next_step = NextStep::Write;
                }
                Ok(false)
            }
            NextStep::Write => {
                let n = self
                    .writer
                    .write_buf(&mut self.buf)
                    .await
                    .context("write error")?;
                // A writer that takes nothing while reporting success can no
                // longer accept bytes. Without this the state stays `Write`
                // with a non-empty buffer, the loop re-enters at once, and the
                // zero-length write counts as progress -- so the watchdog sees
                // a busy connection and the bridge spins hot on a core until
                // `timeouts.total`. The relay paths bail the same way.
                if n == 0 && !self.buf.is_empty() {
                    bail!("write accepted no bytes");
                }
                self.progress += 1;
                if self.buf.is_empty() {
                    self.next_step = NextStep::Flush;
                }
                Ok(false)
            }
            NextStep::Flush => {
                self.writer.flush().await.context("flush error")?;
                self.progress += 1;
                self.next_step = NextStep::Read;
                Ok(false)
            }
            NextStep::Shutdown => {
                timeout(self.cfg.timeouts.shutdown, self.writer.shutdown())
                    .await
                    .ok()
                    .context("shutdown timeout")?
                    .context("shutdown error")?;
                self.next_step = NextStep::Done;
                Ok(true)
            }
            NextStep::Done => Ok(true),
        }
    }
}

enum Rest<A, B> {
    A2b(A),
    B2a(B),
}

/// Relay between two TCP sockets.
///
/// Same logic as [`bridge`], but splitting a `TcpStream` with its own `split()`
/// hands out borrowed halves, where the generic `tokio::io::split` has to wrap
/// the stream in a `BiLock`. That lock showed up at 1.1% of total time on the
/// small-request passthrough profile, and passthrough always has a plain socket
/// on both sides, so it never needs the generic path.
pub(crate) async fn bridge_tcp(
    mut a: TcpStream,
    mut b: TcpStream,
    config: &ProxyConfig,
) -> Result<()> {
    let buf_size = config.buffer_size;
    if !config.timeouts.data_timeout_enabled {
        tokio::io::copy_bidirectional_with_sizes(&mut a, &mut b, buf_size, buf_size)
            .await
            .context("failed to copy")?;
        return Ok(());
    }
    let (mut ra, mut wa) = a.split();
    let (mut rb, mut wb) = b.split();
    relay(&mut ra, &mut wa, &mut rb, &mut wb, config).await
}

pub(crate) async fn bridge<A, B>(mut a: A, mut b: B, config: &ProxyConfig) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let buf_size = config.buffer_size;
    if !config.timeouts.data_timeout_enabled {
        debug!("copying bidirectionally");
        tokio::io::copy_bidirectional_with_sizes(&mut a, &mut b, buf_size, buf_size)
            .await
            .context("failed to copy")?;
        return Ok(());
    }

    let (mut ra, mut wa) = tokio::io::split(a);
    let (mut rb, mut wb) = tokio::io::split(b);
    relay(&mut ra, &mut wa, &mut rb, &mut wb, config).await
}

/// Drive both directions until each has seen EOF and been shut down.
async fn relay<RA, WA, RB, WB>(
    ra: &mut RA,
    wa: &mut WA,
    rb: &mut RB,
    wb: &mut WB,
    config: &ProxyConfig,
) -> Result<()>
where
    RA: AsyncRead + Unpin,
    WA: AsyncWrite + Unpin,
    RB: AsyncRead + Unpin,
    WB: AsyncWrite + Unpin,
{
    let buf_size = config.buffer_size;
    let mut a2b = OneDirection {
        dir: "a2b",
        cfg: config,
        buf: BytesMut::with_capacity(buf_size),
        reader: ra,
        writer: wb,
        next_step: NextStep::Read,
        progress: 0,
    };
    let mut b2a = OneDirection {
        dir: "b2a",
        cfg: config,
        buf: BytesMut::with_capacity(buf_size),
        reader: rb,
        writer: wa,
        next_step: NextStep::Read,
        progress: 0,
    };

    // One watchdog for the whole connection replaces the per-operation timeouts:
    // it samples both directions' progress counters, so a connection only dies
    // when neither has moved. See `super::idle`.
    let mut watchdog = IdleWatchdog::new(config.timeouts.idle);
    watchdog.tick().await; // the first tick completes immediately

    let mut rest;
    // Progress of the direction that finishes first, frozen at that point. The
    // watchdog samples a monotonic counter, so the drain phase has to keep
    // adding it rather than restart from the surviving direction alone.
    // Assigned on every path that leaves the loop, like `rest`.
    let finished: u64;
    // Transfer data between a and b bidirectionally.
    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                if watchdog.stalled(a2b.progress + b2a.progress) {
                    bail!("idle timeout");
                }
            }
            done = a2b.step() => {
                if done? {
                    // a to b is EOF, switch to b to a only
                    finished = a2b.progress;
                    rest = Rest::B2a(b2a);
                    drop(a2b);
                    break;
                }
            }
            done = b2a.step() => {
                if done? {
                    // b to a is EOF, switch to a to b only
                    finished = b2a.progress;
                    rest = Rest::A2b(a2b);
                    drop(b2a);
                    break;
                }
            }
        }
    }

    // One direction is closed; drain the other -- still watched. Half-close is
    // not a licence to hang: before the watchdog existed each read carried its
    // own `idle` timeout, so this phase was covered, and leaving it bare let a
    // client hold a connection open until `timeouts.total` (5h) by
    // half-closing against a backend that never replies.
    match &mut rest {
        Rest::A2b(a2b) => drain(a2b, &mut watchdog, finished).await,
        Rest::B2a(b2a) => drain(b2a, &mut watchdog, finished).await,
    }
}

/// Pump the surviving direction to EOF, giving up if it stalls for `idle`.
async fn drain<R, W>(
    dir: &mut OneDirection<'_, R, W>,
    watchdog: &mut IdleWatchdog,
    finished: u64,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                if watchdog.stalled(finished + dir.progress) {
                    bail!("idle timeout");
                }
            }
            done = dir.step() => {
                if done? {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use std::time::Duration;

    /// A writer that reports success while accepting nothing -- what the
    /// `AsyncWrite` contract calls "can no longer accept bytes".
    struct AcceptsNothing;

    impl AsyncWrite for AcceptsNothing {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn test_config() -> ProxyConfig {
        crate::config::load_config_figment(None)
            .focus("core.proxy")
            .extract()
            .expect("the shipped default config should parse")
    }

    /// A zero-length write leaves the direction in `Write` with a non-empty
    /// buffer, so the loop re-enters immediately -- and it used to count as
    /// progress, which kept the idle watchdog quiet while the bridge span hot
    /// on a core until `timeouts.total`.
    ///
    /// The bridge gets a thread and a runtime of its own because that spin
    /// never yields: a timeout sharing its runtime would never be polled, and
    /// dropping a runtime whose task never returns hangs the test.
    #[test]
    fn a_writer_that_accepts_no_bytes_is_an_error_not_a_spin() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let outcome = rt.block_on(async {
                let config = test_config();
                let mut client_rx: &[u8] = b"request";
                let mut client_tx = tokio::io::sink();
                // The app never answers, so only the direction facing the
                // writer that takes nothing can make progress.
                let mut app_rx = tokio::io::empty();
                let mut app_tx = AcceptsNothing;
                match relay(
                    &mut client_rx,
                    &mut client_tx,
                    &mut app_rx,
                    &mut app_tx,
                    &config,
                )
                .await
                {
                    Ok(()) => "the bridge returned success".to_string(),
                    Err(err) => format!("{err:#}"),
                }
            });
            tx.send(outcome).ok();
        });

        let outcome = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the bridge never came back from a zero-length write");
        assert!(outcome.contains("write accepted no bytes"), "{outcome}");
    }
}
