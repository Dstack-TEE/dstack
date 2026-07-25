// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::config::ProxyConfig;
use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use std::time::Duration;
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
                self.writer
                    .write_buf(&mut self.buf)
                    .await
                    .context("write error")?;
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

    // One watchdog for the whole connection replaces the per-operation timeouts.
    // It samples the progress counters; if neither direction has moved for
    // `idle`, the connection is stalled. Ticking a few times per idle window
    // costs one timer per window instead of three per request.
    let idle = config.timeouts.idle;
    let tick = (idle / 4).max(Duration::from_millis(500));
    let mut watchdog = tokio::time::interval(tick);
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    watchdog.tick().await; // the first tick completes immediately
    let mut last_seen = (0u64, 0u64);
    let mut idle_ticks = 0u32;
    let max_idle_ticks = (idle.as_millis() / tick.as_millis()).max(1) as u32;

    let mut rest;
    // Transfer data between a and b bidirectionally.
    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                let seen = (a2b.progress, b2a.progress);
                if seen == last_seen {
                    idle_ticks += 1;
                    if idle_ticks >= max_idle_ticks {
                        bail!("idle timeout");
                    }
                } else {
                    idle_ticks = 0;
                    last_seen = seen;
                }
            }
            done = a2b.step() => {
                if done? {
                    // a to b is EOF, switch to b to a only
                    rest = Rest::B2a(b2a);
                    drop(a2b);
                    break;
                }
            }
            done = b2a.step() => {
                if done? {
                    // b to a is EOF, switch to a to b only
                    rest = Rest::A2b(a2b);
                    drop(b2a);
                    break;
                }
            }
        }
    }

    // One of the direction is closed, copy the other direction.
    match &mut rest {
        Rest::A2b(a2b) => loop {
            if a2b.step().await? {
                break;
            }
        },
        Rest::B2a(b2a) => loop {
            if b2a.step().await? {
                break;
            }
        },
    }
    Ok(())
}
