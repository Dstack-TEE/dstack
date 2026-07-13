// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::config::ProxyConfig;
use anyhow::{Context, Result};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
}

impl<R, W> OneDirection<'_, R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    async fn step(&mut self) -> Result<bool> {
        match self.next_step {
            NextStep::Read => {
                let n = timeout(self.cfg.timeouts.idle, self.reader.read_buf(&mut self.buf))
                    .await
                    .ok()
                    .context("idle timeout")?
                    .context("read error")?;
                trace!(direction = %self.dir, "read: {n} bytes");
                if n == 0 {
                    self.next_step = NextStep::Shutdown;
                } else {
                    self.next_step = NextStep::Write;
                }
                Ok(false)
            }
            NextStep::Write => {
                timeout(
                    self.cfg.timeouts.write,
                    self.writer.write_buf(&mut self.buf),
                )
                .await
                .ok()
                .context("write timeout")?
                .context("write error")?;
                if self.buf.is_empty() {
                    self.next_step = NextStep::Flush;
                }
                Ok(false)
            }
            NextStep::Flush => {
                timeout(self.cfg.timeouts.write, self.writer.flush())
                    .await
                    .ok()
                    .context("flush timeout")?
                    .context("flush error")?;
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

    let mut a2b = OneDirection {
        dir: "a2b",
        cfg: config,
        buf: BytesMut::with_capacity(buf_size),
        reader: &mut ra,
        writer: &mut wb,
        next_step: NextStep::Read,
    };
    let mut b2a = OneDirection {
        dir: "b2a",
        cfg: config,
        buf: BytesMut::with_capacity(buf_size),
        reader: &mut rb,
        writer: &mut wa,
        next_step: NextStep::Read,
    };

    let mut rest;
    // Transfer data between a and b bidirectionally.
    loop {
        tokio::select! {
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
