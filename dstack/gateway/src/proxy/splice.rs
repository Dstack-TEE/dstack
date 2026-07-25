// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Zero-copy TCP relay using `splice(2)`.
//!
//! For the TLS-passthrough path both sides of the proxy are raw `TcpStream`s
//! and the gateway never inspects the (encrypted) payload. Instead of copying
//! bytes through a userspace buffer we move them kernel-side through a pipe with
//! `splice(2)`, which avoids two copies per direction and the associated CPU.
//!
//! Only used on Linux and only for the passthrough path; TLS-terminate still
//! uses the buffered bridge because one side is a decrypted rustls stream.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use anyhow::{Context, Result};
use nix::fcntl::{fcntl, splice, FcntlArg, SpliceFFlags};
use nix::sys::socket::{shutdown, Shutdown};
use nix::unistd::pipe;
use tokio::io::Interest;
use tokio::net::TcpStream;

/// Bytes moved per `splice` syscall. Also the target pipe capacity so a full
/// read can be buffered kernel-side before draining to the destination.
const PIPE_CAPACITY: usize = 1 << 20; // 1 MiB

fn set_pipe_capacity(fd: &OwnedFd, size: usize) {
    // Best-effort: larger pipes mean fewer syscalls for bulk transfers. If the
    // kernel rejects the size (e.g. over /proc/sys/fs/pipe-max-size) we simply
    // keep the default capacity.
    let _ = fcntl(
        fd.as_raw_fd(),
        FcntlArg::F_SETPIPE_SZ(size as std::os::raw::c_int),
    );
}

fn errno_to_io(e: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e as i32)
}

/// Per-thread cache of splice pipes.
///
/// Creating a pipe per direction per connection costs two `pipe2` calls plus
/// four descriptor closes, which is pure overhead for short connections: it
/// measurably raised passthrough connection-setup CPU (134 -> 142 us per
/// connection) while HAProxy, which pools its pipes, went the other way.
/// Reusing them keeps the bulk-transfer win without paying setup per
/// connection. Thread-local, so no locking -- and with thread-per-core a
/// connection stays on the thread that took the pipe.
const PIPE_POOL_MAX: usize = 64;

thread_local! {
    static PIPE_POOL: std::cell::RefCell<Vec<(OwnedFd, OwnedFd)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// A splice pipe borrowed from the thread-local pool.
///
/// Returned to the pool on drop, but only if the transfer drained it: a pipe
/// still holding bytes would corrupt the next connection that used it.
struct PooledPipe {
    rd: Option<OwnedFd>,
    wr: Option<OwnedFd>,
    drained: bool,
}

impl PooledPipe {
    fn get() -> Result<Self> {
        if let Some((rd, wr)) = PIPE_POOL.with(|p| p.borrow_mut().pop()) {
            return Ok(Self {
                rd: Some(rd),
                wr: Some(wr),
                drained: true,
            });
        }
        let (rd, wr) = pipe().context("failed to create splice pipe")?;
        set_pipe_capacity(&wr, PIPE_CAPACITY);
        Ok(Self {
            rd: Some(rd),
            wr: Some(wr),
            drained: true,
        })
    }

    fn rd(&self) -> &OwnedFd {
        self.rd.as_ref().expect("pipe read end present")
    }

    fn wr(&self) -> &OwnedFd {
        self.wr.as_ref().expect("pipe write end present")
    }
}

impl Drop for PooledPipe {
    fn drop(&mut self) {
        let (Some(rd), Some(wr)) = (self.rd.take(), self.wr.take()) else {
            return;
        };
        if !self.drained {
            // Unknown residue: close instead of poisoning the pool.
            return;
        }
        PIPE_POOL.with(|p| {
            let mut pool = p.borrow_mut();
            if pool.len() < PIPE_POOL_MAX {
                pool.push((rd, wr));
            }
        });
    }
}

/// Copy one direction (`src` -> `dst`) with splice until EOF, then half-close
/// the destination's write side.
async fn splice_one(src: Arc<TcpStream>, dst: Arc<TcpStream>) -> Result<()> {
    let mut pipe = PooledPipe::get()?;

    loop {
        // Move a chunk from the source socket into the pipe.
        let n = loop {
            src.readable().await.context("readable error")?;
            match src.try_io(Interest::READABLE, || {
                splice(
                    src.as_ref(),
                    None,
                    pipe.wr(),
                    None,
                    PIPE_CAPACITY,
                    SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_NONBLOCK,
                )
                .map_err(errno_to_io)
            }) {
                Ok(n) => break n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e).context("splice src->pipe failed"),
            }
        };
        if n == 0 {
            break; // EOF on source; the pipe was left empty by the last drain
        }
        // A chunk is in the pipe now: not safe to recycle until fully drained.
        pipe.drained = false;

        // Drain the pipe fully into the destination socket.
        let mut left = n;
        while left > 0 {
            dst.writable().await.context("writable error")?;
            match dst.try_io(Interest::WRITABLE, || {
                splice(
                    pipe.rd(),
                    None,
                    dst.as_ref(),
                    None,
                    left,
                    SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_NONBLOCK,
                )
                .map_err(errno_to_io)
            }) {
                Ok(m) => {
                    left -= m;
                    if left == 0 {
                        // Fully drained: the pipe is empty again, so it can go
                        // back to the pool even if the connection dies next.
                        pipe.drained = true;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e).context("splice pipe->dst failed"),
            }
        }
    }

    // Propagate EOF: half-close the write side so the peer sees the close.
    let _ = shutdown(dst.as_raw_fd(), Shutdown::Write);
    Ok(())
}

/// Bidirectional zero-copy relay between two TCP streams.
pub(crate) async fn splice_bidirectional(a: TcpStream, b: TcpStream) -> Result<()> {
    let a = Arc::new(a);
    let b = Arc::new(b);
    let a2b = splice_one(a.clone(), b.clone());
    let b2a = splice_one(b, a);
    tokio::try_join!(a2b, b2a)?;
    Ok(())
}
