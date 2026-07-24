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

/// Copy one direction (`src` -> `dst`) with splice until EOF, then half-close
/// the destination's write side.
async fn splice_one(src: Arc<TcpStream>, dst: Arc<TcpStream>) -> Result<()> {
    let (rd, wr) = pipe().context("failed to create splice pipe")?;
    set_pipe_capacity(&wr, PIPE_CAPACITY);

    loop {
        // Move a chunk from the source socket into the pipe.
        let n = loop {
            src.readable().await.context("readable error")?;
            match src.try_io(Interest::READABLE, || {
                splice(
                    src.as_ref(),
                    None,
                    &wr,
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
            break; // EOF on source
        }

        // Drain the pipe fully into the destination socket.
        let mut left = n;
        while left > 0 {
            dst.writable().await.context("writable error")?;
            match dst.try_io(Interest::WRITABLE, || {
                splice(
                    &rd,
                    None,
                    dst.as_ref(),
                    None,
                    left,
                    SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_NONBLOCK,
                )
                .map_err(errno_to_io)
            }) {
                Ok(m) => left -= m,
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
