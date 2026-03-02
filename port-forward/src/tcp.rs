// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// Run a TCP port forwarder: listen on `listen_addr`, forward to `target`.
pub async fn run_tcp_forwarder(
    listen_addr: SocketAddr,
    target: SocketAddr,
    cancel: CancellationToken,
) {
    let listener = match TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("tcp bind {listen_addr} failed: {e}");
            return;
        }
    };
    tracing::info!("tcp forwarding {listen_addr} -> {target}");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = listener.accept() => {
                let (client, peer) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("tcp accept on {listen_addr}: {e}");
                        continue;
                    }
                };
                let cancel = cancel.child_token();
                tokio::spawn(handle_tcp_connection(client, peer, target, cancel));
            }
        }
    }
}

async fn handle_tcp_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    target: SocketAddr,
    cancel: CancellationToken,
) {
    let mut server = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("tcp connect to {target} for {peer}: {e}");
            return;
        }
    };

    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);

    let result = tokio::select! {
        _ = cancel.cancelled() => return,
        r = relay(&mut client, &mut server) => r,
    };

    if let Err(e) = result {
        tracing::debug!("tcp relay {peer} <-> {target}: {e}");
    }
}

async fn relay(client: &mut TcpStream, server: &mut TcpStream) -> io::Result<()> {
    // Try splice(2) zero-copy first, fall back to userspace copy.
    match splice_bidirectional(client, server).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            tracing::debug!("splice not supported, falling back to copy_bidirectional");
            io::copy_bidirectional(client, server).await?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Zero-copy bidirectional TCP relay using Linux splice(2).
///
/// When one direction hits EOF, select! drops the other direction.
#[cfg(target_os = "linux")]
async fn splice_bidirectional(a: &TcpStream, b: &TcpStream) -> io::Result<()> {
    let a_fd = a.as_raw_fd();
    let b_fd = b.as_raw_fd();

    tokio::select! {
        r = splice_one_direction(a, a_fd, b, b_fd) => r,
        r = splice_one_direction(b, b_fd, a, a_fd) => r,
    }
}

/// On non-Linux platforms, splice is not available, so return Unsupported.
#[cfg(not(target_os = "linux"))]
async fn splice_bidirectional(_a: &TcpStream, _b: &TcpStream) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "splice not supported on this platform",
    ))
}

/// Splice data from src fd to dst fd via an intermediate pipe.
///
/// Uses `TcpStream::try_io` for proper readiness handling: when splice returns
/// EAGAIN, try_io automatically clears the readiness flag so the next
/// `readable().await` / `writable().await` blocks until the fd is truly ready.
#[cfg(target_os = "linux")]
async fn splice_one_direction(
    src: &TcpStream,
    src_fd: i32,
    dst: &TcpStream,
    dst_fd: i32,
) -> io::Result<()> {
    use nix::fcntl::{splice, SpliceFFlags};
    use nix::unistd::pipe;

    let (pipe_r, pipe_w): (OwnedFd, OwnedFd) = pipe().map_err(io::Error::other)?;

    let flags = SpliceFFlags::SPLICE_F_NONBLOCK | SpliceFFlags::SPLICE_F_MOVE;
    let chunk: usize = 65536;

    let src_bfd = unsafe { BorrowedFd::borrow_raw(src_fd) };
    let dst_bfd = unsafe { BorrowedFd::borrow_raw(dst_fd) };

    loop {
        src.readable().await?;

        let n = match src.try_io(io::Interest::READABLE, || {
            match splice(src_bfd, None, pipe_w.as_fd(), None, chunk, flags) {
                Ok(n) => Ok(n),
                Err(nix::errno::Errno::EAGAIN) => Err(io::ErrorKind::WouldBlock.into()),
                Err(nix::errno::Errno::EINVAL) => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "splice not supported for this fd type",
                )),
                Err(e) => Err(io::Error::other(e)),
            }
        }) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        };

        let mut written = 0;
        while written < n {
            dst.writable().await?;
            match dst.try_io(io::Interest::WRITABLE, || {
                match splice(pipe_r.as_fd(), None, dst_bfd, None, n - written, flags) {
                    Ok(w) => Ok(w),
                    Err(nix::errno::Errno::EAGAIN) => Err(io::ErrorKind::WouldBlock.into()),
                    Err(e) => Err(io::Error::other(e)),
                }
            }) {
                Ok(w) => written += w,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tcp_forward_roundtrip() {
        // Echo server
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut conn, _) = echo.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        let n = match conn.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if conn.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        // Start forwarder on a free port
        let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fwd_addr = tmp.local_addr().unwrap();
        drop(tmp);

        let cancel = CancellationToken::new();
        tokio::spawn(run_tcp_forwarder(fwd_addr, echo_addr, cancel.child_token()));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut conn = TcpStream::connect(fwd_addr).await.unwrap();
        conn.write_all(b"hello splice").await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), conn.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"hello splice");

        cancel.cancel();
    }
}
