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
use std::time::Instant;

use anyhow::{Context, Result};
use nix::fcntl::{fcntl, splice, FcntlArg, SpliceFFlags};
use nix::sys::socket::{shutdown, Shutdown};
use nix::unistd::pipe;
use or_panic::OptionOrPanic;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::TcpStream;

use crate::config::{EngageAfter, SpliceConfig};

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
/// Per thread. Each pooled pipe holds two descriptors, so the cap costs
/// `PIPE_POOL_MAX * 2 * workers` file descriptors at steady state -- 512 for the
/// 4-worker bench, ~4096 for a 32-worker gateway. That is fine given
/// `set_ulimit` raises RLIMIT_NOFILE to the hard limit, but it is why the number
/// is not larger. A 40-minute soak confirmed the pool fills to the cap and then
/// stops (fds 487 -> 543 -> flat, RSS flat at ~44 MB).
///
/// With `SpliceConfig::release_idle_pipes` this cap stops being just a cache
/// size and becomes the actual descriptor bound: idle connections park their
/// pipes here instead of holding them, so steady-state use is
/// `2 * PIPE_POOL_MAX * workers` plus the pipes carrying data, rather than
/// `4 * connections`. Note that parking does not close anything -- the saving
/// comes from connections sharing a bounded set of pipes, not from idle
/// connections costing zero.
const PIPE_POOL_MAX: usize = 64;

thread_local! {
    static PIPE_POOL: std::cell::RefCell<Vec<(OwnedFd, OwnedFd)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// Pipes currently checked out of the pool. Test-only bookkeeping: together
    /// with `PIPE_POOL.len()` it gives this thread's live pipe count exactly,
    /// where counting `/proc/self/fd` would race with tests on other threads.
    #[cfg(test)]
    static PIPES_BORROWED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
        #[cfg(test)]
        PIPES_BORROWED.with(|n| n.set(n.get() + 1));
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

    /// The ends are `Option` only so `Drop` can move them into the pool, and
    /// `Drop` is the last thing that runs, so both are always present here.
    fn rd(&self) -> &OwnedFd {
        self.rd.as_ref().or_panic("pipe read end present")
    }

    fn wr(&self) -> &OwnedFd {
        self.wr.as_ref().or_panic("pipe write end present")
    }
}

impl Drop for PooledPipe {
    fn drop(&mut self) {
        let (Some(rd), Some(wr)) = (self.rd.take(), self.wr.take()) else {
            return;
        };
        #[cfg(test)]
        PIPES_BORROWED.with(|n| n.set(n.get() - 1));
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
///
/// With `release_idle_pipes` the pipe is handed back to the pool whenever the
/// source runs dry, so a connection only pins descriptors while it actually has
/// bytes in flight. See `SpliceConfig::release_idle_pipes` for why that is safe
/// and what it costs.
async fn splice_one(
    src: Arc<TcpStream>,
    dst: Arc<TcpStream>,
    release_idle_pipes: bool,
) -> Result<()> {
    let mut pipe = PooledPipe::get()?;

    loop {
        // Move a chunk from the source socket into the pipe.
        // Try the syscall first and only wait for readiness when it actually
        // blocks. `try_io` decides with one atomic read of the cached readiness
        // flag, where `readable()` builds, polls and drops a `Readiness` future
        // every time -- which showed up as ~2.4% of total time on the
        // small-request passthrough profile, paid once per splice.
        let n = loop {
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
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // The pipe is empty on every path that reaches here: it was
                    // either just taken from the pool, or the drain below ran to
                    // completion, and a `WouldBlock` from the fill above added
                    // nothing. So it can be parked while the source is idle.
                    if release_idle_pipes {
                        drop(pipe);
                        src.readable().await.context("readable error")?;
                        pipe = PooledPipe::get()?;
                    } else {
                        src.readable().await.context("readable error")?;
                    }
                }
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
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    dst.writable().await.context("writable error")?;
                }
                Err(e) => return Err(e).context("splice pipe->dst failed"),
            }
        }
    }

    // Propagate EOF: half-close the write side so the peer sees the close.
    let _ = shutdown(dst.as_raw_fd(), Shutdown::Write);
    Ok(())
}

/// Bidirectional zero-copy relay between two TCP streams.
pub(crate) async fn splice_bidirectional(
    a: TcpStream,
    b: TcpStream,
    release_idle_pipes: bool,
) -> Result<()> {
    // The single funnel for zero-copy relaying, so counting here covers both the
    // passthrough gate and the post-kTLS handover.
    super::stats::record_splice_engaged();
    let a = Arc::new(a);
    let b = Arc::new(b);
    let a2b = splice_one(a.clone(), b.clone(), release_idle_pipes);
    let b2a = splice_one(b, a, release_idle_pipes);
    tokio::try_join!(a2b, b2a)?;
    Ok(())
}

/// Per-thread cache of relay buffers, for the same reason as the pipe pool:
/// a pair of `buffer_size` allocations per connection is a real cost when the
/// connection only carries a few hundred bytes.
const BUF_POOL_MAX: usize = 32;
/// Phase 1 only runs until the splice threshold, so it does not need the full
/// `buffer_size` used for bulk copying.
const RELAY_BUF_SIZE: usize = 16 * 1024;

thread_local! {
    static BUF_POOL: std::cell::RefCell<Vec<(Vec<u8>, Vec<u8>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

struct PooledBufs {
    a: Vec<u8>,
    b: Vec<u8>,
}

impl PooledBufs {
    fn get(buf_size: usize) -> Self {
        let size = buf_size.clamp(4096, RELAY_BUF_SIZE);
        if let Some((a, b)) = BUF_POOL.with(|p| p.borrow_mut().pop()) {
            return Self { a, b };
        }
        Self {
            a: vec![0u8; size],
            b: vec![0u8; size],
        }
    }
}

impl Drop for PooledBufs {
    fn drop(&mut self) {
        let a = std::mem::take(&mut self.a);
        let b = std::mem::take(&mut self.b);
        BUF_POOL.with(|p| {
            let mut pool = p.borrow_mut();
            if pool.len() < BUF_POOL_MAX {
                pool.push((a, b));
            }
        });
    }
}

/// Relay both directions with plain reads/writes until `gate` is reached, then
/// report whether splice should take over.
///
/// Returns `true` if the gate was reached and both sockets are still open,
/// `false` if the connection finished first (in which case it is fully done).
///
/// The gate is only tested at the tail of the loop, which is the one point
/// where both directions are quiescent: the `select!` arms each finish their
/// `write_all` before falling through, so nothing is buffered in userspace and
/// the sockets can be handed to the kernel safely. A timer arm inside the
/// `select!` would also be safe, but it would promote connections that are
/// merely idle -- allocating a pipe for a stream with nothing to move -- so
/// checking the clock on activity is both cheaper and better behaved.
async fn relay_until(
    a: &mut TcpStream,
    b: &mut TcpStream,
    gate: &EngageAfter,
    buf_size: usize,
) -> Result<bool> {
    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();
    // Buffers come from a thread-local pool: allocating two of them per
    // connection cost more than the pipe setup this phase exists to avoid.
    let mut bufs = PooledBufs::get(buf_size);
    let mut moved: u64 = 0;
    let start = Instant::now();

    loop {
        // `finish_one` drains a half-closed connection without splice: once one
        // side is done there is no long-lived stream left to optimise.
        //
        // Half-close is not end-of-connection. A client that finishes its
        // request with `shutdown(SHUT_WR)` still expects the response, so the
        // EOF is propagated to the *peer of the direction that ended*
        // (`$closing`) and the opposite direction is pumped to completion.
        // Shutting down the writer we are about to pump into instead would
        // deliver the peer's EOF and drop everything still in flight.
        macro_rules! finish_one {
            ($closing:expr, $r:expr, $w:expr, $buf:expr) => {{
                $closing.shutdown().await.ok();
                loop {
                    let n = $r.read(&mut $buf).await.context("read error")?;
                    if n == 0 {
                        break;
                    }
                    $w.write_all(&$buf[..n]).await.context("write error")?;
                }
                // Both directions are drained now; let the other peer see EOF.
                $w.shutdown().await.ok();
                return Ok(false);
            }};
        }
        tokio::select! {
            r = ar.read(&mut bufs.a) => {
                let n = r.context("read from client failed")?;
                // Client is done sending: tell the app, keep relaying its reply.
                if n == 0 { finish_one!(bw, br, aw, bufs.b); }
                bw.write_all(&bufs.a[..n]).await.context("write to app failed")?;
                moved += n as u64;
            }
            r = br.read(&mut bufs.b) => {
                let n = r.context("read from app failed")?;
                // App is done replying: tell the client, keep relaying its input.
                if n == 0 { finish_one!(aw, ar, bw, bufs.a); }
                aw.write_all(&bufs.b[..n]).await.context("write to client failed")?;
                moved += n as u64;
            }
        }
        if gate.reached(moved, start) {
            return Ok(true);
        }
    }
}

/// Bidirectional relay that only switches to splice once the connection has
/// proven itself worth the syscalls.
///
/// splice moves ~17 syscalls per connection to shift a small response (fill the
/// pipe, drain the pipe, plus readiness retries), where a read/write pair needs
/// two. Its benefit is per byte, its cost is per connection -- the same shape as
/// kTLS. Short request/response connections therefore never touch a pipe, while
/// connections that trip either gate still get zero-copy.
pub(crate) async fn splice_bidirectional_after(
    mut a: TcpStream,
    mut b: TcpStream,
    config: &SpliceConfig,
    buf_size: usize,
) -> Result<()> {
    if relay_until(&mut a, &mut b, &config.engage, buf_size).await? {
        splice_bidirectional(a, b, config.release_idle_pipes).await
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn pool_len() -> usize {
        PIPE_POOL.with(|pool| pool.borrow().len())
    }

    /// Descriptors this thread currently holds on a pipe: two per live pipe,
    /// whether the pipe is parked in the pool or checked out by a relay.
    ///
    /// This is the number capacity planning cares about, so the tests assert on
    /// it directly rather than trusting the pool alone as a proxy.
    fn pipe_fds() -> usize {
        2 * (pool_len() + PIPES_BORROWED.with(|n| n.get()))
    }

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    /// Wire up `client <-> relay <-> backend` and start the relay.
    ///
    /// The relay runs on the same thread as the test (a `#[tokio::test]`
    /// runtime is single-threaded), so it shares the thread-local pipe pool and
    /// the test can observe what the relay parks there.
    async fn start_relay(release_idle_pipes: bool) -> (TcpStream, TcpStream) {
        let (client, inbound) = connected_pair().await;
        let (outbound, backend) = connected_pair().await;
        tokio::spawn(splice_bidirectional(inbound, outbound, release_idle_pipes));
        (client, backend)
    }

    fn clear_pool() {
        PIPE_POOL.with(|pool| pool.borrow_mut().clear());
    }

    /// Let the relay reach its next idle wait.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    async fn expect(stream: &mut TcpStream, want: &[u8]) {
        let mut got = vec![0u8; want.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn an_idle_relay_owns_no_pipe_when_release_is_on() {
        clear_pool();
        let (mut client, mut backend) = start_relay(true).await;
        client.write_all(b"ping").await.unwrap();
        expect(&mut backend, b"ping").await;
        settle().await;

        // Only one pipe is ever created: each direction hands its pipe back
        // before the other one asks for it, so an idle bidirectional relay
        // converges on a single pipe shared through the pool -- and owns none
        // of its own.
        assert_eq!(pool_len(), 1, "the relay parked everything it borrowed");
    }

    #[tokio::test]
    async fn an_idle_relay_pins_two_pipes_when_release_is_off() {
        clear_pool();
        let (mut client, mut backend) = start_relay(false).await;
        client.write_all(b"ping").await.unwrap();
        expect(&mut backend, b"ping").await;
        settle().await;

        assert_eq!(pool_len(), 0, "both pipes stay pinned to the connection");
    }

    /// The headline claim: with release on, descriptor use tracks pipes that
    /// are actually carrying data, not open connections.
    ///
    /// Note what this does *not* say. Released pipes stay open in the pool, so
    /// the saving is not "idle connections cost nothing" but "idle connections
    /// share": the steady-state bound moves from `4 * connections` to
    /// `2 * PIPE_POOL_MAX * workers` plus whatever is in flight.
    #[tokio::test]
    async fn idle_connections_share_pipes_instead_of_each_pinning_four() {
        clear_pool();
        assert_eq!(pipe_fds(), 0, "test starts with no pipes on this thread");
        let mut ends = Vec::new();
        for _ in 0..8 {
            let (mut client, mut backend) = start_relay(true).await;
            client.write_all(b"ping").await.unwrap();
            expect(&mut backend, b"ping").await;
            // Without this the previous relay has not yet been polled back to
            // its idle wait, so it still owns its pipe when the next one asks
            // for one -- which is the in-flight case, not the idle case.
            settle().await;
            ends.push((client, backend));
        }

        // Held for the connection's lifetime this would be 8 * 4 = 32.
        assert_eq!(pipe_fds(), 2, "8 idle connections share one pooled pipe");
        drop(ends);
    }

    #[tokio::test]
    async fn idle_connections_each_cost_four_descriptors_when_release_is_off() {
        clear_pool();
        assert_eq!(pipe_fds(), 0, "test starts with no pipes on this thread");
        let mut ends = Vec::new();
        for _ in 0..8 {
            let (mut client, mut backend) = start_relay(false).await;
            client.write_all(b"ping").await.unwrap();
            expect(&mut backend, b"ping").await;
            ends.push((client, backend));
        }
        settle().await;

        assert_eq!(pipe_fds(), 8 * 4, "two pipes pinned per relay");
        drop(ends);
    }

    #[tokio::test]
    async fn data_survives_repeated_park_and_reacquire() {
        clear_pool();
        let (mut client, mut backend) = start_relay(true).await;

        // Each gap forces the relay to park its pipe and take a fresh one from
        // the pool, which is where a stale or half-drained pipe would corrupt
        // the stream.
        for i in 0..5u8 {
            let up = [b'a' + i; 16];
            client.write_all(&up).await.unwrap();
            expect(&mut backend, &up).await;
            settle().await;

            let down = [b'A' + i; 16];
            backend.write_all(&down).await.unwrap();
            expect(&mut client, &down).await;
            settle().await;
        }

        assert_eq!(pool_len(), 1);
    }

    #[tokio::test]
    async fn a_payload_larger_than_one_splice_still_arrives_intact() {
        let (mut client, mut backend) = start_relay(true).await;
        let payload: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
        let sender = tokio::spawn({
            let payload = payload.clone();
            async move {
                client.write_all(&payload).await.unwrap();
                client
            }
        });
        let mut got = vec![0u8; payload.len()];
        backend.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        drop(sender.await.unwrap());
    }

    #[tokio::test]
    async fn eof_propagates_with_release_enabled() {
        let (client, mut backend) = start_relay(true).await;
        drop(client);
        let mut got = Vec::new();
        backend.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty());
    }

    /// A gate that no test connection will ever reach, so the relay stays in
    /// the pre-splice phase for the whole exchange.
    fn ungated() -> SpliceConfig {
        SpliceConfig {
            engage: EngageAfter {
                after_bytes: Some(1 << 30),
                after_duration: None,
            },
            release_idle_pipes: false,
        }
    }

    async fn start_gated_relay() -> (TcpStream, TcpStream) {
        let (client, inbound) = connected_pair().await;
        let (outbound, backend) = connected_pair().await;
        tokio::spawn(async move {
            splice_bidirectional_after(inbound, outbound, &ungated(), 16 * 1024).await
        });
        (client, backend)
    }

    /// Half-closing a request must not cost the response: the client shuts down
    /// its write side, and the backend replies afterwards.
    #[tokio::test]
    async fn response_survives_a_client_half_close_before_the_gate() {
        let (mut client, mut backend) = start_gated_relay().await;

        client.write_all(b"ping").await.unwrap();
        client.shutdown().await.unwrap();

        let mut req = vec![0u8; 4];
        backend.read_exact(&mut req).await.unwrap();
        assert_eq!(&req, b"ping");
        // The app sees the client's EOF but is still free to answer.
        let mut trailing = Vec::new();
        backend.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
        backend.write_all(b"pong").await.unwrap();
        drop(backend);

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"pong", "client lost the response after half-closing");
    }

    /// The mirror image: the backend finishes first and the client is still
    /// sending. Its remaining bytes have to reach the app.
    #[tokio::test]
    async fn request_survives_a_backend_half_close_before_the_gate() {
        let (mut client, mut backend) = start_gated_relay().await;

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
    }
}
